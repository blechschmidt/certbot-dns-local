"""DNS Authenticator using UDP sockets and the libnetfilter_queue library to intercept and answer DNS challenges."""
import atexit
import logging
import os
import select
import signal
import socket

import dns
import dns.message
import dns.resolver
import zope.interface
from certbot import interfaces
from certbot.plugins import dns_common
from dns.exception import DNSException

from .dnsutils import dns_challenge_server_ips, authoritative_nameserver_ips, dns_get_rrsets

netfilter_support = True
try:
    import iptc
    from netfilterqueue import NetfilterQueue
    from scapy.layers.inet import UDP, IP
    from scapy.layers.inet6 import IPv6

    from . import iptc_compat
    iptc_compat.patch()
except ImportError:
    netfilter_support = False

SOL_IPV6 = 41
IPV6_HDRINCL = 36

logger = logging.getLogger(__name__)

NETFILTER_MAX_QUEUES = 64

# Signals for which certbot or Python install handlers that raise exceptions instead of terminating the process.
CHILD_DEFAULT_SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGXCPU,
                         signal.SIGXFSZ]


class ProcolAgnosticNfqueue(object):
    def __init__(self, version):
        self.nfqueue = NetfilterQueue()
        self.queue_num = None
        if version == 4:
            self.table = iptc.Table
            self.rule = iptc.Rule
        elif version == 6:
            self.table = iptc.Table6
            self.rule = iptc.Rule6
        self.rule_inserted = False

    def bind(self, func):
        for i in range(0, NETFILTER_MAX_QUEUES):
            try:
                self.nfqueue.bind(i, func)
                self.queue_num = i
                return True
            except OSError:
                pass
        return False

    def run(self):
        self.nfqueue.run(True)

    def _modify_rule(self, delete):
        chain = iptc.Chain(self.table(self.table.FILTER), 'INPUT')
        rule = self.rule()
        rule.protocol = 'udp'
        match = iptc.Match(rule, 'udp')
        match.dport = '53'
        target = iptc.Target(rule, 'NFQUEUE')
        target.set_parameter('queue-num', str(self.queue_num))
        target.set_parameter('queue-bypass')
        rule.target = target
        rule.add_match(match)
        if delete:
            chain.delete_rule(rule)
        else:
            chain.insert_rule(rule)

    def insert_rule(self):
        self.rule_inserted = True
        self._modify_rule(False)

    def delete_rule(self):
        if self.rule_inserted:
            self.rule_inserted = False
            self._modify_rule(True)


def is_local_address(ip):
    s = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def normalize_name(name):
    name = name.lower()
    if not name.endswith('.'):
        name += '.'
    return name


def fork_child(target):
    """Run target in a child process and return its PID to the parent. The child never returns from this call."""
    pid = os.fork()
    if pid != 0:
        return pid
    status = 1
    try:
        # The child inherits certbot's signal handlers, which turn signals into exceptions. Being killed by the
        # parent would then resume certbot's control flow, e.g. the renewal loop, within the child.
        for signum in CHILD_DEFAULT_SIGNALS:
            signal.signal(signum, signal.SIG_DFL)
        target()
        status = 0
    except BaseException:
        logger.exception('Challenge server process failed')
    finally:
        os._exit(status)  # Exit without calling cleanup handlers etc.


class DNSAuthenticator(object):
    def __init__(self, records):
        # Maps each normalized validation name to the list of validations served for it. A name can have multiple
        # validations, e.g. when a certificate covers both a domain and its wildcard.
        self.records = records
        self.children = []
        self.parent_ns_ips = dict((name, self._get_parent_ns_ips(name)) for name in records)
        atexit.register(self.cleanup)

    @staticmethod
    def _get_parent_ns_ips(validation_name):
        # Nameservers of the zone containing the delegation, used to serve other records within the
        # _acme-challenge subdomain. Addresses of this machine are excluded to prevent query loops.
        parent_domain = validation_name.split('.', 1)[1]
        try:
            return [ip for ip in authoritative_nameserver_ips(parent_domain) if not is_local_address(ip)]
        except DNSException:
            return []

    def _find_validation_name(self, qname):
        # The most specific validation name which is equal to or a parent of qname.
        matches = [name for name in self.records if qname == name or qname.endswith('.' + name)]
        return max(matches, key=len) if matches else None

    def reply_from_data(self, data):
        try:
            msg = dns.message.from_wire(bytes(data))
        except DNSException:
            return
        if len(msg.question) != 1:
            return
        question = msg.question[0]
        if question.rdclass != dns.rdataclass.IN:
            return
        qname = str(question.name).lower()
        validation_name = self._find_validation_name(qname)
        if validation_name is None:
            return
        parent_ns_ips = self.parent_ns_ips[validation_name]
        reply = dns.message.Message()
        reply.id = msg.id
        reply.flags = dns.flags.QR | dns.flags.AA
        reply.question = msg.question
        if qname == validation_name and question.rdtype == dns.rdatatype.TXT:
            # Validations change with every attempt. A TTL of zero prevents the resolvers of the CA from serving
            # those of a previous attempt from their cache.
            record = dns.rrset.from_text(str(question.name), 0, 'IN', 'TXT', *self.records[validation_name])
            reply.answer.append(record)
        elif len(parent_ns_ips) > 0:
            try:
                reply.answer.extend(dns_get_rrsets(qname, question.rdtype, parent_ns_ips))
            except dns.resolver.NXDOMAIN:
                reply.set_rcode(dns.rcode.NXDOMAIN)
            except DNSException:
                return
        else:
            return
        return reply.to_wire()

    def cleanup(self):
        for child in self.children:
            os.kill(child, signal.SIGTERM)
            # Reap the child, so that the sockets it holds are released before the next certificate is processed.
            os.waitpid(child, 0)
        self.children = []


class NetfilterAuthenticator(DNSAuthenticator):
    def __init__(self, records):
        super(NetfilterAuthenticator, self).__init__(records)
        self.nfqueue4 = ProcolAgnosticNfqueue(4)
        self.nfqueue6 = ProcolAgnosticNfqueue(6)

    @staticmethod
    def _send_raw_udp_packet(src_addr, dst_addr, src_port, dst_port, payload, ip_layer):
        s = socket.socket(socket.AF_INET if ip_layer == IP else socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
        if ip_layer == IPv6:
            s.setsockopt(SOL_IPV6, IPV6_HDRINCL, True)
            dst = (dst_addr, 0, 0, 0)
        else:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
            dst = (dst_addr, dst_port)
        s.sendto(bytes(ip_layer(src=src_addr, dst=dst_addr) / UDP(sport=src_port, dport=dst_port) / payload), dst)

    def cleanup(self):
        super(NetfilterAuthenticator, self).cleanup()
        try:
            self.nfqueue4.delete_rule()
        except iptc.IPTCError:
            pass
        try:
            self.nfqueue6.delete_rule()
        except iptc.IPTCError:
            pass

    def authenticate_netfilter(self, nfqueue, handler):
        nfqueue.bind(handler)
        nfqueue.insert_rule()
        self.children.append(fork_child(nfqueue.run))

    def authenticate(self):
        self.authenticate_netfilter(self.nfqueue4, self._handle_packet4)
        self.authenticate_netfilter(self.nfqueue6, self._handle_packet6)

    def _handle_packet4(self, packet):
        self._handle_packet_helper(packet, IP)

    def _handle_packet6(self, packet):
        self._handle_packet_helper(packet, IPv6)

    def _handle_packet_helper(self, packet, ip_layer):
        pkt = ip_layer(packet.get_payload())
        layers = pkt.layers()
        if len(layers) != 3 and not isinstance(layers[1], UDP):
            packet.accept()
            return
        udp = pkt.getlayer(UDP)
        reply = self.reply_from_data(udp.payload)
        if reply is None:
            packet.accept()
            return
        packet.drop()
        self._send_raw_udp_packet(pkt.dst, pkt.src, udp.dport, udp.sport, reply, ip_layer)
        return


class ServerAuthenticator(DNSAuthenticator):
    def __init__(self, records, ips):
        super(ServerAuthenticator, self).__init__(records)
        self.ips = ips
        self.sockets = []

    def try_bind(self):
        for ip in self.ips:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind((ip, 53))
                self.sockets.append(s)
                s.setblocking(False)
            except OSError:
                return False
        return True

    def _serve(self):
        while True:
            read, _, _ = select.select(self.sockets, [], [])
            for s in read:
                data, addr = s.recvfrom(0xFFFF)
                reply = self.reply_from_data(data)
                if reply is not None:
                    s.sendto(reply, addr)

    def authenticate(self):
        self.children.append(fork_child(self._serve))

    def cleanup(self):
        super(ServerAuthenticator, self).cleanup()
        for s in self.sockets:
            s.close()
        self.sockets = []


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class CertbotDNSAuthenticator(dns_common.DNSAuthenticator):
    description = 'Obtain certificates using a DNS TXT record (by configuring the NS record of ' \
                  '_acme-challenge.yourdomain.com to point to the server which is running certbot)'

    def __init__(self, *args, **kwargs):
        super(CertbotDNSAuthenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.authenticator = None
        self.records = {}
        self.bind_ips = []

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=0):
        super(CertbotDNSAuthenticator, cls).add_parser_arguments(add, default_propagation_seconds=default_propagation_seconds)
        add('listen', action='append', default=[], help='IP to bind the challenge DNS server to. If not specified, addresses are fetched from DNS.')

    def _setup_credentials(self):
        pass

    @staticmethod
    def more_info():
        return 'This plugin intercepts DNS TXT queries to respond to a dns-01 challenge'

    def perform(self, achalls):
        # The base implementation calls _perform for each challenge, which only collects the records. A single
        # authenticator serving all of them is started afterwards, because a name may have to be served with
        # multiple validations at once, e.g. when a certificate covers both a domain and its wildcard.
        self.records = {}
        self.bind_ips = []
        responses = super(CertbotDNSAuthenticator, self).perform(achalls)
        self._start_authenticator()
        return responses

    def _perform(self, domain, validation_name, validation):
        self.records.setdefault(normalize_name(validation_name), []).append(validation)
        for ip in self.conf('listen') or dns_challenge_server_ips(domain):
            if ip not in self.bind_ips:
                self.bind_ips.append(ip)

    def _start_authenticator(self):
        server_authenticator = ServerAuthenticator(self.records, self.bind_ips)
        if len(self.bind_ips) > 0 and server_authenticator.try_bind():
            self.authenticator = server_authenticator
        elif netfilter_support:
            self.authenticator = NetfilterAuthenticator(self.records)

        if self.authenticator is None:
            return
        self.authenticator.authenticate()

    def _cleanup(self, domain, validation_name, validation):
        # Called for each challenge, while a single authenticator serves all of them.
        if self.authenticator is None:
            return
        self.authenticator.cleanup()
        self.authenticator = None
