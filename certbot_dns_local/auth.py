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

from .dnsutils import dns_challenge_server_ips

netfilter_support = True
try:
    import iptc
    from netfilterqueue import NetfilterQueue
    from scapy.layers.inet import UDP, IP
    from scapy.layers.inet6 import IPv6
except ImportError:
    netfilter_support = False

SOL_IPV6 = 41
IPV6_HDRINCL = 36

logger = logging.getLogger(__name__)

NETFILTER_MAX_QUEUES = 64


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


class DNSAuthenticator(object):
    def __init__(self, validation_name, validation):
        self.validation_name = validation_name
        self.validation = validation
        if not self.validation_name.endswith('.'):
            self.validation_name += '.'
        self.children = []
        atexit.register(self.cleanup)

    def reply_from_data(self, data):
        try:
            msg = dns.message.from_wire(bytes(data))
        except DNSException:
            return
        if len(msg.question) != 1:
            return
        question = msg.question[0]
        if str(question.name).lower() != self.validation_name.lower() or question.rdtype != dns.rdatatype.TXT \
                or question.rdclass != dns.rdataclass.IN:
            return
        reply = dns.message.Message()
        reply.id = msg.id
        reply.flags = dns.flags.QR | dns.flags.AA
        reply.question = msg.question
        record = dns.rrset.from_text(str(question.name), 60, 'IN', 'TXT', self.validation)
        reply.answer.append(record)
        return reply.to_wire()

    def cleanup(self):
        for child in self.children:
            os.kill(child, signal.SIGTERM)
        self.children = []


class NetfilterAuthenticator(DNSAuthenticator):
    def __init__(self, validation_name, validation):
        super(NetfilterAuthenticator, self).__init__(validation_name, validation)
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
        pid = os.fork()
        if pid == 0:
            nfqueue.run()
            os._exit(0)  # Exit without calling cleanup handlers etc.
        self.children.append(pid)

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
    def __init__(self, validation_name, validation, ips):
        super(ServerAuthenticator, self).__init__(validation_name, validation)
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

    def authenticate(self):
        pid = os.fork()
        if pid == 0:
            while True:
                read, _, _ = select.select(self.sockets, [], [])
                for s in read:
                    data, addr = s.recvfrom(0xFFFF)
                    reply = self.reply_from_data(data)
                    if reply is not None:
                        s.sendto(reply, addr)
        else:
            self.children.append(pid)

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

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=0):
        super(CertbotDNSAuthenticator, cls).add_parser_arguments(add, default_propagation_seconds=default_propagation_seconds)
        add('listen', action='append', default=[], help='IP to bind the challenge DNS server to. If not specified, addresses are fetched from DNS.')

    def _setup_credentials(self):
        pass

    @staticmethod
    def more_info():
        return 'This plugin intercepts DNS TXT queries to respond to a dns-01 challenge'

    def _perform(self, domain, validation_name, validation):
        bind_ips = self.conf('listen') or dns_challenge_server_ips(domain)
        server_authenticator = ServerAuthenticator(validation_name, validation, bind_ips)
        if len(bind_ips) > 0 and server_authenticator.try_bind():
            self.authenticator = server_authenticator
        elif netfilter_support:
            nf_authenticator = NetfilterAuthenticator(validation_name, validation)
            self.authenticator = nf_authenticator

        if self.authenticator is None:
            return
        self.authenticator.authenticate()

    def _cleanup(self, domain, validation_name, validation):
        if self.authenticator is None:
            return
        self.authenticator.cleanup()
