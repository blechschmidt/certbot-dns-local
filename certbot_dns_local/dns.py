import dns
import dns.message
import dns.resolver
from dns.exception import DNSException


def dns_get_all(qname, qtype, nameservers=None, authority=False):
    if not qname.endswith('.'):
        qname += '.'
    resolver = dns.resolver.Resolver()
    if nameservers is not None:
        resolver.nameservers = nameservers
    response = resolver.query(qname, qtype, raise_on_no_answer=False)
    result = []
    section = response.response.answer if not authority else response.response.authority
    for answer in section:
        for value in answer:
            result.append(str(value))
    return result


def dns_resolve_ips(names, nameservers=None):
    result = []
    for name in names:
        try:
            result += dns_get_all(name, 'A', nameservers)
        except DNSException:
            pass
        try:
            result += dns_get_all(name, 'AAAA', nameservers)
        except DNSException:
            pass
    return result


def nameserver_ips(domain):
    nameservers = dns_get_all(domain, 'NS')
    return dns_resolve_ips(nameservers)


def dns_challenge_server_ips(domain):
    ns_ips = None
    ns_domain = domain

    # Obtain the NS IP addresses for the start of authority of the challenge domain by moving up one label at a time.
    while len(ns_domain) != 0 and ns_domain != '.':
        try:
            ns_ips = nameserver_ips(ns_domain)
            if len(ns_ips) != 0:
                break
        except dns.resolver.NXDOMAIN:
            pass
        ns_domain = '.'.join(ns_domain.split('.')[1:])  # Drop the first label

    # These IP addresses are then used in order to find the NS record for the _acme-challenge subdomain.
    chal_ns = dns_get_all('_acme-challenge.' + domain, 'NS', ns_ips, True)

    # Resolve the IP addresses of the server which is supposed to answer the DNS challenges.
    return dns_resolve_ips(chal_ns)
