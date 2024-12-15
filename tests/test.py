import unittest
import certbot_dns_local.dnsutils as dnsutils


class TestDnsMethods(unittest.TestCase):
    def test_dns_get_all(self):
        google_pub_dns_a = dnsutils.dns_get_all('dns.google', 'A')
        assert set(google_pub_dns_a) == {'8.8.8.8', '8.8.4.4'}

    def test_dns_get_nameservers(self):
        domain_ip = dnsutils.dns_get_all('blechschmidt.io', 'A')[0]
        assert dnsutils.dns_challenge_server_ips('blechschmidt.io')[0] == domain_ip


if __name__ == '__main__':
    unittest.main()
