import os
import signal
import time
import unittest
from unittest import mock

import dns.message

import certbot_dns_local.auth as auth
import certbot_dns_local.dnsutils as dnsutils


class TestDnsMethods(unittest.TestCase):
    def test_dns_get_all(self):
        google_pub_dns_a = dnsutils.dns_get_all('dns.google', 'A')
        assert set(google_pub_dns_a) == {'8.8.8.8', '8.8.4.4'}

    def test_dns_get_nameservers(self):
        domain_ip = dnsutils.dns_get_all('blechschmidt.io', 'A')[0]
        assert dnsutils.dns_challenge_server_ips('blechschmidt.io')[0] == domain_ip


class TestAuthenticator(unittest.TestCase):
    @staticmethod
    def _query(authenticator, qname, rdtype='TXT'):
        reply = authenticator.reply_from_data(dns.message.make_query(qname, rdtype).to_wire())
        return None if reply is None else dns.message.from_wire(reply)

    @mock.patch.object(auth, 'authoritative_nameserver_ips', return_value=[])
    def test_reply_serves_all_validations(self, _):
        # A certificate for example.com and *.example.com requires two validations for the same name.
        authenticator = auth.DNSAuthenticator({
            '_acme-challenge.example.com.': ['first', 'second'],
            '_acme-challenge.example.org.': ['third'],
        })
        self.addCleanup(authenticator.cleanup)

        reply = self._query(authenticator, '_ACME-challenge.example.com.')
        values = {b''.join(rdata.strings) for rdata in reply.answer[0]}
        assert values == {b'first', b'second'}

        reply = self._query(authenticator, '_acme-challenge.example.org.')
        assert [b''.join(rdata.strings) for rdata in reply.answer[0]] == [b'third']

        assert self._query(authenticator, '_acme-challenge.example.net.') is None

    def test_fork_child_does_not_return_on_signal(self):
        def raising_handler(signum, frame):
            raise RuntimeError('signal %d' % signum)

        # Mimic certbot's error handler, which raises an exception from its signal handler.
        previous = signal.signal(signal.SIGTERM, raising_handler)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        read_fd, write_fd = os.pipe()

        def target():
            os.close(read_fd)
            os.write(write_fd, b'x')
            while True:
                time.sleep(1)

        pid = auth.fork_child(target)
        os.close(write_fd)
        os.read(read_fd, 1)  # Wait until the child has reset its signal handlers.
        os.close(read_fd)
        os.kill(pid, signal.SIGTERM)
        _, status = os.waitpid(pid, 0)
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGTERM


if __name__ == '__main__':
    unittest.main()
