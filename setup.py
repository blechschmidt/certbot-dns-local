import os
from ctypes.util import find_library
from sys import platform

from setuptools import find_packages
from setuptools import setup


def command_exists(command):
    return any(os.access(os.path.join(path, command), os.X_OK) for path in os.environ['PATH'].split(os.pathsep))


install_requires = [
    'dnspython'
]

if (platform == 'linux' or platform == 'linux2') and find_library('netfilter_queue') is not None:
    install_requires += ['NetfilterQueue', 'python-iptables', 'scapy']

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name='certbot-dns-local',
    version='0.1.0',
    description='Domain registrar agnostic authenticator plugin for certbot',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/blechschmidt/certbot-dns-local',
    author='B. Blechschmidt',
    author_email='github@blechschmidt.pw',
    license='Apache License 2.0',
    install_requires=install_requires,
    packages=find_packages(),
    entry_points={
        'certbot.plugins': [
            'dns-local = certbot_dns_local.auth:CertbotDNSAuthenticator'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Security :: Cryptography',
        'Development Status :: 4 - Beta',
        'Environment :: Plugins',
        'Operating System :: POSIX :: Linux'
    ]
)
