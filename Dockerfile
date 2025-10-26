FROM ubuntu:latest

ARG SOURCE=https://github.com/blechschmidt/certbot-dns-local.git#master

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    certbot \
    libnetfilter-queue-dev \
    iptables

RUN pip install -U setuptools

ADD ${SOURCE} /certbot-dns-local

RUN cd /certbot-dns-local && python3 setup.py install

RUN rm -rf /certbot-dns-local

ENTRYPOINT [ "certbot" ]
