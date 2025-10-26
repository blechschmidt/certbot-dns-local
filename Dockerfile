FROM ubuntu:latest

ARG SOURCE=https://github.com/blechschmidt/certbot-dns-local.git#master
ARG OPTIONAL_DEPENDENCIES=[netfilter]

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libnetfilter-queue-dev \
    iptables \
    curl \
    build-essential

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh

ADD ${SOURCE} /certbot-dns-local

WORKDIR /certbot-dns-local

RUN uv add pip certbot

RUN uv run pip install .${OPTIONAL_DEPENDENCIES}

ENTRYPOINT [ "uv", "run", "certbot", "-a", "dns-local" ]
