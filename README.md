# certbot-dns-local
**Domain registrar agnostic authenticator plugin for certbot**

An authenticator plugin for [certbot](https://certbot.eff.org/) to support [Let's Encrypt](https://letsencrypt.org/) DNS
challenges (dns-01) for domains managed by any registrar.

## Why use this authenticator plugin?
* There is no other authenticator plugin for your domain registrar.
* Some domain registrars do not support fine-grained API permissions. Storing domain registrar credentials in a file on
  a web server might pose a security risk to all your domains.
* Migrating from one domain registrar to another does not require a new authenticator plugin.

## Installation
1. Optionally install the `netfilter_queue` library and `iptables`. On Debian-based systems, run:
   ```
   apt install libnetfilter-queue-dev iptables build-essential
   ```
   These dependencies enable support for DNS challenge authentication if UDP port 53 is already occupied.
   
2. Plugin installation:
   * If you are using `certbot` from your distribution repository or from the Python Package Index:
      ```
      pip install certbot-dns-local[netfilter]
      ```
   * If you are using `certbot-auto`, clone the repository, `cd` into the folder and run:
      ```
      /opt/eff.org/certbot/venv/bin/pip install certbot-dns-local[netfilter]
     ```

   If you do not need the `netfilter` feature, you can install the plugin through `pip install certbot-dns-local` without
   the `[netfilter]` suffix specifying optional dependencies.

3. Set up a DNS `NS` record for `_acme-challenge.yourdomain.com` pointing to the server which certbot is running on.\
   For example:
   ```
   _acme-challenge.yourdomain.com. 300 IN NS yourdomain.com.
   ```
   Such a record has to be created for each subdomain which you want to obtain a certificate for.

## Usage
A new certificate can be requested as follows:

    certbot certonly -a dns-local -d yourdomain.com -d '*.yourdomain.com'

Older versions of `certbot` may require you to use the plugin legacy name as follows:

    certbot certonly -a certbot-dns-local:dns-local -d yourdomain.com -d '*.yourdomain.com'

Renewals will automatically be performed using the same authenticator by certbot.

By default, the authenticator will attempt to resolve the challenge domain's nameserver IP addresses and bind sockets to these addresses.
This is done to prevent listening on `0.0.0.0` or `::`, which may result in collisions with services like `systemd-resolved`. This behavior
can be overridden by specifying one or multiple bind addresses manually using the `--dns-local-listen <address>` parameter, e.g. in cases
where `certbot` is running behind NAT.

## Behind the curtain
Behind the curtain, the plugin will open a UDP server on port 53 in order to serve the DNS validations. In case binding
to port 53 fails because it is already occupied by another application, it will fall back to packet interception using the
`netfilter_queue` library.
