Macen (Previously ACME Management Server (ACMEMS)
=================================================

[![Build Status](https://github.com/mswart/macen/actions/workflows/push+deploy.yml/badge.svg)](https://github.com/mswart/macen/actions/workflows/push+deploy.yml)
[![Build Status](https://img.shields.io/pypi/v/macen.svg)](https://pypi.python.org/pypi/macen)
[![Python Versions](https://img.shields.io/pypi/pyversions/macen.svg)](https://pypi.python.org/pypi/macen)
[![PyPi Status](https://img.shields.io/pypi/status/macen.svg)](https://pypi.python.org/pypi/macen)


[LetsEncrypt](https://letsencrypt.org) supports issuing free certificates by communication via ACME - the Automatically Certificate Management Evaluation protocol.

This tools is yet another ACME client ... but as a client/server model.


## Why yet another ACME client

Some aspects are special:

* **ACME handling can be put into own VM / container ...**: The server can be placed into an own VM, container, network segment to limit the security risk on compromised systems.
* **Only the server requires all the ACME dependencies**: The clients require only a SSL tool like OpenSSL and a HTTP client like wget or curl, no python, no build tools. Python with python-acme and its dependencies (PyOpenSSL, Cryptography, ...) is only needed for the server.
* **Supports distributed web servers**: All `.well-known/acme-challenges` requests for all domains can be served directly by the server. This makes it easy to validate domains when using multiple web server in distributed or fail-over fashion by forwarding all `.well-known/acme-challenges` requests.
* **Only the server needs the ACME account information**: It is not that security relevant, but only the ACME Management Server needs access to the account information / key for the ACME server like LetsEncrypt.
* **Caching CSR signs**: The returned signed certificate of a CSR is cached until the certificate is nearly expired (per default two week). If two machines have manual shared a key and CSR and they reusing both, they will both get from ACMEMS the same certificate back.


## Domain Validations / Challenges.

### HTTP01

The normal webserver must be adjusted to forward `.well-known/acme-challenges` requests to the ACME Management Server - this is a prerequirement and will not be checked/enforced/configured by this tool.

#### Nginx

```
upstream macen {
    server ...;
}
server {
    # ...
    location /.well-known/acme-challenge {
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://macen;
        # to support multiple acme mgmt server check challenge on all upstream server:
        proxy_next_upstream error timeout http_404;
    }
    # ...
}
```

This passes all ACME challenges to the management server. `proxy_next_upstream http_404;` can be used to support multiple ACME management servers and search for the response on all servers.

#### Apache

Up to you - I am happy to accept a PR to complete this.

### TLSNI01

`TLSNI01` is currently not supported, but there are few things are missing. Feel free to open a PR or talk to me if you have use for this challenge type.

### DNS01

ACMEMS can instrument DNS servers to serve the needed `TXT` records to validate domain names via `DNS01` challenge. The DNS servers will be updated vis DNS update. Currently there is no security for the updates implemented. We expect that the zone name managed by the name server are second-level domain name (like `example.org`).


## Installation

### Debian Packages

My preferred installation method are distribution packages. I try to published a packaged version in my own [PPA](https://launchpad.net/~malte.swart/+archive/ubuntu/acme). To goal is to support the current LTS version and the previous version for a upgrade period. The software dependencies should be directly available as distribution packages.

### PyPI

The server and all its dependencies are available on PyPi and can be installed by Python package manager like pip e.g. inside a virtualenv.

### Container image

Use can use the docker image to get a bundled application: `ghcr.io/mswart/macen`.
You need to mount the config into the image and pass its filename as argument.

Example usage:

```sh
docker run -v ./config:/config -p 1313:1313 macen:latest /config/main.ini
```


## Configuration

The configuration is a basic INI file, with multiple key support. The main parts are the blocks to define the account directory, listen information for the http interfaces and the configuration which client is allowed to request certificates for which domains.

```ini
[account]
# the ACME server to talk to; I recommend to first test
# against the staging system
acme-server = https://acme-staging-v02.api.letsencrypt.org/directory
# Accept Terms of Service
# Either in general:
accept-terms-of-service = yes # or true
# or limit the specific terms to accept
# accept-terms-of-service = https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf

# account dir; contains
#   account.pem - private key to identify against the ACME server
#   registration.json - the registration resource as JSON dump
dir = /etc/macen/account/

[mgmt]
# Management interface itself, the clients needs to talk to this
mgmt=192.0.2.13:1313
# maximal size for CSR (in bytes)
max-size = 4k
# define which verification block is used by default
default-verification = http
# should signed certificates be cached? if yes, how?
default-storage = file

# Define verification blocks
[verification "http"]
# the challenge type has to be defined first!
type = http01
# listen for HTTP challenge check requests (e.g. from Nginx)
listener=192.0.2.80:1380
listener=198.51.100.80:1380
listener=[fe80::80%eth0]:1380

[verification "dns"]
# the challenge type has to be defined first!
type = dns01-dnsUpdate
# which name server needs to be updated now
dns-server=192.0.2.53
# time-to-live for the new entries
ttl=5
# timeout for dns update requests
timeout=30

# Storages
[storage "none"]
# this stores nothing and it is the default storage
type = none

[storage "file"]
# caching on disk, the directory must be writeable for the daemon
type = file
directory=/etc/macen/storage
# cached certificates will be treated outdated if their expire date is less 
# than $renew-within$ days away. A new certificate will be issued for the 
# passed CSR, stored and returned in subsequencial requests
# defaults to 14 days - around 30 days is recommended by letsencrypt
renew-within=14

# Define multiple authentification blocks
# a CSR must fulfil all listed authentication methods and must
# only contains listed domains (checks against globs)
[auth "mail"]
# TCP connection must come from one of this IPs
ip=192.0.2.0/24
ip=198.51.100.21
domain=mail.example.org
domain=mail.example.com

# an additional auth block
[auth "ext"]
ip=198.51.100.128/28
domain=*.test.example.org

# CSR must also be signed by HMAC (via a the secret key)
[auth "mail-secure"]
# use special verification and storage
verification = dns
storage = file
ip=198.51.100.21
hmac_type=sha256
hmac_key=A1YP67armNf3cBrecyJHdb035
domain=mail?.example.org
domain=mail.example.com
```


## Registration

On startup, the server checks whether an registered account already exists.
Otherwise, it will be registered automatically.


## Example Client Usage

```bash
# generate domain private key (once!)
openssl genrsa 4096 > domain.key

# generate csr to create/renew your certificate
# please generate a new csr for to renew your certificate
openssl req -new -sha256 -key domain.key -subj "/CN=example.org" > domain-201512.csr
# or
openssl req -new -sha256 -key domain.key -subj "/CN=example.org" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.org,DNS:www.example.org")) > domain-201512.csr

# upload sign csr with shared key
wget --post-file=domain-201512.csr --header="`openssl dgst -sha256 -hmac '$KEY' domain-201512.csr | sed -e 's/HMAC-\(.*\)(.*)= *\(.*\)/Authentication: hmac name=\L\1\E, hash=\2/'`" http://acmese:1313/sign > domain-201512.pem
# upload csr with out sign
wget --post-file=domain-201512.csr http://acmese:1313/sign > domain-201512.pem
```


## HTTP interface

### Client request

Only POST requests to `/sign` are supported.

The body must be a CSR as PEM format; `Content-Length` header is required, `Content-Type` is currently not evaluated.

To authentication the CSR via HMAC, add a header like:

```
Authentication: hmac name=sha256 hash=47d5066525a214c759300d884bdd19d8f461a0ad24a2a0b7b705caee6c912228
```

A complete request could look like:

```
POST /sign HTTP/1.1
Host: 127.0.0.1:4005
Content-Length: 1586
Authentication: hmac name=sha256, hash=47d5066525a214c759300d884bdd19d8f461a0ad24a2a0b7b705caee6c912228

-----BEGIN CERTIFICATE REQUEST-----
MIIEWjCCAkICAQAwFTETMBEGA1UEAwwKZ28uZHh0dC5kZTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAOWXle7/dEo7l/h9O14w2ndsoKmzpHXcfosSyZnK
qrMoJLSKQImm0Y0ACRggs+c4oTbGeyUgm44RmmPjBoFxdL41CHTp5YHOytaYQHUz
A1wCitOzEMuPgRqvLUc4SqgjC7fOk1EP0bUX1YIrGNz40sYy5AsVINp4ZzKFfMoR
KtGrx4j1OrkMOfQNV6f/P8wUyOzoSSN5/XUoxcQ44aeJcfeVY6jHqZtL4BDV3EDq
oFnkHHKNGndYA6e0ov/WxHtXqxKrmsp7IN99sCvtwcoi8Kuf2OWE8/MuebsDRUCI
fhCXCsGU+2+99qan70fL7o+VmZTwBGr3GHtjJ5+QthJ92oH6uXsS+AamyhyLpp1V
3CRi1BO2G746QCIDpMmnXHe4uV49igZsOX75kl8i4dpXkzMe4lvgj4jL2nftFYGy
lv0LOwiiIUovRoTeVJlmD2RIgWz85MdxgHKFHpgBmgbmSoOlM1Uad4yY7WbsvtpT
aoSjbuG6NGa77YJBZ8eAF0FEfhvYpEAN1+3pRtHWiGsHEZ0tbQU8bpy+hOXYCMkv
iwpjyd+kTMBH9oCSeM3pQ8S74grpDV0L/wlfRoii2bImJDNurcRY22RJmPSQSSia
3KDHGZDzKW+uJs07FTa5y9RbavnCNQDrK6oyMMDZW876cQWHrj76U/f/8yuoeIuJ
NdZtAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAgEAOK5sq1dtr8SxSxbhaib+b/hz
F8F0xYpMBLrLpFfoAtoLWXp0a9AM3vqaHN+iPVTkwGri9c2Hi+E3VFltH39i+Ml1
U6I2KtiN1YB5/ARpQXCMT/29c31lPpvR3FfdKjOa078inacY+3bB7qwu3mC5qjrz
ZzkJxMf5c7iQTWhp18ISD0zw2jN9I0OeyFZVfrQleGtlhVBSYemEyuurPu2vlwlq
Xm0WpJ1wZlxNDolGTJ525HjIJEPJhGMnIwGSDKvN8INurfDzcPy1dUlRzxmoeRIs
23xu5D0DTfIPaMFT1yZaCF45nZLCcbNyUbbLK21+TABNwwAlm2UDz1RGsUK8h94x
KeHJunfvtmQ7DB/Y7IfYkGJYt20RovuUniv/ruZtc8xPxcs3Sv8H93ISrKJ1ElmO
Hvj45TYRjKC1Hl4YB30Yi/MQJJgN32Td48miTgyK5Sloc+v60CGWWsxfXC4zrUd9
CxzpbR5AeEOlsrjWBUJx3V1Ri5die1J+j0cutSC42BnFXkL3/W5JGpaiIpqlK1Ha
jTC+FnojbcxDDW+SJpI3HI/Bzv3qAbMJS2WcyVGiN//sX5iuOW5r6fJECFQhCDzE
3f0YiD2Wh6N4xcf41bOVE7gA+TjmlShzSwZQPsEwUO4brRiBErnCbwpgK/T9vCV8
A3IlV6YS/4SoAHraTLA=
-----END CERTIFICATE REQUEST-----
```


### Server response

Error code:

* **200**: CSR was signed. Response body contains the certificate and the intermediate certificate in PEM form.
* **403**: Signing is denied, have a look at your auth blocks / authentication methods; are you missing an `Authentication` header?
* **413**: CSR request is too long. You might increase the `max-size` setting.
* **415**: CSR could not be parsed.
* **421**: Challenge validation failed (temporarily)
* **429**: Rated limited (currently only based on ACME upstream errors)
* **500**: Internal exception - take a look at the log and report the bug.


## Testing

The server is tested by unit tests, integration tests against the "official" ACME test server [Pebble](https://github.com/letsencrypt/pebble)) and with end-to-end tests. All major features should be covered like authentication, HTTP requests, validation methods (HTTP01, DNS01), different CSR and certificate algorithms (RSA and EC).

The test are exectued by `py.test`. `docker-compose` is used to run the ACME servers. Take a look at `tests/scripts` to inspect the commands, that are run as part of the CI.


## Support

The goal is to be compatible with all supported Python versions. But adjusting the CI and publishing a new release might take some time. This primarily means that removing support for a EOL Python version is not considered a breaking change and will happen in normal minor releases (but not in patch/bug-fix releases).

Recently new dependency version are expected. This is difficult to pin-point at the moment, but the idea is to be compatible with the version from the latest Ubuntu LTS and Debian releases. The minimal dependency versions are tried to express. But as the CI does not run tests for all existing versions, they could be slightly out-of-date from time to time.


## Contributing

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Add tests for your feature.
4. Add your feature.
5. Commit your changes (git commit -am 'Add some feature')
6. Push to the branch (git push origin my-new-feature)
7. Create new Pull Request


## License

GPL License

Copyright (c) 2015-2025, Malte Swart
