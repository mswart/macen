ChangeLog
=========

This page lists all versions with its changes. Macen follows Semantic Versioning.


Version 0
-------------------------

v0.5.0 (2025-09-11)
^^^^^^^^^^^^^^^^^^^

Rename project to "Macen":
The similarity to mason is welcome (as ACME server are called boulder and pebble),
but uses the letters of ACME.

Modernize project

* Switch to pyproject.toml (instead of setup.py); use scripts instead of custom binaries
* Auto-format code
* Configure linter and fix diagnostics
* Refresh supported Python versions (now 3.10 to 3.13)

Merge register cli into server startup to automatically register if needed.

Offer container images via ghcr.io/mswart/macen.


v0.4.1
^^^^^^

Fix PyPI deployment bug (missing long description content type)


v0.4.0
^^^^^^

Stabilization towards 1.0 release:

* Support newer `python-acme` releases
* handling nonce errors (with updated acme library), fixes #8
* switch to ACME v2 endpoints
* support for wildcard domains
* a basic logging framework, fixes #3
* test against multiple ACME backends (https://github.com/letsencrypt/boulder
  and https://github.com/letsencrypt/pebble)
* use docker-compose for simple and reliable ACME backend setup
* Refresh supported Python versions (add new released major versions,
  drop unsupported old ones): target 3.5 to 3.8 for now
* Dedicated HTTP error codes for rating limiting and validation errors
* Simplified Python dependencies: only use PyOpenSSL and cryptograph to
  parse CSR and during tests


v0.3.1
^^^^^^

Multiple bug fixes:

* Fix auth-block specific storage and verification settings
* IOError when replace certification in file storage
* Fix typos in dns01-dnsUpdate verification


v0.3.0
^^^^^^

(Experimental) support for DNS challenges


v0.2.0
^^^^^^

Reaching base architecture for 1.0 release. This includes:

* Restucture code and! *config* to support multiple verification mechanism
* WIP: experiment / prepare for dns01 challenge support (via dns updates)
* add storage support to not reissue CSRs the same pem, supporting reissue from multiple machines via a once shared key and CSR
* support newer python-acme releases


v0.1.1
^^^^^^

* Fix syntax error in setup.py, preventing to upload to PyPI

v0.1.0
^^^^^^

Implement basic feature set:

* submit CSR
* validate domain via HTTP
* sign certificate
* authenticate clients based on IP and HMAC
