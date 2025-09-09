from typing import cast

import acme.messages
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
import pytest

from macen import challenges, exceptions
from tests.conftest import ACMEBackend
from tests.helpers import gencsrpem, randomize_domains

### domain verificateion


def test_auto_domain_verification_by_dns(
    backend: ACMEBackend,
    dnschalltestsrv_validator: challenges.DnsChalltestsrvImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    m = backend.registered_manager(validator=dnschalltestsrv_validator)
    domains = randomize_domains("www", "mail", suffix=".example{}.com")
    csr = gencsrpem(domains, ckey)
    orderr = m.acquire_domain_validations(dnschalltestsrv_validator, csr)
    authorizations = cast(tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations)
    assert len(authorizations) == 2
    assert authorizations[0].body.status.name == "valid"
    assert authorizations[1].body.status.name == "valid"
    assert sorted(a.body.identifier.value for a in authorizations) == sorted(domains)


### certificate creation


def test_certificate_creation_by_dns(
    backend: ACMEBackend,
    dnschalltestsrv_validator: challenges.DnsChalltestsrvImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    domains = randomize_domains("www", "mail", suffix=".example{}.org")
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=dnschalltestsrv_validator)
    orderr = m.acquire_domain_validations(dnschalltestsrv_validator, csr)
    authorizations = cast(tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations)
    assert len(authorizations) == 2
    certs = m.issue_certificate(orderr)
    assert "-----BEGIN CERTIFICATE-----" in certs
    assert "-----END CERTIFICATE-----" in certs


def test_rate_limit_on_certificate_creation_by_dns(
    backend: ACMEBackend,
    dnschalltestsrv_validator: challenges.DnsChalltestsrvImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    if backend.name == "pebble":
        return pytest.skip("Rate limiting is not implemented in pebble!")
    domains = randomize_domains("dnsexample-rate{}.org")
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=dnschalltestsrv_validator)
    for _ in range(5):
        orderr = m.acquire_domain_validations(dnschalltestsrv_validator, csr)
        authorizations = cast(
            tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations
        )
        assert len(authorizations) == 1
        certs = m.issue_certificate(orderr)
        assert "-----BEGIN CERTIFICATE-----" in certs
        assert "-----END CERTIFICATE-----" in certs

    with pytest.raises(exceptions.RateLimited) as e:
        orderr = m.acquire_domain_validations(dnschalltestsrv_validator, csr)
        authorizations = cast(
            tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations
        )
        assert len(authorizations) == 1
        m.issue_certificate(orderr)
    assert domains[0] in str(e.value)
