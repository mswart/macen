from pathlib import Path
import random
import shutil
from typing import cast

import acme
import acme.client
import acme.messages
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
import josepy.jwk
import pytest

from acmems import challenges, exceptions
from tests.conftest import ACMEBackend
from tests.helpers import M, gencsrpem, randomize_domains

### load private key


def test_key_load() -> None:
    m = M("""[account]
        dir = tests/support/valid
        [mgmt]""")
    m.load_private_key()
    assert type(m.key) is josepy.jwk.JWKRSA
    assert (
        m.key.thumbprint()
        == b"\xfe\xb1\xaa\xf8\xc8&\xb6v\x1f\xd3Jc\xbc\x80\xb0ie\xf6\xf6\xb9x$\x14\xf9\x1b\x99{\xe6\x91L\x89\x9e"
    )


def test_no_key_file() -> None:
    m = M("""[account]
        dir = tests/support/notexisting
        [mgmt]""")
    with pytest.raises(exceptions.AccountError) as e:
        m.load_private_key()
    assert "account.pem not found" in str(e.value)


### create private key


def test_create_key(tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        [mgmt]"""
    )
    m.create_private_key()
    assert type(m.key) is josepy.jwk.JWKRSA


def test_override_key(tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        [mgmt]"""
    )
    shutil.copyfile("tests/support/valid/account.pem", str(tmp_path / "account.pem"))
    with pytest.raises(exceptions.AccountError) as e:
        m.create_private_key()
    assert "force" in str(e.value)
    assert "Existing key is only override if I am forced to" in str(e.value)
    m.create_private_key(force=True)
    assert type(m.key) is josepy.jwk.JWKRSA
    assert (
        m.key.thumbprint()
        != b"\xfe\xb1\xaa\xf8\xc8&\xb6v\x1f\xd3Jc\xbc\x80\xb0ie\xf6\xf6\xb9x$\x14\xf9\x1b\x99{\xe6\x91L\x89\x9e"
    )


### register
def randomized_email() -> str:
    return "acme@pytest{}.org".format(random.randint(0, 2**16))  # noqa: S311


def test_register_with_general_tos(backend: ACMEBackend, tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        acme-server = {backend.endpoint}
        accept-terms-of-service = yes
        [mgmt]"""
    )
    m.create_private_key()
    m.init_client()
    assert m.config.account.accept_terms_of_service is True
    tos_agreement = m.tos_agreement_required()
    assert tos_agreement and tos_agreement.startswith(backend.tos_prefix)
    m.register(emails=[randomized_email()])
    assert not m.tos_agreement_required()


def test_register_with_specific_term_of_service(backend: ACMEBackend, tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        acme-server = {backend.endpoint}
        [mgmt]"""
    )
    m.create_private_key()
    m.init_client()
    tos_agreement = m.tos_agreement_required()
    assert tos_agreement and tos_agreement.startswith(backend.tos_prefix)
    m.register(emails=[randomized_email()], tos_agreement=[tos_agreement])
    assert not m.tos_agreement_required()


def test_register_with_specific_terms_of_service(backend: ACMEBackend, tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        acme-server = {backend.endpoint}
        [mgmt]"""
    )
    m.create_private_key()
    m.init_client()
    tos_agreement = m.tos_agreement_required()
    assert tos_agreement and tos_agreement.startswith(backend.tos_prefix)
    m.register(
        emails=[randomized_email()], tos_agreement=[tos_agreement, "http://example.org/terms.pdf"]
    )
    assert not m.tos_agreement_required()


def test_register_without_tos_agreement(backend: ACMEBackend, tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        acme-server = {backend.endpoint}
        [mgmt]"""
    )
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required()
    with pytest.raises(exceptions.NeedToAgreeToTOS):
        m.register(emails=[randomized_email()], tos_agreement=False)


def test_register_ignoring_tos_agreement(backend: ACMEBackend, tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        acme-server = {backend.endpoint}
        [mgmt]"""
    )
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required()
    with pytest.raises(exceptions.NeedToAgreeToTOS):
        m.register(emails=[randomized_email()], tos_agreement=None)


def test_register_different_tos_agreement(backend: ACMEBackend, tmp_path: Path) -> None:
    m = M(
        f"""[account]
        dir = {tmp_path}
        acme-server = {backend.endpoint}
        [mgmt]"""
    )
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required()
    with pytest.raises(exceptions.NeedToAgreeToTOS):
        m.register(emails=[randomized_email()], tos_agreement=["http://example.org/terms.pdf"])


### refresh registration


def test_refresh_registration_for_unknown_key(backend: ACMEBackend) -> None:
    m = M(
        f"""[account]
        dir = tests/support/valid
        acme-server = {backend.endpoint}
        [mgmt]"""
    )
    m.load_private_key()
    assert type(m.key) is josepy.jwk.JWKRSA
    m.init_client()
    assert type(m.client) is acme.client.ClientV2
    with pytest.raises(exceptions.AccountError) as e:
        m.refresh_registration()
    assert "Key is not yet registered" in str(e.value)


### domain verificateion


def test_auto_domain_verification(
    backend: ACMEBackend,
    http_server: challenges.HttpChallengeImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    m = backend.registered_manager(validator=http_server)
    domains = randomize_domains("www", "mail", suffix=".example{}.com")
    csr = gencsrpem(domains, ckey)
    orderr = m.acquire_domain_validations(http_server, csr)
    authorizations = cast(tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations)
    assert len(authorizations) == 2
    assert authorizations[0].body.status.name == "valid"
    assert authorizations[1].body.status.name == "valid"
    assert sorted([v.body.identifier.value for v in authorizations]) == sorted(domains)


def test_invalid_domain_verification(
    backend: ACMEBackend,
    http_server: challenges.HttpChallengeImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    if backend.name == "pebble":
        return pytest.skip("Rate limiting is not implemented in pebble!")
    m = backend.registered_manager(validator=http_server)
    csr = gencsrpem(["test.invalid"], ckey)
    with pytest.raises(exceptions.InvalidDomainName) as e:
        m.acquire_domain_validations(http_server, csr)
    assert "test.invalid" in str(e.value)


### certificate creation


def test_certificate_creation(
    backend: ACMEBackend,
    http_server: challenges.HttpChallengeImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    domains = randomize_domains("www", "mail", suffix=".example{}.org")
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=http_server)
    orderr = m.acquire_domain_validations(http_server, csr)
    authorizations = cast(tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations)
    assert len(authorizations) == 2
    certs = m.issue_certificate(orderr)
    assert len(certs.split("\n\n")) == 2


def test_rate_limit_on_certificate_creation(
    backend: ACMEBackend,
    http_server: challenges.HttpChallengeImplementor,
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    if backend.name == "pebble":
        return pytest.skip("Rate limiting is not implemented in pebble!")
    domains = randomize_domains("httpexample-rate{}.org")
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=http_server)
    for _ in range(5):
        orderr = m.acquire_domain_validations(http_server, csr)
        authorizations = cast(
            tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations
        )
        assert len(authorizations) == 1
        certs = m.issue_certificate(orderr)
        assert "-----BEGIN CERTIFICATE-----" in certs
        assert "-----END CERTIFICATE-----" in certs
    with pytest.raises(exceptions.RateLimited) as e:
        orderr = m.acquire_domain_validations(http_server, csr)
        authorizations = cast(
            tuple[acme.messages.AuthorizationResource, ...], orderr.authorizations
        )
        assert len(authorizations) == 1
        m.issue_certificate(orderr)
    assert domains[0] in str(e.value)
