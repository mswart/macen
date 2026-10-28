"""Orders exercise real providers with a deterministic upstream ACME client."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import acme.challenges
import acme.errors
import acme.messages
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
import pytest

from macen.application import build_components
from macen.auth import AuthenticationContext
from macen.challenges import (
    ChallengeRoute,
    ChallengeRouter,
    DnsChallengeServerImplementor,
    HttpChallengeImplementor,
)
from macen.config import validate_config
from macen.exceptions import (
    AuthorizationDenied,
    ChallengeFailed,
    NoChallengeMethodsSupported,
    PayloadInvalid,
)
from macen.issuance import CertificateRequest, IssuanceService
from macen.manager import ACMEManager
from tests.helpers import gencsrpem


def authorization(
    domain: str, *, wildcard: bool = False, valid: bool = False, token: bytes = b"abcdefghijklmnop"
) -> acme.messages.AuthorizationResource:
    return acme.messages.AuthorizationResource(
        body=acme.messages.Authorization(
            identifier=acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value=domain),
            wildcard=wildcard,
            status=acme.messages.STATUS_VALID if valid else acme.messages.STATUS_PENDING,
            challenges=(
                acme.messages.ChallengeBody(chall=acme.challenges.HTTP01(token=token)),
                acme.messages.ChallengeBody(chall=acme.challenges.DNS01(token=token)),
            ),
        )
    )


@pytest.fixture
def manager() -> ACMEManager:
    config = validate_config({"account": {"dir": "tests/support/valid"}})
    manager = ACMEManager(config.settings, connect=False)
    manager.load_private_key()
    manager.client = Mock()
    return manager


def test_mixed_order_and_cleanup(manager: ACMEManager) -> None:
    http = HttpChallengeImplementor("http", {})
    dns = DnsChallengeServerImplementor("dns", {})
    router = ChallengeRouter(
        http,
        (
            ChallengeRoute(dns, ("mail.example.org",)),
            ChallengeRoute(dns, wildcard=True),
        ),
    )
    order = SimpleNamespace(
        authorizations=[
            authorization("www.example.org"),
            authorization("mail.example.org"),
            authorization("example.org", wildcard=True),
        ]
    )
    manager.client.new_order.return_value = order

    def poll(actual: object, deadline: object) -> object:
        assert actual is order
        assert set(http.responses) == {"www.example.org"}
        assert set(dns.responses) == {
            "_acme-challenge.mail.example.org.",
            "_acme-challenge.example.org.",
        }
        return order

    manager.client.poll_authorizations.side_effect = poll
    assert manager.acquire_domain_validations(router, b"csr") is order
    assert manager.client.answer_challenge.call_count == 3
    assert http.responses == dns.responses == {}


@pytest.mark.parametrize("failure", ["answer", "poll", "route"])
def test_partial_order_failure_cleans_every_provider(manager: ACMEManager, failure: str) -> None:
    http = HttpChallengeImplementor("http", {})
    dns = DnsChallengeServerImplementor("dns", {})
    router = ChallengeRouter(http, (ChallengeRoute(dns, ("mail.example.org",)),))
    authorizations = [authorization("www.example.org"), authorization("mail.example.org")]
    if failure == "route":
        # A wildcard cannot use the default HTTP provider, even if a broken CA offers HTTP.
        authorizations.append(authorization("example.org", wildcard=True))
        error = NoChallengeMethodsSupported
    elif failure == "answer":
        manager.client.answer_challenge.side_effect = [None, RuntimeError("answer failed")]
        error = RuntimeError
    else:
        manager.client.poll_authorizations.side_effect = acme.errors.ValidationError([])
        error = ChallengeFailed
    manager.client.new_order.return_value = SimpleNamespace(authorizations=authorizations)
    with pytest.raises(error):
        manager.acquire_domain_validations(router, b"csr")
    assert http.responses == dns.responses == {}
    assert not dns._records


def test_valid_authorizations_need_no_route(manager: ACMEManager) -> None:
    order = SimpleNamespace(authorizations=[authorization("example.org", valid=True)])
    manager.client.new_order.return_value = order
    manager.client.poll_authorizations.return_value = order
    assert manager.acquire_domain_validations(ChallengeRouter(None), b"csr") is order
    manager.client.answer_challenge.assert_not_called()


def test_shared_dns_owner_retains_other_values(manager: ACMEManager) -> None:
    dns = DnsChallengeServerImplementor("dns", {})
    apex = dns.prepare(authorization("example.org").body, manager.key, "example.org")
    wildcard = dns.prepare(
        authorization("example.org", wildcard=True, token=b"different-token!").body,
        manager.key,
        "example.org",
    )
    assert len(dns.responses["_acme-challenge.example.org."]) == 2
    apex.cleanup()
    assert len(dns.responses["_acme-challenge.example.org."]) == 1
    wildcard.cleanup()
    assert not dns.responses


def test_identical_dns_values_are_reference_counted(manager: ACMEManager) -> None:
    dns = DnsChallengeServerImplementor("dns", {})
    first = dns.prepare(authorization("example.org").body, manager.key, "example.org")
    second = dns.prepare(authorization("example.org").body, manager.key, "example.org")
    first.cleanup()
    assert len(dns.responses["_acme-challenge.example.org."]) == 1
    second.cleanup()
    assert not dns.responses


def test_publication_error_cleans_partial_dns_record(manager: ACMEManager) -> None:
    class BrokenDNS(DnsChallengeServerImplementor):
        def add_entry(self, entry: str, value: str) -> None:
            super().add_entry(entry, value)
            raise RuntimeError("response lost")

    dns = BrokenDNS("dns", {})
    manager.client.new_order.return_value = SimpleNamespace(
        authorizations=[authorization("example.org")]
    )
    with pytest.raises(RuntimeError, match="response lost"):
        manager.acquire_domain_validations(dns, b"csr")
    assert not dns.responses
    manager.client.answer_challenge.assert_not_called()


def test_service_authorizes_before_cache_and_checks_csr_identifiers(
    ckey: CertificateIssuerPrivateKeyTypes,
) -> None:
    components = build_components(
        validate_config(
            {
                "account": {"dir": "."},
                "policies": [{"domains": ["example.org"], "auth": {"all": {}}}],
            }
        )
    )
    issuer = Mock()
    service = IssuanceService(components.auth, issuer)
    request = CertificateRequest.parse(gencsrpem(["example.org"], ckey))
    context = AuthenticationContext("127.0.0.1", body=request.pem)
    grant = components.auth.authorize(context, request.identifiers)
    cache = Mock()
    cache.from_cache.return_value = "cached certificate"
    grant = replace(grant, policy=replace(grant.policy, storage=cache))
    assert service.issue(request, grant) == "cached certificate"
    issuer.acquire_domain_validations.assert_not_called()
    extra = CertificateRequest.parse(gencsrpem(["example.org", "other.example.org"], ckey))
    with pytest.raises(AuthorizationDenied):
        service.issue(extra, grant)
    with pytest.raises(AuthorizationDenied):
        service.sign(replace(context, body=extra.pem))
    assert cache.from_cache.call_count == 1


def test_service_stores_only_successful_issuance(ckey: CertificateIssuerPrivateKeyTypes) -> None:
    components = build_components(
        validate_config(
            {"account": {"dir": "."}, "policies": [{"domains": ["*"], "auth": {"all": {}}}]}
        )
    )
    issuer = Mock()
    service = IssuanceService(components.auth, issuer)
    request = CertificateRequest.parse(gencsrpem(["example.org"], ckey))
    grant = components.auth.authorize(AuthenticationContext("127.0.0.1"), request.identifiers)
    cache = Mock()
    cache.from_cache.return_value = None
    grant = replace(grant, policy=replace(grant.policy, storage=cache))
    issuer.issue_certificate.side_effect = RuntimeError("finalization failed")
    with pytest.raises(RuntimeError):
        service.issue(request, grant)
    cache.add_to_cache.assert_not_called()
    issuer.issue_certificate.side_effect = None
    issuer.issue_certificate.return_value = "issued"
    assert service.issue(request, grant) == "issued"
    cache.add_to_cache.assert_called_once_with(request.pem, "issued")


def test_csr_signature_and_san_only_requests(ckey: CertificateIssuerPrivateKeyTypes) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.org")]),
            critical=False,
        )
        .sign(ckey, hashes.SHA256())
    )
    request = CertificateRequest.parse(csr.public_bytes(serialization.Encoding.PEM))
    assert request.common_name is None
    assert request.identifiers == ("example.org",)
    with pytest.raises(PayloadInvalid):
        CertificateRequest.parse(b"not a CSR")


def test_tampered_csr_signature_rejected(ckey: CertificateIssuerPrivateKeyTypes) -> None:
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    csr = x509.load_pem_x509_csr(gencsrpem(["example.org"], ckey))
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    pem = (
        b"-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.encodebytes(der)
        + b"-----END CERTIFICATE REQUEST-----\n"
    )
    with pytest.raises(PayloadInvalid):
        CertificateRequest.parse(pem)
