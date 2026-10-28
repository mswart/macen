"""Certificate requests and issuance for /sign and future protocol adapters."""

from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Protocol

import acme.messages
from cryptography import x509
from cryptography.x509.oid import NameOID

from .auth import AuthenticationContext, Authorization, PolicyEvaluator
from .exceptions import AuthorizationDenied, PayloadInvalid

if TYPE_CHECKING:
    from .challenges import ChallengeRouter


@dataclass(frozen=True)
class CertificateRequest:
    pem: bytes
    identifiers: tuple[str, ...]
    common_name: str | None

    @classmethod
    def parse(cls, pem: bytes) -> "CertificateRequest":
        try:
            csr = x509.load_pem_x509_csr(pem)
            if not csr.is_signature_valid:
                raise ValueError("Invalid CSR signature")
            names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = str(names[0].value) if names else None
            try:
                san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                if any(not isinstance(name, x509.DNSName) for name in san):
                    raise ValueError("Only DNS identifiers are supported")
                domains = san.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                domains = []
            if common_name and common_name not in domains:
                domains.insert(0, common_name)
            if not domains:
                raise ValueError("CSR contains no DNS identifiers")
            return cls(pem, tuple(dict.fromkeys(domains)), common_name)
        except (ValueError, TypeError, x509.DuplicateExtension) as exc:
            raise PayloadInvalid() from exc


class Issuer(Protocol):
    def acquire_domain_validations(
        self, validator: "ChallengeRouter", csrpem: bytes
    ) -> acme.messages.OrderResource: ...

    def issue_certificate(self, order: acme.messages.OrderResource) -> str: ...


class IssuanceService:
    def __init__(self, policies: PolicyEvaluator, issuer: Issuer) -> None:
        self.policies = policies
        self.issuer = issuer
        # The upstream ACME client has mutable nonce/account state. Serialize its
        # use and the cache read/write transaction, independently of HTTP threads.
        self._lock = Lock()

    def sign(self, context: AuthenticationContext) -> str:
        request = CertificateRequest.parse(context.body)
        authorization = self.policies.authorize(context, request.identifiers)
        if authorization is None:
            raise AuthorizationDenied()
        return self.issue(request, authorization)

    def issue(self, request: CertificateRequest, authorization: Authorization) -> str:
        # Recheck permissions at finalization; future adapters may have authorized
        # an order before the CSR existed. Never issue extra CSR identifiers.
        if set(request.identifiers) != set(authorization.identifiers):
            raise AuthorizationDenied()
        if not authorization.policy.permits(request.identifiers):
            raise AuthorizationDenied()
        policy = authorization.policy
        with self._lock:
            cached = policy.storage.from_cache(request.pem)
            if cached:
                return cached
            order = self.issuer.acquire_domain_validations(policy.verification, request.pem)
            certificate = self.issuer.issue_certificate(order)
            policy.storage.add_to_cache(request.pem, certificate)
            return certificate
