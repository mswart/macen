"""Authentication methods and domain authorization, independent of HTTP handlers.

A method owns its Config model and authenticate() implementation. Registering
it is the only integration step; configuration loading uses the model directly.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
import hmac
from ipaddress import IPv4Network, IPv6Network, ip_address
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar

from pydantic import BaseModel, Field, SecretStr, field_validator

from .settings import ConfigurationError, StrictConfig

if TYPE_CHECKING:
    from .challenges import ChallengeRouter
    from .storages import StorageImplementor


@dataclass(frozen=True)
class Identity:
    """An identity verified by a method or a trusted protocol adapter."""

    subject: str
    issuer: str


@dataclass(frozen=True)
class AuthenticationContext:
    peer_address: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    identity: Identity | None = None

    def __post_init__(self) -> None:
        # Copy before wrapping so the caller cannot mutate the evidence later.
        object.__setattr__(
            self, "headers", MappingProxyType({k.lower(): v for k, v in self.headers.items()})
        )


class AuthStatus(Enum):
    SUCCESS = "success"
    MISSING = "missing"
    REJECTED = "rejected"


@dataclass(frozen=True)
class AuthResult:
    status: AuthStatus
    identity: Identity | None = None

    @property
    def successful(self) -> bool:
        return self.status is AuthStatus.SUCCESS


class Requirement(Protocol):
    def authenticate(self, request: AuthenticationContext) -> AuthResult: ...


@dataclass(frozen=True)
class AllOf:
    methods: tuple[Requirement, ...]

    def authenticate(self, request: AuthenticationContext) -> AuthResult:
        if not self.methods:
            return AuthResult(AuthStatus.REJECTED)
        identity = request.identity
        for method in self.methods:
            result = method.authenticate(request)
            if not result.successful:
                return result
            if result.identity is not None:
                if identity is not None and identity != result.identity:
                    return AuthResult(AuthStatus.REJECTED)
                identity = result.identity
        return AuthResult(AuthStatus.SUCCESS, identity)


@dataclass(frozen=True)
class Policy:
    name: str
    requirement: Requirement
    domains: tuple[str, ...]
    verification: "ChallengeRouter"
    storage: "StorageImplementor"

    def permits(self, identifiers: Sequence[str]) -> bool:
        return bool(identifiers) and all(
            any(fnmatchcase(domain.lower(), pattern.lower()) for pattern in self.domains)
            for domain in identifiers
        )


@dataclass(frozen=True)
class Authorization:
    policy: Policy
    identifiers: tuple[str, ...]
    identity: Identity | None = None


class PolicyEvaluator:
    def __init__(self, policies: Sequence[Policy]) -> None:
        self.policies = tuple(policies)

    def authorize(
        self, request: AuthenticationContext, identifiers: Sequence[str]
    ) -> Authorization | None:
        """Authorize identifiers independently of whether a CSR exists yet.

        An implementation exception propagates: it must never trigger fallback
        to a more permissive policy. No permissions are combined across policies.
        """
        for policy in self.policies:
            if not policy.permits(identifiers):
                continue
            result = policy.requirement.authenticate(request)
            if result.successful:
                return Authorization(policy, tuple(identifiers), result.identity)
        return None


C = TypeVar("C", bound=BaseModel)


class AuthenticationMethod(Generic[C]):
    Config: type[C]

    def __init__(self, config: C) -> None:
        self.config = config

    def authenticate(self, request: AuthenticationContext) -> AuthResult:
        raise NotImplementedError


class IPConfig(StrictConfig):
    networks: list[IPv4Network | IPv6Network] = Field(min_length=1)


class IPAuthMethod(AuthenticationMethod[IPConfig]):
    Config = IPConfig

    def authenticate(self, request: AuthenticationContext) -> AuthResult:
        try:
            address = ip_address(request.peer_address)
        except ValueError:
            return AuthResult(AuthStatus.REJECTED)
        return AuthResult(
            AuthStatus.SUCCESS
            if any(address in network for network in self.config.networks)
            else AuthStatus.REJECTED
        )


class HmacConfig(StrictConfig):
    algorithm: str = "sha256"
    secret: SecretStr = Field(min_length=1)

    @field_validator("algorithm")
    @classmethod
    def valid_algorithm(cls, value: str) -> str:
        # Validate once at startup, including algorithms that cannot be used by HMAC.
        try:
            hmac.new(b"", digestmod=value)
        except (ValueError, TypeError) as exc:
            raise ValueError("Unsupported HMAC algorithm") from exc
        return value


class HmacAuthMethod(AuthenticationMethod[HmacConfig]):
    Config = HmacConfig

    def authenticate(self, request: AuthenticationContext) -> AuthResult:
        header = request.headers.get("authentication")
        if header is None:
            return AuthResult(AuthStatus.MISSING)
        try:
            scheme, parameters = header.split(None, 1)
            if scheme != "hmac":
                return AuthResult(AuthStatus.REJECTED)
            fields: dict[str, str] = {}
            for item in parameters.split(","):
                key, value = item.strip().split("=", 1)
                if key in fields:
                    return AuthResult(AuthStatus.REJECTED)
                fields[key] = value
            if fields.keys() != {"name", "hash"} or fields["name"] != self.config.algorithm:
                return AuthResult(AuthStatus.REJECTED)
            digest = hmac.new(
                self.config.secret.get_secret_value().encode("utf-8"),
                request.body,
                digestmod=self.config.algorithm,
            ).hexdigest()
            valid = hmac.compare_digest(digest, fields["hash"])
        except (ValueError, TypeError):
            return AuthResult(AuthStatus.REJECTED)
        return AuthResult(AuthStatus.SUCCESS if valid else AuthStatus.REJECTED)


class AllConfig(StrictConfig):
    # The method itself must be explicitly named in the configuration.
    pass


class AllAuthMethod(AuthenticationMethod[AllConfig]):
    Config = AllConfig

    def authenticate(self, request: AuthenticationContext) -> AuthResult:
        return AuthResult(AuthStatus.SUCCESS)


class IdentityConfig(StrictConfig):
    issuer: str
    subjects: list[str] = Field(min_length=1)


class IdentityAuthMethod(AuthenticationMethod[IdentityConfig]):
    """Match a verified adapter identity; never trusts identity HTTP headers."""

    Config = IdentityConfig

    def authenticate(self, request: AuthenticationContext) -> AuthResult:
        identity = request.identity
        if identity is None:
            return AuthResult(AuthStatus.MISSING)
        if identity.issuer != self.config.issuer or identity.subject not in self.config.subjects:
            return AuthResult(AuthStatus.REJECTED)
        return AuthResult(AuthStatus.SUCCESS, identity)


@dataclass(frozen=True)
class MethodSpec:
    implementation: type[AuthenticationMethod]
    config: BaseModel

    def build(self) -> AuthenticationMethod:
        return self.implementation(self.config)


class AuthenticationRegistry:
    def __init__(self) -> None:
        self._methods: dict[str, type[AuthenticationMethod]] = {}

    def register(self, name: str, implementation: type[AuthenticationMethod]) -> None:
        if name in self._methods:
            raise ConfigurationError(f"Authentication method already registered: {name}")
        self._methods[name] = implementation

    def validate(self, name: str, values: Mapping[str, Any]) -> MethodSpec:
        try:
            implementation = self._methods[name]
        except KeyError:
            raise ConfigurationError(f"Unknown authentication method: {name}") from None
        return MethodSpec(implementation, implementation.Config.model_validate(values))


auth_methods = AuthenticationRegistry()
for _name, _implementation in (
    ("ip", IPAuthMethod),
    ("hmac", HmacAuthMethod),
    ("all", AllAuthMethod),
    ("identity", IdentityAuthMethod),
):
    auth_methods.register(_name, _implementation)
