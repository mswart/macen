"""Authentication and policy regressions, independent of CSR and HTTP plumbing."""

from dataclasses import FrozenInstanceError, replace
import hmac
from pathlib import Path
from typing import Any

from pydantic import ValidationError
import pytest

from macen.application import build_components
from macen.auth import (
    AllOf,
    AuthenticationContext,
    AuthenticationMethod,
    AuthenticationRegistry,
    AuthResult,
    AuthStatus,
    HmacAuthMethod,
    Identity,
    PolicyEvaluator,
)
from macen.config import load_config, validate_config
from macen.settings import ConfigurationError, StrictConfig


def evaluator(*policies: dict[str, Any]) -> PolicyEvaluator:
    return build_components(
        validate_config({"account": {"dir": "."}, "policies": list(policies)})
    ).auth


def policy(domains: list[str], **methods: dict) -> dict[str, Any]:
    return {"domains": domains, "auth": methods}


def context(
    address: str = "192.0.2.34", *, key: bytes | None = None, algorithm: str = "sha256"
) -> AuthenticationContext:
    body = b"the exact request body\r\n"
    headers = {}
    if key:
        digest = hmac.new(key, body, digestmod=algorithm).hexdigest()
        headers["Authentication"] = f"hmac name={algorithm}, hash={digest}"
    return AuthenticationContext(address, headers, body)


def test_no_policy_denies() -> None:
    assert evaluator().authorize(context(), ["example.org"]) is None


@pytest.mark.parametrize(
    ("domains", "requested", "allowed"),
    [
        ([], ["example.org"], False),
        (["*.org"], ["test.example.org"], True),
        (["*.example.org"], ["test.example.org", "test.example.com"], False),
        (["example.org", "*.example.com"], ["example.org", "*.example.com"], True),
        (["example.org", "www.example.com"], ["example.org", "*.example.com"], False),
        (["test.example.org", "www.example.com"], ["test.example.org", "www.example.com"], True),
        (["*"], [], False),
    ],
)
def test_domain_permissions(domains: list[str], requested: list[str], allowed: bool) -> None:
    auth = evaluator(policy(domains, all={}))
    assert (auth.authorize(context(), requested) is not None) is allowed


@pytest.mark.parametrize(
    ("address", "allowed"), [("192.0.2.34", True), ("198.51.100.21", True), ("203.0.113.1", False)]
)
def test_ip_authentication(address: str, allowed: bool) -> None:
    auth = evaluator(
        policy(["*.example.org"], ip={"networks": ["198.51.100.0/24", "192.0.2.0/24"]})
    )
    assert (auth.authorize(context(address), ["test.example.org"]) is not None) is allowed


def test_permissions_are_not_combined_across_policies() -> None:
    auth = evaluator(policy(["*.example.org"], all={}), policy(["*.example.com"], all={}))
    assert auth.authorize(context(), ["test.example.org", "test.example.com"]) is None


def test_first_complete_match_wins() -> None:
    auth = evaluator(
        {"name": "wrong-ip", **policy(["*"], ip={"networks": ["203.0.113.0/24"]})},
        {"name": "selected", **policy(["*"], all={})},
        {"name": "later", **policy(["*"], all={})},
    )
    assert auth.authorize(context(), ["example.org"]).policy.name == "selected"


@pytest.mark.parametrize(
    ("address", "key", "algorithm", "allowed"),
    [
        ("192.0.2.34", b"secret", "sha256", True),
        ("192.0.2.34", None, "sha256", False),
        ("192.0.2.34", b"wrong", "sha256", False),
        ("192.0.2.34", b"secret", "sha384", False),
        ("203.0.113.1", b"secret", "sha256", False),
    ],
)
def test_all_checks_required(
    address: str, key: bytes | None, algorithm: str, allowed: bool
) -> None:
    auth = evaluator(
        policy(["*.example.org"], ip={"networks": ["192.0.2.0/24"]}, hmac={"secret": "secret"})
    )
    assert (
        auth.authorize(context(address, key=key, algorithm=algorithm), ["test.example.org"])
        is not None
    ) is allowed


@pytest.mark.parametrize(
    "header",
    [
        "",
        "hmac",
        "hmac broken",
        "hmac name=sha256",
        "hmac name=sha256, hash=é",
        "hmac name=sha256, hash=bad, hash=bad",
    ],
)
def test_malformed_credentials_rejected(header: str) -> None:
    method = HmacAuthMethod(HmacAuthMethod.Config.model_validate({"secret": "secret"}))
    assert (
        method.authenticate(AuthenticationContext("127.0.0.1", {"Authentication": header})).status
        is AuthStatus.REJECTED
    )


def test_missing_credentials_and_exact_body() -> None:
    method = HmacAuthMethod(HmacAuthMethod.Config.model_validate({"secret": "secret"}))
    assert method.authenticate(context()).status is AuthStatus.MISSING
    signed = context(key=b"secret")
    assert method.authenticate(signed).successful
    assert not method.authenticate(replace(signed, body=signed.body.rstrip())).successful


def test_context_is_immutable() -> None:
    headers = {"Authentication": "original"}
    evidence = AuthenticationContext("127.0.0.1", headers)
    headers["Authentication"] = "modified"
    assert evidence.headers["authentication"] == "original"
    with pytest.raises(TypeError):
        evidence.headers["authentication"] = "modified"
    with pytest.raises(FrozenInstanceError):
        evidence.body = b"modified"


@pytest.mark.parametrize(
    "methods",
    [
        {},
        {"unknown": {}},
        {"hmac": {}},
        {"hmac": {"secret": "secret", "algorithm": "unknown"}},
        {"ip": {"networks": ["invalid"]}},
        {"all": {"typo": True}},
    ],
)
def test_bad_auth_config_fails_at_startup(methods: dict) -> None:
    with pytest.raises((ValidationError, ConfigurationError)):
        evaluator({"domains": ["*"], "auth": methods})


def test_empty_allof_denies() -> None:
    assert not AllOf(()).authenticate(context()).successful


def test_verified_identity_does_not_trust_headers() -> None:
    auth = evaluator(policy(["example.org"], identity={"issuer": "acme", "subjects": ["client-1"]}))
    assert (
        auth.authorize(
            AuthenticationContext("127.0.0.1", {"identity": "client-1"}), ["example.org"]
        )
        is None
    )
    evidence = AuthenticationContext("127.0.0.1", identity=Identity("client-1", "acme"))
    assert auth.authorize(evidence, ["example.org"]).identity == evidence.identity


def test_method_registration_owns_configuration(tmp_path: Path) -> None:
    class TokenConfig(StrictConfig):
        token: str

    class TokenMethod(AuthenticationMethod[TokenConfig]):
        Config = TokenConfig

        def authenticate(self, request: AuthenticationContext) -> AuthResult:
            return AuthResult(
                AuthStatus.SUCCESS
                if request.headers.get("token") == self.config.token
                else AuthStatus.REJECTED
            )

    registry = AuthenticationRegistry()
    registry.register("token", TokenMethod)
    path = tmp_path / "config.toml"
    path.write_text(
        '[account]\ndir="."\n[[policies]]\ndomains=["example.org"]\n[policies.auth.token]\ntoken="test"\n'
    )
    config = load_config(path, registry=registry)
    auth = build_components(config).auth
    assert auth.authorize(AuthenticationContext("127.0.0.1", {"token": "test"}), ["example.org"])
    assert auth.authorize(context(), ["example.org"]) is None
    with pytest.raises(ConfigurationError):
        registry.register("token", TokenMethod)


def test_method_exception_aborts_policy_fallback() -> None:
    class Broken:
        def authenticate(self, request: AuthenticationContext) -> AuthResult:
            raise RuntimeError("unavailable")

    auth = evaluator(policy(["*"], all={}), policy(["*"], all={}))
    auth = PolicyEvaluator(
        [replace(auth.policies[0], requirement=AllOf((Broken(),))), auth.policies[1]]
    )
    with pytest.raises(RuntimeError, match="unavailable"):
        auth.authorize(context(), ["example.org"])
