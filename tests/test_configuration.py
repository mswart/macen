"""Configuration formats, reference resolution, and pure validation."""

import io
from pathlib import Path

import pydantic
import pytest

from macen.application import build_components
from macen.auth import AuthenticationContext
from macen.config import load_config, validate_config
from macen.exceptions import NoChallengeMethodsSupported
from macen.settings import ConfigurationError


def test_ini_and_toml_equivalence(tmp_path: Path) -> None:
    ini = io.StringIO("""
[account]
dir = /tmp/macen-account
accept-terms-of-service = yes
[mgmt]
listener = 127.0.0.1:1313
listener = [::1]:1313
[verification "web"]
listener = 127.0.0.1:1380
type = http01
[auth "client"]
ip = 192.0.2.0/24
hmac_type = sha256
hmac_key = secret
domain = *.example.org
""")
    path = tmp_path / "config.toml"
    path.write_text("""
[account]
dir = "/tmp/macen-account"
accept-terms-of-service = true
[mgmt]
listener = ["127.0.0.1:1313", "[::1]:1313"]
[verification.providers.web]
type = "http01"
listener = "127.0.0.1:1380"
[[policies]]
name = "client"
domains = ["*.example.org"]
[policies.auth.ip]
networks = ["192.0.2.0/24"]
[policies.auth.hmac]
algorithm = "sha256"
secret = "secret"
""")
    first, second = load_config(ini), load_config(path)
    assert first.settings == second.settings
    assert first.methods == second.methods
    assert first.providers == second.providers
    assert first.routes == second.routes


def test_merge_before_resolving_references(tmp_path: Path) -> None:
    first = io.StringIO("""[account]
dir=/tmp/macen
[mgmt]
default-verification=dns
[auth "first"]
all=yes
domain=example.org
""")
    second = tmp_path / "later.toml"
    second.write_text("""
[mgmt]
max-size = "8k"
[verification.providers.dns]
type = "dns01-dnsUpdate"
[[policies]]
name = "second"
domains = ["example.com"]
auth = { all = {} }
""")
    config = load_config(first, second)
    assert config.settings.account.dir == Path("/tmp/macen")  # noqa: S108
    assert config.settings.mgmt.max_size == 8000
    assert [p.name for p in config.settings.policies] == ["first", "second"]
    assert all(route.default == "dns" for route in config.routes)


def test_later_named_provider_replaces_whole_definition(tmp_path: Path) -> None:
    first = tmp_path / "first.toml"
    second = tmp_path / "second.toml"
    first.write_text(
        '[account]\ndir="."\n[verification.providers.main]\ntype="dns01-dnsUpdate"\ndns-server="192.0.2.53"'
    )
    second.write_text('[verification.providers.main]\ntype="http01"')
    config = load_config(first, second)
    assert config.settings.verification.providers == {"main": {"type": "http01"}}


@pytest.mark.parametrize(
    "settings",
    [
        {"verification": {"default": "missing"}},
        {"mgmt": {"default-storage": "missing"}},
        {"verification": {"default": False, "rules": [{"domains": ["*"], "provider": "missing"}]}},
        {"policies": [{"domains": ["*"], "auth": {"all": {}}, "verification": "missing"}]},
        {"policies": [{"domains": ["*"], "auth": {"all": {}}, "storage": "missing"}]},
        {
            "mgmt": {"default-verification": False},
            "policies": [{"domains": ["*"], "auth": {"all": {}}}],
        },
        {"mgmt": {"default-storage": False}, "policies": [{"domains": ["*"], "auth": {"all": {}}}]},
    ],
)
def test_unknown_references_fail(settings: dict) -> None:
    with pytest.raises(ConfigurationError):
        validate_config({"account": {"dir": "."}, **settings})


@pytest.mark.parametrize(
    "options", ["pi=127.0.0.1", "hmac_key=secret\nhmac_typ=sha256", "hmac_type=sha256", ""]
)
def test_invalid_legacy_auth_fails_closed(options: str) -> None:
    with pytest.raises((ConfigurationError, pydantic.ValidationError)):
        load_config(io.StringIO(f'[account]\ndir=.\n[auth "client"]\ndomain=*\n{options}'))


def test_default_storage_is_not_overwritten() -> None:
    runtime = build_components(
        validate_config(
            {
                "account": {"dir": "."},
                "mgmt": {"default-storage": "selected"},
                "storage": {"selected": {"type": "none"}, "other": {"type": "none"}},
            }
        )
    )
    assert runtime.default_storage is runtime.storages["selected"]


def test_short_form_and_advanced_routing() -> None:
    short = build_components(
        validate_config({"account": {"dir": "."}, "verification": {"type": "http01"}})
    )
    assert list(short.validators) == ["default"]
    assert short.default_validator is short.validators["default"]
    runtime = build_components(
        validate_config(
            {
                "account": {"dir": "."},
                "verification": {
                    "default": "web",
                    "providers": {"web": {"type": "http01"}, "dns": {"type": "dns01-server"}},
                    "rules": [
                        {"wildcard": True, "provider": "dns"},
                        {"domains": ["mail.example.org"], "provider": "dns"},
                    ],
                },
                "policies": [{"domains": ["*"], "auth": {"all": {}}}],
            }
        )
    )
    router = runtime.auth.policies[0].verification
    assert router.select("www.example.org") is runtime.validators["web"]
    assert router.select("mail.example.org") is runtime.validators["dns"]
    assert router.select("*.example.org") is runtime.validators["dns"]


def test_policy_can_override_routing_without_combining_permissions() -> None:
    runtime = build_components(
        validate_config(
            {
                "account": {"dir": "."},
                "verification": {
                    "default": "web",
                    "providers": {"web": {"type": "http01"}, "dns": {"type": "dns01-server"}},
                },
                "policies": [
                    {
                        "domains": ["mail.example.org"],
                        "auth": {"all": {}},
                        "verification": {
                            "default": False,
                            "rules": [{"domains": ["mail.example.org"], "provider": "dns"}],
                        },
                    }
                ],
            }
        )
    )
    decision = runtime.auth.authorize(AuthenticationContext("127.0.0.1"), ["mail.example.org"])
    assert decision.policy.verification.select("mail.example.org") is runtime.validators["dns"]
    with pytest.raises(NoChallengeMethodsSupported):
        decision.policy.verification.select("www.example.org")
    assert (
        runtime.auth.authorize(
            AuthenticationContext("127.0.0.1"), ["mail.example.org", "www.example.org"]
        )
        is None
    )


def test_validation_does_not_construct_providers_or_touch_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from macen.challenges import HttpChallengeImplementor

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider constructed during validation")

    monkeypatch.setattr(HttpChallengeImplementor, "__init__", fail)
    validate_config({"account": {"dir": str(tmp_path / "account")}})
    assert not (tmp_path / "account").exists()


def test_duplicate_ini_section_rejected() -> None:
    with pytest.raises(ConfigurationError, match="Duplicate"):
        load_config(io.StringIO("[account]\ndir=.\n[account]\ndir=elsewhere"))
