"""INI/TOML loading and validation, separate from runtime construction.

Files are merged before references are resolved. Later scalar settings and named
providers replace earlier values; policies append in command-line order.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import importlib
import io
from pathlib import Path
import re
import sys
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar
import warnings

import pydantic

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[unresolved-import]

from .application import Components, build_components
from .auth import AuthenticationRegistry, MethodSpec, auth_methods
from .settings import (
    AccountConfig,
    ConfigurationError,
    MgmtConfig,
    StrictConfig,
    UnknownStorageError,
    UnknownVerificationError,
    UnusedOptionWarning,
    UnusedSectionWarning,
    aggregate,
    parse_group,
)

if TYPE_CHECKING:
    from .challenges import ChallengeImplementor
    from .storages import StorageImplementor

P = TypeVar("P", "ChallengeImplementor", "StorageImplementor")


class RouteConfig(StrictConfig):
    provider: str
    domains: list[str] = pydantic.Field(default_factory=list)
    wildcard: bool | None = None

    @pydantic.model_validator(mode="after")
    def needs_selector(self) -> "RouteConfig":
        if not self.domains and self.wildcard is None:
            raise ValueError("A verification rule needs domains or wildcard")
        return self


class RoutingConfig(StrictConfig):
    default: str | Literal[False] | None = None
    rules: list[RouteConfig] = pydantic.Field(default_factory=list)


class VerificationConfig(RoutingConfig):
    providers: dict[str, dict[str, Any]] = pydantic.Field(default_factory=dict)


class PolicyConfig(StrictConfig):
    name: str = ""
    domains: list[str] = pydantic.Field(default_factory=list)
    auth: dict[str, dict[str, Any]] = pydantic.Field(min_length=1)
    verification: str | RoutingConfig | None = None
    storage: str | None = None


class SetupConfig(StrictConfig):
    plugins: list[str] = pydantic.Field(default_factory=list, alias="plugin")
    include_paths: list[str] = pydantic.Field(default_factory=list, alias="include-path")


class AppConfig(StrictConfig):
    account: AccountConfig
    mgmt: MgmtConfig = pydantic.Field(default_factory=MgmtConfig)
    verification: VerificationConfig = pydantic.Field(default_factory=VerificationConfig)
    storage: dict[str, dict[str, Any]] = pydantic.Field(default_factory=dict)
    policies: list[PolicyConfig] = pydantic.Field(default_factory=list)
    logging: dict[str, str] = pydantic.Field(default_factory=dict)
    setup: SetupConfig = pydantic.Field(default_factory=SetupConfig)

    @property
    def keyfile(self) -> Path:
        return self.account.dir / "account.pem"

    @property
    def registration_file(self) -> Path:
        return self.account.dir / "registration.json"


@dataclass(frozen=True)
class ProviderSpec(Generic[P]):
    implementation: type[P]
    config: pydantic.BaseModel

    def build(self, name: str) -> P:
        return self.implementation(name, self.config)


@dataclass(frozen=True)
class ValidatedConfig:
    settings: AppConfig
    providers: dict[str, ProviderSpec["ChallengeImplementor"]]
    storages: dict[str, ProviderSpec["StorageImplementor"]]
    methods: tuple[tuple[MethodSpec, ...], ...]
    routes: tuple[RoutingConfig, ...]
    default_storage: str | None


def legacy_policy(name: str, options: Sequence[tuple[str, str]]) -> dict[str, Any]:
    """The only place that knows the old flat authentication option names."""
    values = aggregate(options)
    result: dict[str, Any] = {"name": name, "auth": {}}
    for old, new in (
        ("domain", "domains"),
        ("verification", "verification"),
        ("storage", "storage"),
    ):
        if old in values:
            result[new] = values.pop(old)
    if "domains" in result and isinstance(result["domains"], str):
        result["domains"] = [result["domains"]]
    if "ip" in values:
        ips = values.pop("ip")
        result["auth"]["ip"] = {"networks": ips if isinstance(ips, list) else [ips]}
    if "hmac_type" in values or "hmac_key" in values:
        hmac_settings = {}
        for old, new in (("hmac_type", "algorithm"), ("hmac_key", "secret")):
            if old in values:
                hmac_settings[new] = values.pop(old)
        result["auth"]["hmac"] = hmac_settings
    if "all" in values:
        if values.pop("all") not in ("yes", "true", True):
            raise ConfigurationError(f'auth "{name}": all must be yes')
        result["auth"]["all"] = {}
    if values:
        # Never include credential values in this error.
        raise ConfigurationError(f'auth "{name}": unknown options: {", ".join(values)}')
    return result


def read_ini(stream: io.TextIOBase) -> dict[str, Any]:
    sections: dict[str, list[tuple[str, str]]] = {}
    current: list[tuple[str, str]] | None = None
    for number, raw in enumerate(stream, 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            if name in sections:
                raise ConfigurationError(f"Duplicate INI section: {name}")
            current = sections[name] = []
        elif current is None:
            warnings.warn(f"Option without sections: {line}", UnusedOptionWarning, stacklevel=2)
        elif "=" not in line:
            raise ConfigurationError(f"Invalid INI option on line {number}")
        else:
            key, value = line.split("=", 1)
            current.append((key.strip(), value.strip()))

    data: dict[str, Any] = {}
    for section, options in sections.items():
        if section in ("account", "mgmt", "logging", "setup"):
            data[section] = aggregate(options)
            if section == "setup":
                for key, value in data[section].items():
                    if isinstance(value, str):
                        data[section][key] = [value]
            continue
        match = re.fullmatch(r'(auth|verification|storage) (?:"([^"]+)"|([^"].*))', section)
        if not match:
            warnings.warn(f"Unknown section name: {section}", UnusedSectionWarning, stacklevel=2)
            continue
        kind, quoted, plain = match.groups()
        name = quoted or plain
        if kind == "auth":
            data.setdefault("policies", []).append(legacy_policy(name, options))
        elif kind == "verification":
            data.setdefault("verification", {}).setdefault("providers", {})[name] = aggregate(
                options
            )
        else:
            data.setdefault("storage", {})[name] = aggregate(options)
    return data


def normalize(data: dict[str, Any]) -> dict[str, Any]:
    """Expand the short provider form to the same shape used by advanced configs."""
    verification = data.get("verification")
    if isinstance(verification, dict) and "type" in verification:
        if {"providers", "rules", "default"} & verification.keys():
            raise ConfigurationError("Inline verification cannot also define providers or rules")
        data["verification"] = {"default": "default", "providers": {"default": verification}}
    return data


def merge(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key == "policies":
            target.setdefault(key, []).extend(value)
        elif key == "verification":
            routing = target.setdefault(key, {})
            for option, setting in value.items():
                if option == "providers":
                    routing.setdefault(option, {}).update(setting)
                else:
                    routing[option] = setting
        elif key in ("account", "mgmt", "storage", "logging", "setup"):
            target.setdefault(key, {}).update(value)
        else:
            target[key] = value


def load_config(
    *sources: Path | str | io.TextIOBase,
    registry: AuthenticationRegistry = auth_methods,
) -> ValidatedConfig:
    data: dict[str, Any] = {}
    for source in sources:
        if isinstance(source, (str, Path)):
            with open(source, encoding="utf-8") as stream:
                part = (
                    tomllib.loads(stream.read())
                    if Path(source).suffix.lower() == ".toml"
                    else read_ini(stream)
                )
        else:
            name = getattr(source, "name", "")
            part = (
                tomllib.loads(source.read())
                if str(name).lower().endswith(".toml")
                else read_ini(source)
            )
        merge(data, normalize(part))
    return validate_config(data, registry=registry)


def validate_config(
    data: Mapping[str, Any], *, registry: AuthenticationRegistry = auth_methods
) -> ValidatedConfig:
    settings = AppConfig.model_validate(normalize(dict(data)))
    # Keep legacy warnings for non-auth options; authentication models are strict.
    for model in (settings.account, settings.mgmt):
        if model.model_extra:
            warnings.warn(
                f"{type(model).__name__}: Ignore extra options {model.model_extra}",
                UnusedOptionWarning,
                stacklevel=2,
            )
    from .challenges import implementors as challenge_types
    from .storages import implementors as storage_types

    providers = dict(settings.verification.providers)
    default = settings.verification.default
    if default is None:
        default = settings.mgmt.default_verification
    if default is None:
        if len(providers) == 1:
            default = next(iter(providers))
        else:
            default = "http" if "http" not in providers else "__default_http__"
            providers[default] = {"type": "http01"}
    settings.verification.default = default
    settings.verification.providers = providers

    storages = dict(settings.storage)
    storage_default = settings.mgmt.default_storage
    if storage_default is None:
        if len(storages) == 1:
            storage_default = next(iter(storages))
        else:
            storage_default = "none" if "none" not in storages else "__default_none__"
            storages[storage_default] = {"type": "none"}
    settings.storage = storages
    if storage_default is not False and storage_default not in storages:
        raise UnknownStorageError(f"Storage {storage_default!r} undefined")

    def specs(
        definitions: dict[str, dict[str, Any]], implementations: Mapping[str, type[P]]
    ) -> dict[str, ProviderSpec[P]]:
        result = {}
        for name, raw in definitions.items():
            options = dict(raw)
            kind = options.pop("type", None)
            if not isinstance(kind, str) or kind not in implementations:
                raise ConfigurationError(f"Unknown provider type {kind!r} for {name!r}")
            implementation = implementations[kind]
            result[name] = ProviderSpec(implementation, parse_group(implementation.Config, options))
        return result

    def check_route(route: RoutingConfig) -> None:
        references = [r.provider for r in route.rules]
        if isinstance(route.default, str):
            references.append(route.default)
        for name in references:
            if name not in providers:
                raise UnknownVerificationError(f"Validator {name!r} undefined")

    check_route(settings.verification)
    methods = []
    routes = []
    for policy in settings.policies:
        methods.append(
            tuple(registry.validate(kind, options) for kind, options in policy.auth.items())
        )
        route = policy.verification
        if route is None:
            route = RoutingConfig(default=default, rules=settings.verification.rules)
        elif isinstance(route, str):
            route = RoutingConfig(default=route)
        check_route(route)
        if not route.default and not route.rules:
            raise UnknownVerificationError(
                f'auth "{policy.name}" does not define a validator and the default one is disabled'
            )
        routes.append(route)
        storage = policy.storage if policy.storage is not None else storage_default
        if not storage or storage not in storages:
            raise UnknownStorageError(
                f'auth "{policy.name}": storage {storage!r} undefined or default one is disabled'
            )
    return ValidatedConfig(
        settings,
        specs(providers, challenge_types),
        specs(storages, storage_types),
        tuple(methods),
        tuple(routes),
        storage_default or None,
    )


def load_plugins(*sources: Path | str | io.TextIOBase) -> None:
    """Explicit startup hook for legacy setup plugins, before model validation.

    Validation itself never imports configured plugins or changes sys.path.
    """
    data: dict[str, Any] = {}
    for source in sources:
        if not isinstance(source, (str, Path)):
            raise ConfigurationError("Plugin setup requires configuration file paths")
        with open(source, encoding="utf-8") as stream:
            part = (
                tomllib.loads(stream.read())
                if Path(source).suffix.lower() == ".toml"
                else read_ini(stream)
            )
        data.update(part.get("setup", {}))
    setup = SetupConfig.model_validate(data)
    for path in reversed(setup.include_paths):
        sys.path.insert(0, path)
    for plugin in setup.plugins:
        importlib.import_module(plugin)


# Compatibility facade for callers constructing a configured runtime directly.
# New callers can validate with load_config() before build_components().
class Configurator(Components):
    parse_group = staticmethod(parse_group)

    def __init__(self, *sources: Path | str | io.TextIOBase) -> None:
        validated = load_config(*sources) if sources else validate_config({"account": {"dir": "."}})
        runtime = build_components(validated)
        super().__init__(
            runtime.settings,
            runtime.validators,
            runtime.default_validator,
            runtime.storages,
            runtime.default_storage,
            runtime.auth,
        )
