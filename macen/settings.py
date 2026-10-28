"""Configuration primitives shared by loaders and implementations (no runtime effects)."""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar
import warnings

import pydantic


class ConfigurationError(Exception):
    pass


class UnknownVerificationError(ConfigurationError):
    pass


class UnknownStorageError(ConfigurationError):
    pass


class ConfigurationWarning(UserWarning):
    pass


class UnusedOptionWarning(ConfigurationWarning):
    pass


class UnusedSectionWarning(ConfigurationWarning):
    pass


# Default config that should be used by all pydantic based config sections.
default_config: pydantic.ConfigDict = pydantic.ConfigDict(
    alias_generator=lambda n: n.replace("_", "-"), extra="allow"
)


def extract_bool(value: str | Any) -> bool | str | Any:  # noqa: ANN401
    if value in ("false", "no"):
        return False
    if value in ("true", "yes"):
        return True
    return value


class AccountConfig(pydantic.BaseModel):
    model_config = default_config.copy()

    acme_server: str = "https://acme-staging-v02.api.letsencrypt.org/directory"
    accept_terms_of_service: Annotated[
        bool | str | list[str], pydantic.AfterValidator(extract_bool)
    ] = False
    dir: Path


class MgmtConfig(pydantic.BaseModel):
    model_config = default_config.copy()

    max_size: pydantic.ByteSize = pydantic.ByteSize(4096)
    default_verification: Literal[False] | str | None = None
    default_storage: str | Literal[False] | None = None
    listeners: list[str] | str = pydantic.Field(
        default=["127.0.0.1:1313", "[::1]:1313"], alias="listener"
    )


T = TypeVar("T", bound=pydantic.BaseModel)


def aggregate(options: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """Normalize repeated INI keys, preserving native TOML values."""
    result: dict[str, Any] = {}
    for key, value in options:
        if isinstance(value, str) and not value.strip():
            value = False
        if key in result:
            previous = result[key]
            result[key] = [*previous, value] if isinstance(previous, list) else [previous, value]
        else:
            result[key] = value
    return result


def parse_group(model: type[T], options: Mapping[str, Any] | Sequence[tuple[str, Any]]) -> T:
    data = dict(options) if isinstance(options, Mapping) else aggregate(options)
    parsed = model.model_validate(data)
    if parsed.model_extra:
        warnings.warn(
            f"{model.__name__}: Ignore extra options {parsed.model_extra}",
            UnusedOptionWarning,
            stacklevel=2,
        )
    return parsed


class StrictConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(
        alias_generator=lambda n: n.replace("_", "-"), extra="forbid", hide_input_in_errors=True
    )
