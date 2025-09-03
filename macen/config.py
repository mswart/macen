"""
This module contains mainly the `.config.Configurator` class. It
parses configuration files. It valides all options are known and in the
correct format. It might raise a dedicated error or warning upon issues.

The parsed configuration is stored as instance variables and referenced
options are directly instanciated.
"""

from collections.abc import Generator
import importlib
import io
import logging
import logging.config
import logging.handlers
from pathlib import Path
import re
import socket
import sys
from typing import TYPE_CHECKING, Annotated, Any, Literal, Sequence, TypeVar
import warnings

import pydantic

from .auth import Authenticator

ListenerInfo = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
]

if TYPE_CHECKING:
    from .challenges import ChallengeImplementor
    from .storages import StorageImplementor


class ConfigurationError(Exception):
    pass


class MissingSectionError(ConfigurationError):
    pass


class UnknownVerificationError(ConfigurationError):
    pass


class UnknownStorageError(ConfigurationError):
    pass


class SingletonOptionRedifined(ConfigurationError):
    def __init__(self, section: str, option: str, old: Any, new: Any) -> None:  # noqa: ANN401 (value are for informational purpose only)
        self.section = section
        self.option = option
        self.old = old
        self.new = new

    def __str__(self) -> str:
        return "Singleton option redefined: {}.{} was {}, redefined as {}".format(
            self.section, self.option, self.old, self.new
        )


class ConfigurationWarning(UserWarning):
    pass


class UnusedOptionWarning(ConfigurationWarning):
    pass


class OptionRedifinitionWarning(ConfigurationWarning):
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


class Configurator:
    def __init__(self, *configs: io.TextIOBase) -> None:
        self.validators: "dict[str, ChallengeImplementor]" = {}
        self.default_validator: "ChallengeImplementor | None" = None
        self.storages: "dict[str, StorageImplementor]" = {}
        self.default_storage: "StorageImplementor | None" = None
        self.mgmt = MgmtConfig()

        self.auth = Authenticator(self)
        for config in configs:
            self.parse(config)

    @property
    def keyfile(self) -> Path:
        return self.account.dir / "account.pem"

    @property
    def registration_file(self) -> Path:
        return self.account.dir / "registration.json"

    def parse(self, config: io.TextIOBase) -> None:
        parsed_config = self.read_data(config)
        self.parse_setup_config(parsed_config.pop("setup", []))
        self.parse_logging_config(parsed_config.pop("logging", []))
        self.account = self.parse_group(AccountConfig, parsed_config.pop("account", []))
        self.mgmt = self.parse_group(MgmtConfig, parsed_config.pop("mgmt", []))
        special_group_re = re.compile(
            '^(?P<type>(auth|verification|storage)) (?P<opener>"?)(?P<name>.+)(?P=opener)$'
        )
        auth_blocks: list[tuple[str, list[tuple[str, str]]]] = []
        for group, options in parsed_config.items():
            match = special_group_re.match(group)
            if match:
                if match.group("type") == "auth":
                    # parse auth blocks last to have verification and storage blocks processed
                    auth_blocks.append((match.group("name"), options))
                elif match.group("type") == "verification":
                    self.parse_verification_group(match.group("name"), options)
                else:
                    self.parse_storage_group(match.group("name"), options)
            else:
                warnings.warn(
                    "Unknown section name: {0}".format(group), UnusedSectionWarning, stacklevel=2
                )

        self.setup_default_validator()
        self.setup_default_storage()

        for name, options in auth_blocks:
            self.auth.parse_block(name, options)

    @staticmethod
    def parse_group(model: type[T], options: Sequence[tuple[str, Any]]) -> T:
        aggregated: dict[str, list[Any] | Any] = {}
        for key, value in options:
            if key in aggregated:
                if not isinstance(aggregated[key], list):
                    aggregated[key] = [aggregated[key]]
                aggregated[key].append(value)
            elif not value.strip():
                aggregated[key] = False
            else:
                aggregated[key] = value
        parsed = model.model_validate(aggregated)
        if parsed.model_extra:
            warnings.warn(
                f"{model.__name__}: Ignore extra options {parsed.model_extra}",
                UnusedOptionWarning,
                stacklevel=2,
            )
        return parsed

    @staticmethod
    def read_data(config: io.TextIOBase) -> dict[str, list[tuple[str, str]]]:
        """Reads the given file name. It assumes that the file has a INI file
        syntax. The parser returns the data without comments and fill
        characters. It supports multiple option with the same name per
        section but not multiple sections with the same name."""
        sections: dict[str, list[tuple[str, str]]] = {}
        with config as f:
            section: str | None = None
            options: list[tuple[str, str]] = []
            for line in f:
                line = line.strip()
                # ignore comments:
                if line.startswith(("#", ";")):
                    continue
                if not line:
                    continue
                # handle section header:
                if line.startswith("[") and line.endswith("]"):
                    if section:  # save old section data
                        sections[section] = options
                    section = line[1:-1]
                    options = []
                    continue
                if section is None:
                    warnings.warn(
                        "Option without sections: {0}".format(line),
                        UnusedOptionWarning,
                        stacklevel=2,
                    )
                    continue
                option, value = line.split("=", 1)
                options.append((option.strip(), value.strip()))
            if section:  # save old section data
                sections[section] = options
        return sections

    def parse_setup_config(self, config: list[tuple[str, str]]) -> None:
        for option, value in config:
            if option == "include-path":
                sys.argv.insert(0, value)
            elif option == "plugin":
                importlib.import_module(value)
            else:
                warnings.warn(
                    "Option unknown [{}]{} = {}".format("setup", option, value),
                    UnusedOptionWarning,
                    stacklevel=2,
                )

    def parse_logging_config(self, config: list[tuple[str, str]]) -> None:
        level = None
        destination = None
        format = None
        config_file = None
        for option, value in config:
            if option == "level":
                level = value.upper()
            elif option == "destination":
                destination = value
            elif option == "format":
                format = value
            elif option == "config-file":
                config_file = value
            else:
                warnings.warn(
                    "Option unknown [{}]{} = {}".format("logging", option, value),
                    UnusedOptionWarning,
                    stacklevel=2,
                )
        if config_file:
            if level or destination:
                warnings.warn(
                    "logging: external config will be used - other logging settings like level and destination will be ignored",
                    UnusedOptionWarning,
                    stacklevel=2,
                )
            logging.config.fileConfig(config_file)
        else:
            opts: dict[str, Any] = {}
            if destination == "syslog":
                opts = {"handlers": [logging.handlers.SysLogHandler("/dev/log")]}
            elif destination == "stdout":
                opts = {"handlers": [logging.StreamHandler(sys.stdout)]}
            elif destination == "stderr":
                opts = {"handlers": [logging.StreamHandler(sys.stderr)]}
            elif destination == "journalctl":
                try:
                    import systemd.journal  # type: ignore  # noqa: PGH003
                except ImportError:
                    raise ConfigurationError(
                        "systemd python module required to log to journalctl"
                    ) from None
                opts = {"handlers": [systemd.journal.JournalHandler()]}  # type: ignore  # noqa: PGH003
            elif destination:  # normal file:
                opts = {"filename": destination}
            else:  # reuse loggings default destination (stderr)
                opts = {}
            if format:
                opts["format"] = format
            logging.basicConfig(level=level or "WARNING", **opts)

    def parse_verification_group(self, name: str, options: list[tuple[str, str]]) -> None:
        option, value = options.pop(0)
        if option != "type":
            raise ConfigurationError("A verification must start with the type value!")
        from .challenges import setup

        self.validators[name] = setup(value, name, options)

    def setup_default_validator(self) -> None:
        if self.mgmt.default_verification is False:  # default validator disabled
            self.default_validator = None
            return
        if self.mgmt.default_verification:  # defined
            self.default_validator = self.validators[self.mgmt.default_verification]
            return
        if len(self.validators) == 1:  # we use the only defined validator as default
            self.default_validator = next(iter(self.validators.values()))
        else:  # define a default http storage
            from .challenges import setup

            self.default_validator = self.validators["http"] = setup("http01", "http", [])

    def parse_storage_group(self, name: str, options: list[tuple[str, str]]) -> None:
        option, value = options.pop(0)
        if option != "type":
            raise ConfigurationError("A storage must start with the type value!")
        from .storages import setup

        self.storages[name] = setup(value, name, options)

    def setup_default_storage(self) -> None:
        if self.mgmt.default_storage is False:  # default storage disabled
            self.default_storage = None
            return
        if self.mgmt.default_storage:
            self.default_storage = self.storages[self.mgmt.default_storage]
        if len(self.storages) == 1:
            self.default_storage = next(iter(self.storages.values()))
        else:
            from .storages import setup

            self.default_storage = self.storages["none"] = setup("none", "none", [])


def iter_addrinfo(listeners: str | list[str]) -> Generator[ListenerInfo, None, None]:
    if isinstance(listeners, str):
        listeners = [listeners]
    for listener in listeners:
        host, port = listener.rsplit(":", 1)
        if host[0] == "[" and host[-1] == "]":
            host = host[1:-1]
        for info in socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP):
            yield info
