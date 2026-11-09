"""Shared listener and logging setup helpers."""

from collections.abc import Generator
import logging
import logging.config
import logging.handlers
import socket
import sys
from typing import Any
import warnings

from .settings import ConfigurationError, UnusedOptionWarning

ListenerInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple]


def iter_addrinfo(listeners: str | list[str]) -> Generator[ListenerInfo, None, None]:
    if isinstance(listeners, str):
        listeners = [listeners]
    for listener in listeners:
        host, port = listener.rsplit(":", 1)
        if host[0] == "[" and host[-1] == "]":
            host = host[1:-1]
        for info in socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP):
            yield info


def configure_logging(config: list[tuple[str, str]]) -> None:
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
