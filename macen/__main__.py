#!/usr/bin/env python3
import argparse
import importlib.metadata
from pathlib import Path
import signal
from types import FrameType

from .application import Application, build_components
from .config import load_config, load_plugins
from .helpers import configure_logging


def notify(message: str) -> None:
    try:
        import systemd.daemon  # type: ignore[unresolved-import]
    except ImportError:
        return
    systemd.daemon.notify(message)


def request_shutdown(signum: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt


def main() -> None:
    parser = argparse.ArgumentParser(description="ACME issuance on behalf of simple clients")
    parser.add_argument(
        "configs", type=Path, nargs="+", metavar="CONFIG", help="INI or TOML configuration paths"
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration without starting listeners or contacting the CA",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + importlib.metadata.version("macen")
    )
    args = parser.parse_args()

    load_plugins(*args.configs)
    config = load_config(*args.configs)
    if args.check_config:
        print("Configuration valid")
        return
    configure_logging(list(config.settings.logging.items()))
    app = Application(build_components(config))
    previous = signal.signal(signal.SIGTERM, request_shutdown)
    try:
        app.start()
        notify("READY=1")
        app.wait()
    except KeyboardInterrupt:
        pass
    finally:
        notify("STOPPING=1")
        app.close()
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    main()
