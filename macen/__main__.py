#!/usr/bin/env python3
import argparse
import importlib.metadata
from threading import Thread

from .config import Configurator, iter_addrinfo
from .manager import ACMEManager
from .server import ACMEAbstractHandler, ACMEMgmtHandler, ThreadedACMEServerByType


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Basic Python Server to execute ACME instead of dump clients"
    )
    parser.add_argument(
        "configs",
        type=argparse.FileType("r"),
        nargs="+",
        metavar="CONFIG",
        help="file path to configuration file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + importlib.metadata.version("macen"),
    )

    args = parser.parse_args()

    config = Configurator(*args.configs)

    print("load account and init acme client ... ", end="", flush=True)
    ACMEAbstractHandler.manager = ACMEManager(config)
    print("done")

    for validator in config.validators.values():
        validator.start()

    mgmt_services: list[Thread] = []
    mgmt_threads: list[Thread] = []

    for mgmt_listen in iter_addrinfo(config.mgmt.listeners):
        mgmt_service = ThreadedACMEServerByType[mgmt_listen[0]](mgmt_listen[4], ACMEMgmtHandler)
        mgmt_services.append(mgmt_service)
        thread = Thread(
            target=mgmt_service.serve_forever, name="http service to server validation request"
        )
        mgmt_threads.append(thread)
        thread.start()

    print("running")

    try:
        import systemd.daemon

        systemd.daemon.notify("READY=1")
    except ImportError:
        pass  # systemd integration is optional

    finished = 0
    try:
        for thread, service in zip(list(mgmt_threads), list(mgmt_services), strict=True):
            thread.join()
            service.shutdown()
            finished += 1
    except KeyboardInterrupt:
        try:
            import systemd.daemon

            systemd.daemon.notify("STOPPING=1")
        except ImportError:
            pass  # systemd integration is optional
        for mgmt_service in mgmt_services[finished:]:
            mgmt_service.shutdown()


if __name__ == "__main__":
    main()
