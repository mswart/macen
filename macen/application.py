"""Explicit application construction and ownership of runtime resources."""

from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING

from .auth import AllOf, Policy, PolicyEvaluator
from .challenges import ChallengeRoute, ChallengeRouter
from .helpers import iter_addrinfo
from .settings import AccountConfig, MgmtConfig

if TYPE_CHECKING:
    from .challenges import ChallengeImplementor
    from .config import AppConfig, ValidatedConfig
    from .storages import StorageImplementor


@dataclass
class Components:
    settings: "AppConfig"
    validators: "dict[str, ChallengeImplementor]"
    default_validator: "ChallengeImplementor | None"
    storages: "dict[str, StorageImplementor]"
    default_storage: "StorageImplementor | None"
    auth: PolicyEvaluator

    @property
    def account(self) -> AccountConfig:
        return self.settings.account

    @property
    def mgmt(self) -> MgmtConfig:
        return self.settings.mgmt

    @property
    def keyfile(self) -> Path:
        return self.settings.keyfile

    @property
    def registration_file(self) -> Path:
        return self.settings.registration_file


def build_components(config: "ValidatedConfig") -> Components:
    providers = {name: spec.build(name) for name, spec in config.providers.items()}
    storages = {name: spec.build(name) for name, spec in config.storages.items()}
    settings = config.settings
    policies = []
    for policy, methods, routing in zip(
        settings.policies, config.methods, config.routes, strict=True
    ):
        router = ChallengeRouter(
            providers.get(routing.default),
            tuple(
                ChallengeRoute(providers[r.provider], tuple(r.domains), r.wildcard)
                for r in routing.rules
            ),
        )
        storage = storages[policy.storage or config.default_storage]
        policies.append(
            Policy(
                policy.name,
                AllOf(tuple(m.build() for m in methods)),
                tuple(policy.domains),
                router,
                storage,
            )
        )
    return Components(
        settings,
        providers,
        providers.get(settings.verification.default),
        storages,
        storages.get(config.default_storage),
        PolicyEvaluator(policies),
    )


class Application:
    def __init__(self, components: Components) -> None:
        self.components = components
        self.resources = ExitStack()
        self.threads: list[Thread] = []

    def start(self) -> None:
        from .issuance import IssuanceService
        from .manager import ACMEManager
        from .server import ACMEMgmtHandler, ThreadedACMEServerByType

        try:
            manager = ACMEManager(self.components.settings)
            service = IssuanceService(self.components.auth, manager)
            for provider in self.components.validators.values():
                self.resources.callback(provider.stop)
                provider.start()
            for info in iter_addrinfo(self.components.mgmt.listeners):
                server = ThreadedACMEServerByType[info[0]](info[4], ACMEMgmtHandler)
                server.issuance = service
                server.max_size = int(self.components.mgmt.max_size)
                self.resources.callback(server.server_close)
                thread = Thread(target=server.serve_forever, name="macen management", daemon=True)
                thread.start()
                self.resources.callback(thread.join)
                self.resources.callback(server.shutdown)
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise

    def wait(self) -> None:
        for thread in self.threads:
            thread.join()

    def close(self) -> None:
        self.resources.close()
