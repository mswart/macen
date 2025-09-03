import json
import os
from threading import Thread
from urllib.request import urlopen

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
import pytest

from macen import challenges, server
from tests.helpers import MA, M


class ACMEBackend:
    def __init__(self, name: str, endpoint: str, tos_prefix: str) -> None:
        self.name = name
        self.endpoint = endpoint
        self.tos_prefix = tos_prefix

    def __repr__(self) -> str:
        return "ACMEBackend<{}>".format(self.name)

    @property
    def challtestapi(self) -> str:
        port = os.getenv("CHALLTEST_PORT_" + self.name.upper(), 8055)
        return "http://127.0.0.1:" + str(port)

    def register_account(self, tmpdir_factory: str) -> None:
        account_dir = tmpdir_factory.mktemp("account-" + self.name)
        conf = """[account]
            dir = {}
            acme-server = {}
            [mgmt]\n""".format(account_dir, self.endpoint)
        m = M(conf)
        m.create_private_key()
        m.init_client()
        m.register(
            emails=["acme-{}-permanent@pytest{}.org".format(self.name, os.getpid())],
            tos_agreement=True,
        )
        self.registered_account = conf

    def registered_manager(
        self, validator: challenges.ChallengeImplementor | None = None
    ) -> server.ACMEManager:
        manager = MA(self.registered_account, validator=validator)
        server.ACMEAbstractHandler.manager = manager
        return manager

    def set_default_ipv4(self) -> None:
        """Configure the challengetest server to return the
        FAKE_DNS address if not otherwise specifed"""
        ip = os.getenv("FAKE_DNS")
        if not ip:
            return
        task = json.dumps({"ip": ip}).encode("utf-8")
        urlopen(self.challtestapi + "/set-default-ipv4", task)

    def add_servfail_response(self, host: str) -> None:
        if self.name == "pebble":
            urlopen(
                self.challtestapi + "/add-a",
                json.dumps({"host": host, "addresses": ["127.254.254.254"]}).encode("utf-8"),
            )
            return
        urlopen(self.challtestapi + "/set-servfail", json.dumps({"host": host}).encode("utf-8"))


test_backends: list[ACMEBackend] = [
    ACMEBackend("boulder", "http://127.0.0.1:4001/directory", "https:"),
    ACMEBackend("pebble", "https://127.0.0.1:14000/dir", "data:"),
]


@pytest.fixture(
    scope="session", name="backend", ids=[b.name for b in test_backends], params=test_backends
)
def acme_backend(request: pytest.FixtureRequest, tmpdir_factory: str) -> ACMEBackend:
    backend: ACMEBackend = request.param
    backend.register_account(tmpdir_factory)
    backend.set_default_ipv4()
    return backend


@pytest.fixture(scope="session", params=["rsa", "ec"])
def ckey(request: pytest.FixtureRequest) -> CertificateIssuerPrivateKeyTypes:
    if request.param == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
    if request.param == "ec":
        a = ec.generate_private_key(ec.SECP384R1(), default_backend())
        return a
    raise NotImplementedError()


@pytest.fixture(scope="session")
def http_server(request: pytest.FixtureRequest) -> challenges.HttpChallengeImplementor:
    validator = challenges.setup(
        "http01", "http", [("listener", os.getenv("FAKE_DNS", "127.0.0.1") + ":5002")]
    )
    services = validator.start()

    def fin() -> None:
        for service, thread in services:
            service.shutdown()
            thread.join()

    request.addfinalizer(fin)
    return validator


@pytest.fixture(scope="session")
def dnsboulder_validator(backend: ACMEBackend) -> challenges.DnsChallengeBoulderImplementor:
    validator = challenges.setup(
        "dns01-boulder", "dns", [("set-txt_url", backend.challtestapi + "/set-txt")]
    )
    validator.start()
    return validator


@pytest.fixture(scope="session")
def dnslib_validator() -> challenges.DnsChallengeServerImplementor:
    validator = challenges.setup(
        "dns01-server", "dns", [("listener", os.getenv("FAKE_DNS", "127.0.0.1") + ":5053")]
    )
    validator.start()
    return validator


MgmtServer = server.ThreadedACMEServerInet4


@pytest.fixture(scope="session")
def mgmt_server(request: pytest.FixtureRequest) -> MgmtServer:
    mgmt_service = server.ThreadedACMEServerInet4(("127.0.0.1", 0), server.ACMEMgmtHandler)
    thread = Thread(
        target=mgmt_service.serve_forever,
        daemon=True,
        name="http service to server validation request",
    )
    thread.start()

    def fin() -> None:
        mgmt_service.shutdown()
        thread.join()

    request.addfinalizer(fin)
    return mgmt_service
