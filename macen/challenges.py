"""Challenge selection, providers, and the resources they temporarily publish."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import partial
import http.server
import json
import os
from threading import Event, RLock, Thread
from typing import Any, cast
import urllib.request

import acme.challenges
import acme.messages
import josepy.jwk
import pydantic

from .exceptions import NoChallengeMethodsSupported
from .helpers import iter_addrinfo
from .server import ACMEHTTPHandler, ThreadedACMEServerByType
from .settings import ConfigurationError, default_config, parse_group


@dataclass(frozen=True)
class PreparedChallenge:
    challenge: acme.messages.ChallengeBody
    response: acme.challenges.ChallengeResponse
    cleanup: Callable[[], None]


class ChallengeImplementor:
    class Config(pydantic.BaseModel):
        model_config = default_config.copy()

    def __init__(
        self,
        name: str,
        options: pydantic.BaseModel | Mapping[str, Any] | Sequence[tuple[str, str]],
    ) -> None:
        self.name = name
        self.config = (
            options if isinstance(options, self.Config) else parse_group(self.Config, options)
        )
        self._lock = RLock()

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def prepare(
        self, authz: acme.messages.Authorization, key: josepy.jwk.JWK, domain: str
    ) -> PreparedChallenge | None:
        raise NotImplementedError


@dataclass(frozen=True)
class ChallengeRoute:
    provider: "ChallengeImplementor"
    domains: tuple[str, ...] = ()
    wildcard: bool | None = None

    def matches(self, identifier: str) -> bool:
        return (self.wildcard is None or identifier.startswith("*.") == self.wildcard) and (
            not self.domains
            or any(fnmatchcase(identifier.lower(), pattern.lower()) for pattern in self.domains)
        )


@dataclass(frozen=True)
class ChallengeRouter:
    default: "ChallengeImplementor | None"
    rules: tuple[ChallengeRoute, ...] = ()

    def select(self, identifier: str) -> "ChallengeImplementor":
        for rule in self.rules:
            if rule.matches(identifier):
                return rule.provider
        if self.default is not None:
            return self.default
        raise NoChallengeMethodsSupported(f"No verification route for {identifier}")


class HttpChallengeImplementor(ChallengeImplementor):
    class Config(ChallengeImplementor.Config):
        listeners: list[str] | str = pydantic.Field(
            default_factory=lambda: ["0.0.0.0:1380", "[::]:1380"], alias="listener"
        )

    config: Config

    def __init__(self, name: str, options: Any) -> None:  # noqa: ANN401
        super().__init__(name, options)
        self.responses: dict[str, dict[str, tuple[str, Event]]] = {}
        self._references: dict[tuple[str, str], int] = {}
        self._services: list[tuple[http.server.HTTPServer, Thread]] = []

    def start(self) -> list[tuple[http.server.HTTPServer, Thread]]:
        def bound_handler(*args: Any, **kwargs: Any) -> ACMEHTTPHandler:  # noqa: ANN401
            return ACMEHTTPHandler(self, *args, **kwargs)

        try:
            for info in iter_addrinfo(self.config.listeners):
                service = ThreadedACMEServerByType[info[0]](info[4], bound_handler)
                thread = Thread(
                    target=service.serve_forever, daemon=True, name="macen HTTP challenge"
                )
                try:
                    thread.start()
                except BaseException:
                    service.server_close()
                    raise
                self._services.append((service, thread))
        except BaseException:
            self.stop()
            raise
        return self._services

    def stop(self) -> None:
        for service, thread in self._services:
            service.shutdown()
            thread.join()
            service.server_close()
        self._services.clear()

    def prepare(
        self, authz: acme.messages.Authorization, key: josepy.jwk.JWK, domain: str
    ) -> PreparedChallenge | None:
        if authz.wildcard:
            return None
        for challenger in cast(tuple[acme.messages.ChallengeBody, ...], authz.challenges):
            challenge = challenger.chall
            if not isinstance(challenge, acme.challenges.HTTP01):
                continue
            domain = domain.lower()
            path = challenge.path
            with self._lock:
                self.responses.setdefault(domain, {})[path] = (challenge.validation(key), Event())
                token = (domain, path)
                self._references[token] = self._references.get(token, 0) + 1

            return PreparedChallenge(
                challenger, challenge.response(key), partial(self._release, token)
            )
        return None

    def _release(self, token: tuple[str, str]) -> None:
        with self._lock:
            self._references[token] -= 1
            if self._references[token] == 0:
                del self._references[token]
                domain, path = token
                del self.responses[domain][path]
                if not self.responses[domain]:
                    del self.responses[domain]

    def response_for(self, host: str, path: str) -> str:
        with self._lock:
            content, event = self.responses[host][path]
            event.set()
            return content


class DnsChallengeImplementor(ChallengeImplementor):
    def __init__(self, name: str, options: Any) -> None:  # noqa: ANN401
        super().__init__(name, options)
        self._records: dict[tuple[str, str], int] = {}

    def prepare(
        self, authz: acme.messages.Authorization, key: josepy.jwk.JWK, domain: str
    ) -> PreparedChallenge | None:
        for challenger in cast(tuple[acme.messages.ChallengeBody, ...], authz.challenges):
            challenge = challenger.chall
            if not isinstance(challenge, acme.challenges.DNS01):
                continue
            response, validation = challenge.response_and_validation(key)
            entry = challenge.validation_domain_name(domain.removeprefix("*.").lower()) + "."
            token = (entry, validation)
            with self._lock:
                if token not in self._records:
                    try:
                        self.add_entry(entry, validation)
                    except Exception:
                        # An update may have succeeded even if its response was lost.
                        self.remove_entry(entry, validation)
                        raise
                self._records[token] = self._records.get(token, 0) + 1

            return PreparedChallenge(challenger, response, partial(self._release, token))
        return None

    def _release(self, token: tuple[str, str]) -> None:
        with self._lock:
            self._records[token] -= 1
            if self._records[token] == 0:
                del self._records[token]
                self.remove_entry(*token)

    def add_entry(self, entry: str, value: str) -> None:
        raise NotImplementedError

    def remove_entry(self, entry: str, value: str) -> None:
        raise NotImplementedError


class DnsChallengeServerImplementor(DnsChallengeImplementor):
    class Config(ChallengeImplementor.Config):
        listeners: list[str] | str = pydantic.Field(
            default_factory=lambda: ["0.0.0.0:1353", "[::1]:1353"], alias="listener"
        )

    config: Config

    def __init__(self, name: str, options: Any) -> None:  # noqa: ANN401
        super().__init__(name, options)
        self.responses: dict[str, set[str]] = {}
        self._servers: list[Any] = []

    def start(self) -> None:
        import dnslib.server

        try:
            for info in iter_addrinfo(self.config.listeners):
                server = dnslib.server.DNSServer(self, port=info[4][1], address=info[4][0])
                self._servers.append(server)
                server.start_thread()
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        for server in self._servers:
            server.stop()
            server.server.server_close()
        self._servers.clear()

    def resolve(self, request: Any, handler: Any) -> Any:  # noqa: ANN401
        import dnslib

        question = request.q
        reply = request.reply()
        with self._lock:
            values = self.responses.get(str(question.qname).lower(), set())
            if values and question.qtype == dnslib.QTYPE.TXT:
                for value in sorted(values):
                    reply.add_answer(
                        dnslib.RR(question.qname, question.qtype, rdata=dnslib.TXT(value), ttl=5)
                    )
            elif question.qtype == dnslib.QTYPE.A:
                reply.add_answer(
                    dnslib.RR(
                        question.qname,
                        question.qtype,
                        rdata=dnslib.A(os.getenv("FAKE_DNS", "127.0.0.1")),
                        ttl=5,
                    )
                )
            else:
                reply.header.rcode = dnslib.RCODE.NXDOMAIN
        return reply

    def add_entry(self, entry: str, value: str) -> None:
        with self._lock:
            self.responses.setdefault(entry, set()).add(value)

    def remove_entry(self, entry: str, value: str) -> None:
        with self._lock:
            values = self.responses.get(entry)
            if values is not None:
                values.discard(value)
                if not values:
                    del self.responses[entry]


class DnsChalltestsrvImplementor(DnsChallengeImplementor):
    class Config(DnsChallengeImplementor.Config):
        set_txt_url: str = pydantic.Field(
            default="http://localhost:8055/set-txt", alias="set-txt_url"
        )
        clear_txt_url: str | None = pydantic.Field(default=None, alias="clear-txt_url")
        timeout: float = 5

    config: Config

    def _post(self, url: str, data: dict[str, str]) -> None:
        with urllib.request.urlopen(
            url, json.dumps(data).encode("utf-8"), timeout=self.config.timeout
        ) as response:
            if response.code != 200:
                raise ValueError("Challenge test server rejected DNS update")

    def add_entry(self, entry: str, value: str) -> None:
        self._post(self.config.set_txt_url, {"host": entry, "value": value})

    def remove_entry(self, entry: str, value: str) -> None:
        # The test server only supports clearing a whole host. Restore all values
        # still owned by other active authorizations while holding the provider lock.
        url = self.config.clear_txt_url or self.config.set_txt_url.rsplit("/", 1)[0] + "/clear-txt"
        self._post(url, {"host": entry})
        for (host, record), count in self._records.items():
            if host == entry and count:
                self.add_entry(host, record)


class DnsChallengeDnsUpdateImplementor(DnsChallengeImplementor):
    class Config(DnsChallengeImplementor.Config):
        dns_server: str = "127.0.0.1"
        ttl: int = 60
        timeout: int = 5

    config: Config

    def _update(self, entry: str, value: str, *, delete: bool) -> None:
        import dns.query
        import dns.rcode
        import dns.update

        update = dns.update.Update(self.select_zone(entry))
        if delete:
            update.delete(entry, "TXT", value)
        else:
            update.add(entry, self.config.ttl, "TXT", value)
        response = dns.query.tcp(update, self.config.dns_server, timeout=self.config.timeout)
        if response.rcode() != dns.rcode.NOERROR:
            raise ValueError(f"DNS update failed: {dns.rcode.to_text(response.rcode())}")

    def add_entry(self, entry: str, value: str) -> None:
        self._update(entry, value, delete=False)

    def remove_entry(self, entry: str, value: str) -> None:
        self._update(entry, value, delete=True)

    def select_zone(self, entry: str) -> str:
        return ".".join(entry.split(".")[-3:])


implementors: dict[str, type[ChallengeImplementor]] = {
    "http01": HttpChallengeImplementor,
    "dns01-challtestsrv": DnsChalltestsrvImplementor,
    "dns01-server": DnsChallengeServerImplementor,
    "dns01-dnsUpdate": DnsChallengeDnsUpdateImplementor,
}


def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> ChallengeImplementor:
    try:
        implementation = implementors[type]
    except KeyError:
        raise ConfigurationError(f"Unsupported challenge type {type!r}") from None
    return implementation(name, options)
