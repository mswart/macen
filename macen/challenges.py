from abc import abstractmethod
import http.server
import json
import os
import socket
from threading import Event, Thread
from typing import Any, Literal, Sequence, cast, overload
import urllib.request

import acme.challenges
import acme.client
import acme.messages
import josepy.jwk
import pydantic

from .config import ConfigurationError, Configurator, default_config, iter_addrinfo
from .server import ACMEHTTPHandler, ThreadedACMEServerByType

ListenerInfo = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
]


class ChallengeImplementor:
    class Config(pydantic.BaseModel):
        model_config = default_config.copy()

    def __init__(self, name: str, options: Sequence[tuple[str, str]]) -> None:
        self.name = name
        self.config = Configurator.parse_group(self.Config, options)

    @abstractmethod
    def start(self) -> Any: ...  # noqa: ANN401 (depends on implementation)

    @abstractmethod
    def new_authorization(
        self,
        authz: acme.messages.Authorization,
        client: acme.client.ClientV2,
        key: josepy.jwk.JWK,
        domain: str,
    ) -> bool: ...


class HttpChallengeImplementor(ChallengeImplementor):
    class Config(ChallengeImplementor.Config):
        listeners: list[str] | str = pydantic.Field(
            default_factory=lambda: ["0.0.0.0:1380", "[::]:1380"], alias="listener"
        )

    config: Config
    responses: dict[str, dict[str, tuple[str, Event]]]

    def start(self) -> list[tuple[http.server.HTTPServer, Thread]]:
        services: list[tuple[http.server.HTTPServer, Thread]] = []

        def bound_handler(*args: Any, **kwargs: Any) -> ACMEHTTPHandler:  # noqa: ANN401 (we just delegate)
            return ACMEHTTPHandler(self, *args, **kwargs)

        for info in iter_addrinfo(self.config.listeners):
            http_service = ThreadedACMEServerByType[info[0]](info[4], bound_handler)
            thread = Thread(
                target=http_service.serve_forever,
                daemon=True,
                name="http service to server validation request",
            )
            thread.start()
            services.append((http_service, thread))
        self.responses = {}
        return services

    def new_authorization(
        self,
        authz: acme.messages.Authorization,
        client: acme.client.ClientV2,
        key: josepy.jwk.JWK,
        domain: str,
    ) -> bool:
        for challenger in cast(tuple[acme.messages.ChallengeBody, ...], authz.challenges):
            challenge = challenger.chall
            if isinstance(challenge, acme.challenges.HTTP01):
                # store (and deliver) needed response for challenge
                content = challenge.validation(key)
                event = Event()
                self.responses.setdefault(domain, {})
                self.responses[domain][challenge.path] = (content, event)

                # answer challenges / give ACME server go to check challenge
                resp = challenge.response(key)
                client.answer_challenge(challenger, resp)

                return True
        else:
            return False

    def response_for(self, host: str, path: str) -> str:
        """request a response for a given request

        :param str host: Hostname of the request
        :param str path: Requested path (e.g. /.well-known/acme-challenges/?)
        :raises KeyError: Unknown host or path; return 404
        """
        content, event = self.responses[host][path]
        event.set()
        return content


class DnsChallengeImplementor(ChallengeImplementor):
    """WIP"""

    def start(self) -> None:
        pass

    def new_authorization(
        self,
        authz: acme.messages.Authorization,
        client: acme.client.ClientV2,
        key: josepy.jwk.JWK,
        domain: str,
    ) -> bool:
        for challenger in cast(tuple[acme.messages.ChallengeBody, ...], authz.challenges):
            challenge = challenger.chall
            if isinstance(challenge, acme.challenges.DNS01):
                response, validation = challenge.response_and_validation(key)

                self.add_entry(challenge.validation_domain_name(domain) + ".", validation)

                # answer challenges / give ACME server go to check challenge
                client.answer_challenge(challenger, response)

                return True
        else:
            return False

    @abstractmethod
    def add_entry(self, entry: str, value: str) -> None:
        pass


class DnsChallengeServerImplementor(DnsChallengeImplementor):
    class Config(ChallengeImplementor.Config):
        listeners: list[str] | str = pydantic.Field(
            default_factory=lambda: ["0.0.0.0:1353", "[::1]:1380"]
        )

    config: Config
    responses: "dict[tuple[dnslib.DNSLabel, dnslib.CLASS, dnslib.QTYPE], dnslib.DNSRecord]"  # type: ignore  # noqa: F821, PGH003

    def start(self) -> None:
        import dnslib.server  # type: ignore  # noqa: PGH003

        self.responses = {}
        for info in iter_addrinfo(self.config.listeners):
            server = dnslib.server.DNSServer(self, port=info[4][1], address=info[4][0])
            server.start_thread()

    def resolve(self, request: Any, handler: Any) -> None:  # noqa: ANN401
        import dnslib  # type: ignore  # noqa: PGH003

        question = request.q
        lookup = (question.qname, question.qclass, question.qtype)
        reply = request.reply()
        if lookup in self.responses:
            reply.add_answer(
                dnslib.RR(question.qname, question.qtype, rdata=self.responses[lookup], ttl=5)
            )
        elif question.qtype == dnslib.QTYPE.A:  # type: ignore  # noqa: PGH003
            reply.add_answer(
                dnslib.RR(
                    question.qname,
                    question.qtype,
                    rdata=dnslib.A(os.getenv("FAKE_DNS", "127.0.0.1")),
                    ttl=5,
                )
            )
        else:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN  # type: ignore  # noqa: PGH003
        return reply

    def add_entry(self, entry: str, value: str) -> None:
        import dnslib  # type: ignore  # noqa: PGH003

        self.responses[(dnslib.DNSLabel(entry), dnslib.CLASS.IN, dnslib.QTYPE.TXT)] = dnslib.TXT(  # type: ignore  # noqa: PGH003
            value
        )


class DnsChalltestsrvImplementor(DnsChallengeImplementor):
    class Config(DnsChallengeImplementor.Config):
        set_txt_url: str = pydantic.Field(
            default="http://localhost:8055/set-txt", alias="set-txt_url"
        )

    config: Config

    def add_entry(self, entry: str, value: str) -> None:
        task = json.dumps({"host": entry, "value": value}).encode("utf-8")

        response = urllib.request.urlopen(self.config.set_txt_url, task)
        assert response.code == 200


class DnsChallengeDnsUpdateImplementor(DnsChallengeImplementor):
    class Config(DnsChallengeImplementor.Config):
        dns_server: str = "127.0.0.1"
        ttl: int = 60
        timeout: int = 5

    config: Config

    def add_entry(self, entry: str, value: str) -> None:
        import dns
        import dns.query
        import dns.update

        upd = dns.update.Update(
            self.select_zone(entry),
            # keyring=dns.tsigkeyring.from_text({keyname: key}),
            # keyalgorithm=algo)
        )
        upd.add(entry, self.config.ttl, "TXT", value)
        try:
            response = dns.query.tcp(upd, self.config.dns_server, timeout=self.config.timeout)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                rcode_text = dns.rcode.to_text(rcode)
                raise ValueError(rcode_text)
            return response
        except Exception as e:
            raise ValueError("could not update {}: {}".format(e.__class__.__name__, e)) from None

    def select_zone(self, entry: str) -> str:
        parts = entry.split(".")
        return ".".join(parts[-3:])


implementors: dict[str, type[ChallengeImplementor]] = {
    "http01": HttpChallengeImplementor,
    "dns01-challtestsrv": DnsChalltestsrvImplementor,
    "dns01-server": DnsChallengeServerImplementor,
    "dns01-dnsUpdate": DnsChallengeDnsUpdateImplementor,
}


@overload
def setup(
    type: Literal["http01"], name: str, options: Sequence[tuple[str, str]]
) -> HttpChallengeImplementor: ...
@overload
def setup(
    type: Literal["dns01-challtestsrv"], name: str, options: Sequence[tuple[str, str]]
) -> DnsChalltestsrvImplementor: ...
@overload
def setup(
    type: Literal["dns01-server"], name: str, options: Sequence[tuple[str, str]]
) -> DnsChallengeServerImplementor: ...
@overload
def setup(
    type: Literal["dns01-dnsUpdate"], name: str, options: Sequence[tuple[str, str]]
) -> DnsChallengeDnsUpdateImplementor: ...
@overload
def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> ChallengeImplementor: ...


def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> ChallengeImplementor:
    try:
        return implementors[type](name, options)
    except KeyError:
        raise ConfigurationError('Unsupported challenge type "{}"'.format(type)) from None
