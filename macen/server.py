import http.server
import logging
import socket
import socketserver
from typing import TYPE_CHECKING, Any

from .auth import Authenticator
from .exceptions import ChallengeFailed, PayloadInvalid, PayloadToLarge, RateLimited
from .manager import ACMEManager

if TYPE_CHECKING:
    from .challenges import HttpChallengeImplementor

logger = logging.getLogger(__name__)


class ThreadedACMEServerInet4(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadedACMEServerInet6(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
        http.server.HTTPServer.server_bind(self)


ThreadedACMEServerByType: dict[socket.AddressFamily, type[http.server.HTTPServer]] = {
    socket.AF_INET: ThreadedACMEServerInet4,
    socket.AF_INET6: ThreadedACMEServerInet6,
}


class ACMEAbstractHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AcmeManager/0.1"
    manager: ACMEManager

    def send_data(
        self, data: bytes | str, content_type: str = "text/plain", response_code: int = 200
    ) -> None:
        """Helper method to send data as HTTP response. The data are
        transfered as :mimetype:`text/plain`.

        :param str data: The text to send as :py:obj:`Python String <str>`.
        :param int response_code: HTTP response code"""
        if type(data) is not bytes:
            data = str(data).encode("utf-8")
        self.send_response(response_code)
        self.send_header("Content-type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ACMEHTTPHandler(ACMEAbstractHandler):
    def __init__(self, validator: "HttpChallengeImplementor", *args: Any, **kwargs: Any) -> None:  # noqa: ANN401 (we delegate parameters)
        self.validator = validator
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        """Handles POST request (upload files)."""
        host: str = self.headers["Host"]
        if host.endswith(":5002"):
            host = host[:-5]
        try:
            self.send_data(self.validator.response_for(host, self.path))
        except KeyError:
            self.send_error(404)


class ACMEMgmtHandler(ACMEAbstractHandler):
    @property
    def auth(self) -> Authenticator:
        return self.manager.config.auth

    def do_POST(self) -> None:
        """Handles POST request (upload files)."""
        extra: dict[str, Any] = {
            "client_ip": self.client_address,
            "path": self.path,
            "endpoint": "macen",
            "host": self.headers.get("Host", "<unknown>"),
        }
        if self.path != "/sign":
            logger.warning('Unknown request URL "%s"', self.path, extra=extra)
            self.send_error(404)
            return
        try:
            with self.auth.process(self.client_address, self.headers, self.rfile) as p:
                if not p.acceptable():
                    self.send_error(403)
                    return
                logger.info(
                    "Sign request is valid (CN=%s, DNS=%s)",
                    p.common_name,
                    ", ".join(p.dns_names),
                    extra=extra,
                )
                cached_certs = p.storage.from_cache(p.csrpem)
                if cached_certs:
                    logger.info("Redeliver already issued certificate", extra=extra)
                    self.send_data(cached_certs)
                    return
                order = self.manager.acquire_domain_validations(p.validator, p.csrpem)
                certs = self.manager.issue_certificate(order)
                p.storage.add_to_cache(p.csrpem, certs)
                logger.info("New certificate issued", extra=extra)
                self.send_data(certs)
        except PayloadToLarge as e:
            logger.warning(
                "Payload (CSR) to large (%s submitted > %s allowed)", e.size, e.allowed, extra=extra
            )
            self.send_error(413)
        except PayloadInvalid:
            logger.warning("Payload (CSR) could not be parsed", extra=extra)
            self.send_error(415)
        except ChallengeFailed:
            logger.warning("Unable to validate wanted domains!")
            self.send_error(421, "Misdirected Request: Validation failed")
        except RateLimited:
            logger.warning("Payload (CSR) could not be parsed", extra=extra)
            self.send_error(429, "Certificate declined due to rate limiting")
        except Exception:
            logger.error("Unknown exception during request processing", exc_info=True, extra=extra)
            self.send_error(500)
