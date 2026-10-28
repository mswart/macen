import http.server
import logging
import socket
import socketserver
from typing import TYPE_CHECKING, Any

from .auth import AuthenticationContext
from .exceptions import (
    AuthorizationDenied,
    ChallengeFailed,
    NoChallengeMethodsSupported,
    PayloadInvalid,
    PayloadToLarge,
    RateLimited,
)
from .issuance import IssuanceService

if TYPE_CHECKING:
    from .challenges import HttpChallengeImplementor

logger = logging.getLogger(__name__)


class ThreadedACMEServerInet4(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    issuance: IssuanceService
    max_size: int = 4096
    allow_reuse_address = True


class ThreadedACMEServerInet6(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    issuance: IssuanceService
    max_size: int = 4096
    allow_reuse_address = True
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
        http.server.HTTPServer.server_bind(self)


ThreadedACMEServerByType: dict[
    socket.AddressFamily, type[ThreadedACMEServerInet4] | type[ThreadedACMEServerInet6]
] = {
    socket.AF_INET: ThreadedACMEServerInet4,
    socket.AF_INET6: ThreadedACMEServerInet6,
}


class ACMEAbstractHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AcmeManager/0.1"

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
        host = host.split(":", 1)[0].lower()
        try:
            self.send_data(self.validator.response_for(host, self.path))
        except KeyError:
            self.send_error(404)


class ACMEMgmtHandler(ACMEAbstractHandler):
    server: ThreadedACMEServerInet4 | ThreadedACMEServerInet6

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
            # Body limits and framing are transport concerns, never auth plugin work.
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None:
                raise PayloadInvalid()
            try:
                length = int(lengths[0])
            except ValueError:
                raise PayloadInvalid() from None
            if length < 0:
                raise PayloadInvalid()
            if length > self.server.max_size:
                raise PayloadToLarge(length, self.server.max_size)
            body = self.rfile.read(length)
            if len(body) != length:
                raise PayloadInvalid()
            context = AuthenticationContext(self.client_address[0], dict(self.headers), body)
            certificate = self.server.issuance.sign(context)
            self.send_data(certificate)
            logger.info("Certificate delivered", extra=extra)
        except AuthorizationDenied:
            self.send_error(403)
        except PayloadToLarge as e:
            logger.warning(
                "Payload (CSR) to large (%s submitted > %s allowed)", e.size, e.allowed, extra=extra
            )
            self.send_error(413)
        except PayloadInvalid:
            logger.warning("Payload (CSR) could not be parsed", extra=extra)
            self.send_error(415)
        except (ChallengeFailed, NoChallengeMethodsSupported):
            logger.warning("Unable to validate wanted domains!")
            self.send_error(421, "Misdirected Request: Validation failed")
        except RateLimited:
            logger.warning("Payload (CSR) could not be parsed", extra=extra)
            self.send_error(429, "Certificate declined due to rate limiting")
        except Exception:
            logger.error("Unknown exception during request processing", exc_info=True, extra=extra)
            self.send_error(500)
