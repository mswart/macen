"""
This modules organize the decision making whether the signing request is
valid and should be processed or unauthorized and should be rejected.

The main external interfaced is constructed with the `.Authenticator`:
it tangles everything together. The `.Processor` implemented the generel
decision process by iterating through all available authentication blocks
and invokes every referenced auchentication mothod to execute it
authentication and autorisation itself.
"""

from fnmatch import fnmatch
import hashlib
import hmac
from io import BufferedIOBase
import logging
from types import TracebackType
from typing import TYPE_CHECKING, Literal, Protocol, Sequence, cast
import warnings

from cryptography import x509
from cryptography.x509.extensions import Extension, SubjectAlternativeName
from cryptography.x509.oid import ExtensionOID, NameOID
from IPy import IP

from . import exceptions

if TYPE_CHECKING:
    from typing import Self

    from .challenges import ChallengeImplementor
    from .config import Configurator
    from .storages import StorageImplementor

logger = logging.getLogger(__name__)


class Authenticator:
    """Cooridantes the authentication. It stores to configuration with all
    known authentication blocks.
    """

    def __init__(self, config: "Configurator") -> None:
        self.config: "Configurator" = config
        self.blocks: list[Block] = []

    def parse_block(self, name: str, options: list[tuple[str, str]]) -> None:
        self.blocks.append(Block(name, options, self.config))

    def process(
        self,
        client_address: tuple[str, int],
        headers: dict[str, str],
        rfile: BufferedIOBase,
    ) -> "Processor":
        """Executes the request authentication by delicating it to the
        `.Processor`.
        """
        return Processor(self, client_address, headers, rfile)


class Method(Protocol):
    @staticmethod
    def option_names() -> tuple[str, ...]: ...

    def possible(self, processor: "Processor") -> bool: ...
    def check(self, processor: "Processor") -> bool: ...
    def parse(self, option: str, value: str) -> None: ...


class IPAuthMethod:
    """Autentication by source IP"""

    @staticmethod
    def option_names() -> tuple[str, ...]:
        return ("ip",)

    def __init__(self, ips: list[IP] | None = None) -> None:
        self.ips = ips or []

    def parse(self, option: str, value: str) -> None:
        assert option == "ip"
        self.ips.append(IP(value))

    def possible(self, processor: "Processor") -> bool:
        return self.check(processor)

    def check(self, processor: "Processor") -> bool:
        cip = IP(processor.client_address[0])
        for ip in self.ips:
            if cip in ip:
                return True
        return False


class HmacAuthMethod:
    """Authentication by HMAC / secret key"""

    @staticmethod
    def option_names() -> tuple[str, ...]:
        return ("hmac_type", "hmac_key")

    def parse(self, option: str, value: str) -> None:
        if option == "hmac_type":
            self.name = value
            self.hmac = getattr(hashlib, self.name)
        elif option == "hmac_key":
            self.key = value.encode("utf-8")

    def parse_authentification_header(
        self, processor: "Processor"
    ) -> tuple[str | None, dict[str, str]]:
        if "Authentication" not in processor.headers:
            return (None, {})
        else:
            name, opts = processor.headers["Authentication"].split(" ", 1)
            opts = {opt.split("=")[0]: opt.split("=", 1)[1] for opt in opts.split(", ")}
            return name, opts

    def possible(self, processor: "Processor") -> bool:
        name, opts = self.parse_authentification_header(processor)
        if name != "hmac":
            return False
        if opts.get("name", None) != self.name:
            return False
        if "hash" not in opts:
            return False
        return True

    def check(self, processor: "Processor") -> bool:
        _name, opts = self.parse_authentification_header(processor)
        csrhash = hmac.new(self.key, processor.csrpem, digestmod=self.hmac).hexdigest()
        if hmac.compare_digest(csrhash, opts["hash"]):
            return True
        else:
            return False


class AllAuthMethod:
    """Allow all authentication"""

    @staticmethod
    def option_names() -> tuple[str, ...]:
        return ("all",)

    def parse(self, option: str, value: str) -> None:
        assert option == "all"
        assert value == "yes"

    def possible(self, processor: "Processor") -> Literal[True]:
        return True

    def check(self, processor: "Processor") -> Literal[True]:
        return True


class Block:
    """One authentication block - combination of authentications
    and list of allowed domains
    """

    validator: "ChallengeImplementor"
    storage: "StorageImplementor"

    def __init__(self, name: str, options: list[tuple[str, str]], config: "Configurator") -> None:
        self.name = name
        self.methods: list[Method] = []
        self.domain_matchers: list[str] = []
        self.parse(options, config)

    def possible(self, processor: "Processor") -> bool:
        if not self.domain_matchers:
            return False
        for method in self.methods:
            if not method.possible(processor):
                logger.debug("block %s excluded by %s", self.name, method.__class__.__name__)
                return False
        return True

    def check(self, processor: "Processor") -> bool:
        for method in self.methods:
            if not method.check(processor):
                return False
        # check matching of domain names
        for dns_name in processor.dns_names:
            for matcher in self.domain_matchers:
                if fnmatch(dns_name, matcher):
                    break
            else:
                return False
        return True

    def parse(self, options: Sequence[tuple[str, str]], config: "Configurator") -> None:
        unused_methods: list[type[Method]] = [IPAuthMethod, AllAuthMethod, HmacAuthMethod]
        validator = config.default_validator
        storage = config.default_storage
        for option, value in options:
            if option == "domain":
                self.domain_matchers.append(value)
                continue
            if option == "verification":
                try:
                    validator = config.validators[value.strip()]
                except KeyError:
                    from macen.config import UnknownVerificationError

                    raise UnknownVerificationError(
                        'Validator "{}" undefined'.format(value.strip())
                    ) from None
                continue
            if option == "storage":
                try:
                    storage = config.storages[value.strip()]
                except KeyError:
                    from macen.config import UnknownStorageError

                    raise UnknownStorageError(
                        'Storage "{}" undefined'.format(value.strip())
                    ) from None
                continue
            for method in self.methods:
                if option in method.option_names():
                    method.parse(option, value)
                    break
            else:  # no known method processes this option
                for method in unused_methods:
                    if option in method.option_names():
                        break
                else:
                    from macen.config import UnusedOptionWarning

                    warnings.warn(
                        'Option unknown [auth "{}"]{} = {}'.format(self.name, option, value),
                        UnusedOptionWarning,
                        stacklevel=2,
                    )
                    break
                unused_methods.remove(method)
                self.methods.append(method())
                self.methods[-1].parse(option, value)
        if validator is None:
            from macen.config import UnknownVerificationError

            raise UnknownVerificationError(
                'auth "{}" does not define a validator and the default one is disabled'.format(
                    self.name
                )
            )
        else:
            self.validator = validator
        if storage is None:
            from macen.config import UnknownStorageError

            raise UnknownStorageError(
                'auth "{}" does not define a storage and the default one is disabled'.format(
                    self.name
                )
            )
        else:
            self.storage = storage


class Processor:
    """Helper object to process a request, check authentication,
    reads and parse CSR
    """

    storage: "StorageImplementor"
    validator: "ChallengeImplementor"
    dns_names: list[str]
    common_name: str | bytes
    csrpem: bytes

    def __init__(
        self,
        auth: Authenticator,
        client_address: tuple[str, int],
        headers: dict[str, str],
        rfile: BufferedIOBase,
    ) -> None:
        self.auth = auth
        self.client_address = client_address
        self.headers = headers
        self.rfile = rfile

    def __enter__(self) -> "Self":
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass

    def acceptable(self) -> bool:
        """process the given request parameter for a CSR signing request and
        decide whether this request is allowed or not.

        :param client_ip str: The source IP of the client (TCP level)
        :param dict headers: The request header
        :param callable get_body: function to read in body (CSR)
        :return bool: whether request should be accepted
        """
        # 1. precheck
        possible_blocks: list[Block] = []
        for block in self.auth.blocks:
            if block.possible(self):
                possible_blocks.append(block)
        if not possible_blocks:
            return False
        # 2. process CSR
        try:
            self.read_and_parse_csr()
        except ValueError:
            raise exceptions.PayloadInvalid() from None
        self.accepted_block = None
        # 3. final check
        for block in possible_blocks:
            if block.check(self):
                self.validator = block.validator
                self.storage = block.storage
                return True
        return False

    def read_and_parse_csr(self) -> None:
        content_length = int(self.headers["Content-Length"])
        if self.auth.config and content_length > self.auth.config.mgmt.max_size:
            raise exceptions.PayloadToLarge(
                size=content_length, allowed=int(self.auth.config.mgmt.max_size)
            )
        self.csrpem = self.rfile.read(content_length)
        self.csr = x509.load_pem_x509_csr(self.csrpem)
        self.common_name = self.csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        try:
            extension = cast(
                Extension[SubjectAlternativeName],
                self.csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME),
            )
            self.dns_names = extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            self.dns_names = []
        if self.common_name not in self.dns_names and isinstance(self.common_name, str):
            self.dns_names.insert(0, self.common_name)
