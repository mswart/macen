from datetime import datetime, timedelta
import logging
import os.path
import sys
from typing import TYPE_CHECKING, Any, Literal, cast

if sys.version_info >= (3, 11):
    from datetime import UTC
else:
    from datetime import timezone

    UTC: timezone = timezone.utc

import acme.client
import acme.errors
import acme.messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as pem_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy.jwk
import josepy.util

from .config import Configurator
from .exceptions import (
    AccountError,
    ChallengeFailed,
    InvalidDomainName,
    NeedToAgreeToTOS,
    NoChallengeMethodsSupported,
    RateLimited,
)

if TYPE_CHECKING:
    from .challenges import ChallengeImplementor

logger = logging.getLogger(__name__)


class ACMEManager:
    """ACME manager - high level ACME client; process authorizations automatically."""

    def __init__(self, config: Configurator, connect: bool = True) -> None:
        self.responses: dict[str, dict[str, Any]] = {}
        self.authzrs: dict[str, acme.messages.AuthorizationResource] = {}
        self.config = config
        if connect:
            self.connect()

    # ----------------------------------------------------------
    # 1. generall ACME account handling (keys, registration ...)
    # ----------------------------------------------------------

    def connect(self) -> None:
        """initialize/setup ourself; load private key, create ACME client
        and refresh our registration
        """
        if self.account_key_created():
            self.load_private_key()
        else:
            self.create_private_key()
        self.init_client()
        if self.account_registered():
            self.refresh_registration()
        else:
            self.register()

    def load_private_key(self) -> None:
        """load our private key / the key to identify ourself against
        the ACME server. This key MUST NOT be used for certificates.
        """
        try:
            with open(self.config.keyfile, "rb") as f:
                key = pem_serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
        except FileNotFoundError:
            raise AccountError("Key {} not found".format(self.config.keyfile)) from None
        # TODO - handle IOError; keyfile without valid key
        self.key = josepy.jwk.JWKRSA(key=josepy.util.ComparableRSAKey(key))

    def account_key_created(self) -> bool:
        return os.path.isfile(self.config.keyfile)

    def create_private_key(self, force: bool = False, key_size: int = 4096) -> None:
        """create new private key to be used for identify ourself against
        the ACME server

        Key is afterwards read via `load_private_key`!

        :param bool force: create new key even key exists already
        :param int key_size: private key size in bits (at least 2048)
        """
        if self.account_key_created() and not force:
            raise AccountError("Existing key is only override if I am forced to")
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        self.config.account.dir.mkdir(parents=True, exist_ok=True)
        with open(self.config.keyfile, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=pem_serialization.Encoding.PEM,
                    format=pem_serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=pem_serialization.NoEncryption(),
                )
            )
        # verify that everythings works by reading the key from disk
        self.load_private_key()

    @property
    def directory(self) -> acme.messages.Directory:
        return acme.messages.Directory.from_json(
            acme.client.ClientNetwork(None, verify_ssl=os.getenv("ACME_CAFILE", True))
            .get(self.config.account.acme_server)
            .json()
        )

    def init_client(self) -> None:
        """create ACME client"""
        net = acme.client.ClientNetwork(self.key, verify_ssl=os.getenv("ACME_CAFILE", True))
        directory = acme.messages.Directory.from_json(
            net.get(self.config.account.acme_server).json()
        )
        self.client = acme.client.ClientV2(directory, net)

    def register(
        self,
        emails: list[str] | None = None,
        tos_agreement: list[str] | bool | str | None = None,
    ) -> None:
        agreed_tos = tos_agreement or self.config.account.accept_terms_of_service
        if agreed_tos is True:
            tos_accepted = True
        elif isinstance(agreed_tos, str):
            tos_accepted = self.directory.meta.terms_of_service == agreed_tos
        elif isinstance(agreed_tos, list):
            tos_accepted = self.directory.meta.terms_of_service in agreed_tos
        else:
            tos_accepted = False

        resource = acme.messages.NewRegistration(
            key=self.key.public_key(),
            contact=tuple(["mailto:{}".format(mail) for mail in emails or []]),
            terms_of_service_agreed=tos_accepted,
        )
        try:
            self.registration = self.client.new_account(resource)
        except acme.messages.Error as err:
            if err.typ == "urn:ietf:params:acme:error:agreementRequired":
                raise NeedToAgreeToTOS(self.client.directory.meta.terms_of_service) from None
            elif (
                err.typ == "urn:ietf:params:acme:error:malformed"
                and "must agree to terms of service" in err.detail
            ):
                # fallback (agreementRequired isn't standardized)
                raise NeedToAgreeToTOS(self.client.directory.meta.terms_of_service) from None
            raise
        self.dump_registration()

    def tos_agreement_required(self) -> None | Literal[False] | str:
        if "terms_of_service" not in self.directory.meta:
            return None
        if not hasattr(self, "registration"):
            return cast(str, self.directory.meta.terms_of_service)
        return False

    def accept_terms_of_service(self, url: str) -> None:
        assert url is not False
        self.registration.body.update(terms_of_service_agreed=True)
        self.dump_registration()

    def account_registered(self) -> bool:
        return os.path.isfile(self.config.registration_file)

    def dump_registration(self) -> None:
        with open(self.config.registration_file, "w") as f:
            f.write(self.registration.json_dumps_pretty())
        self.client.net.account = self.registration

    def refresh_registration(self) -> None:
        # return
        # Register or validate and update our registration.
        existing_regr = None

        # Validate existing registration by querying for it from the server.
        try:
            with open(self.config.registration_file, "r") as f:
                self.registration = acme.messages.RegistrationResource.json_loads(f.read())
        except FileNotFoundError:
            raise AccountError("Key is not yet registered or registration is losted!") from None
        existing_regr = self.registration.json_dumps()
        self.client.net.account = self.registration
        self.registration = self.client.query_registration(self.registration)

        if existing_regr != self.registration.json_dumps():
            self.dump_registration()

        # the terms of server needs to be agreed to use the ACME server!
        if tos := self.tos_agreement_required():
            raise NeedToAgreeToTOS(tos)

    # ---------------------------------------------------------
    # 2. the real part (handling authorizations + certificates)
    # ---------------------------------------------------------

    def acquire_domain_validations(
        self, validator: "ChallengeImplementor", csrpem: bytes
    ) -> acme.messages.OrderResource:
        """requests for all given domains domain validations
        If we have cached a valid challenge return this.
        Expired challenges will clear automatically; invalided challenges
        will not.
        """
        logger.info("Requesting a new order for a certificate")
        try:
            order = self.client.new_order(csrpem)
        except acme.messages.Error as e:
            logger.info("Request for a new order has been declined")
            if e.typ == "urn:ietf:params:acme:error:rejectedIdentifier":
                raise InvalidDomainName("unknown", e.detail) from None
            elif e.typ == "urn:ietf:params:acme:error:rateLimited":
                logger.warning("New certificate rejected due to rate limiting")
                raise RateLimited(e.detail) from None
            raise
        for authz in cast(tuple[acme.messages.AuthorizationResource, ...], order.authorizations):
            domain = authz.body.identifier.value
            logger.info("processing authorization for %s", domain)
            if not validator.new_authorization(authz.body, self.client, self.key, domain):
                # HTTP01 is not support; no clue what to do ...
                raise NoChallengeMethodsSupported(
                    "No supported challenge methods were offered for {}.".format(domain)
                )
        logger.info("Awaiting for authorization to be validated")
        try:
            return self.client.poll_authorizations(order, datetime.now() + timedelta(seconds=90))  # noqa: DTZ005 (acme expects offset-naive datetimes)
        except acme.errors.ValidationError:
            logger.error("Authorizations could not be validated!")
            raise ChallengeFailed() from None

    def issue_certificate(self, order: acme.messages.OrderResource) -> str:
        # Request a certificate using the CSR and some number of domain validation challenges.
        logger.info("Requesting a certificate for order")
        try:
            order = self.client.finalize_order(order, datetime.now() + timedelta(seconds=90))  # noqa: DTZ005 (acme expects offset-naive datetimes)
        except acme.messages.Error as e:
            if e.typ == "urn:ietf:params:acme:error:rateLimited":
                logger.warning("New certificate rejected due to rate limiting")
                raise RateLimited(e.detail) from None
            logger.warning("Certificate issueing failed")
            raise  # unhandled
        logger.info("New certificate issued")
        return order.fullchain_pem.replace(
            "-----END CERTIFICATE-----", "-----END CERTIFICATE-----\n"
        ).strip()
