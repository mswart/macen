from datetime import datetime, timedelta
import io
import random
import sys
from typing import Sequence, cast
import uuid

if sys.version_info >= (3, 11):
    from datetime import UTC
else:
    from datetime import timezone

    UTC: timezone = timezone.utc

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as pem_serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509 import Certificate, CertificateSigningRequest
from cryptography.x509.extensions import Extension, SubjectAlternativeName
from cryptography.x509.oid import ExtensionOID, NameOID

from macen import config, manager
from macen.challenges import ChallengeImplementor


def M(
    configcontent: str, *, connect: bool = False, validator: ChallengeImplementor | None = None
) -> manager.ACMEManager:
    c = config.Configurator(io.StringIO(configcontent))
    if validator:
        c.default_validator = validator
        for block in c.auth.blocks:
            block.validator = validator
    return manager.ACMEManager(c, connect=connect)


def MA(
    conf: str, connect: bool = True, validator: ChallengeImplementor | None = None
) -> manager.ACMEManager:
    return M(
        conf
        + """[auth "all"]
        all=yes
        domain=*
        """,
        connect=connect,
        validator=validator,
    )


def gencsrpem(domains: Sequence[str], key: CertificateIssuerPrivateKeyTypes) -> bytes:
    # Generates a CSR and returns a pyca/cryptography CSR object.
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
            ]
        )
    )
    csr = csr.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
        critical=False,
    )
    csr = csr.sign(key, hashes.SHA256(), default_backend())
    return csr.public_bytes(pem_serialization.Encoding.PEM)


def gencsr(
    domains: Sequence[str], key: CertificateIssuerPrivateKeyTypes
) -> CertificateSigningRequest:
    pem = gencsrpem(domains, key)
    return x509.load_pem_x509_csr(pem)


def signcsr(
    csrpem: bytes,
    key: CertificateIssuerPrivateKeyTypes,
    period: timedelta,
    issued_before: timedelta | None = None,
) -> str:
    csr = x509.load_pem_x509_csr(csrpem, default_backend())
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(csr.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.not_valid_before(datetime.now(tz=UTC) - (issued_before or timedelta(1, 0, 0)))
    builder = builder.not_valid_after(datetime.now(tz=UTC) + period)
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())
    return "\n".join(
        [
            cert.public_bytes(pem_serialization.Encoding.PEM).decode("utf-8"),
            cert.public_bytes(pem_serialization.Encoding.PEM).decode("utf-8"),
        ]
    )


def extract_alt_names(cert: Certificate) -> list[str]:
    try:
        extension = cast(
            Extension[SubjectAlternativeName],
            cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME),
        )
        return extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def randomize_domains(*domains: str, suffix: str = "") -> list[str]:
    rand = random.randint(0, 2**16)  # noqa: S311
    return [(domain + suffix).format(rand) for domain in domains]
