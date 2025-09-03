from abc import abstractmethod
from datetime import datetime, timedelta
from hashlib import sha384
import os
import os.path
from pathlib import Path
import sys
from typing import Sequence

import pydantic

if sys.version_info >= (3, 11):
    from datetime import UTC
else:
    from datetime import timezone

    UTC: timezone = timezone.utc

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .config import ConfigurationError, Configurator, default_config


class StorageImplementor:
    class Config(pydantic.BaseModel):
        model_config = default_config.copy()

    def __init__(self, name: str, options: Sequence[tuple[str, str]]) -> None:
        self.name = name
        self.config = Configurator.parse_group(self.Config, options)

    @abstractmethod
    def parse(self, options: Sequence[tuple[str, str]]) -> None: ...

    @abstractmethod
    def from_cache(self, csr: bytes) -> str | None: ...

    @abstractmethod
    def add_to_cache(self, csr: bytes, certs: str) -> bool: ...


class NoneStorageImplementor(StorageImplementor):
    def from_cache(self, csr: bytes) -> str | None:
        return None

    def add_to_cache(self, csr: bytes, certs: str) -> bool:
        return False


class FileStorageImplementor(StorageImplementor):
    class Config(StorageImplementor.Config):
        directory: Path
        renew_within: int = 14

    config: Config

    def cache_dir(self, csr: bytes) -> Path:
        hash = sha384(csr).hexdigest()
        return self.config.directory / hash[0:2] / hash[2:]

    def from_cache(self, csr: bytes) -> str | None:
        dir = self.cache_dir(csr)
        if not dir.joinpath("csr.pem").is_file():
            return None
        if not dir.joinpath("cert.pem").is_file():
            return None
        if csr != dir.joinpath("csr.pem").read_bytes():
            # should not happen!!
            return None
        certpem = dir.joinpath("cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(certpem, default_backend())
        current_validation_time = cert.not_valid_after_utc - datetime.now(tz=UTC)
        if current_validation_time < timedelta(days=self.config.renew_within):
            return None
        else:
            return certpem.decode("utf-8")

    def add_to_cache(self, csr: bytes, certs: str) -> bool:
        dir = self.cache_dir(csr)
        os.makedirs(dir, exist_ok=True)
        with open(os.path.join(dir, "csr.pem"), "bw") as f:
            f.write(csr)
        with open(os.path.join(dir, "cert.pem"), "w") as f:
            f.write(certs)
        return True


implementors: dict[str, type[StorageImplementor]] = {
    "none": NoneStorageImplementor,
    "file": FileStorageImplementor,
}


def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> StorageImplementor:
    try:
        return implementors[type](name, options)
    except KeyError:
        raise ConfigurationError('Unsupported storage type "{}"'.format(type)) from None
