import io
from pathlib import Path
from typing import cast

import pydantic
import pytest

from macen import challenges, config, storages


def parse(configcontent: str) -> config.Configurator:
    return config.Configurator(io.StringIO(configcontent))


### generall


def test_error_on_option_without_section() -> None:
    with pytest.warns(config.UnusedOptionWarning) as w:
        parse("""
            acme-server = https://acme.example.org/directory
            [account]
            dir = /tmp/dir
            [mgmt]
            """)
    assert "acme-server" in str(w[-1].message)
    assert "https://acme.example.org/directory" in str(w[-1].message)


def test_comment() -> None:
    parse("""
        [account]
        dir = /tmp/dir
        #acme-server https://acme.example.org/directory
        [mgmt]
        """)


### [account] acme-server


def test_acme_server_address() -> None:
    c = parse("""
[account]
dir = /tmp/dir
acme-server = https://acme.example.org/directory
[mgmt]
""")
    assert c.account.acme_server == "https://acme.example.org/directory"


def test_default_acme_server_address() -> None:
    c = parse("""[account]
        dir=/tmp/test
        [mgmt]""")
    assert c.account.acme_server == "https://acme-staging-v02.api.letsencrypt.org/directory"


def test_error_on_multiple_acme_server_addresses() -> None:
    with pytest.raises(pydantic.ValidationError) as e:
        parse("""
            [account]
            dir = /tmp/dir
            acme-server = https://acme.example.org/directory
            acme-server = https://acme2.example.org/directory
            [mgmt]
            """)
    assert "acme-server" in str(e.value)


### [account] dir


def test_account_dir() -> None:
    config = parse("""
        [account]
        dir = /tmp/test
        [mgmt]
        """)
    assert config.account.dir == Path("/tmp/test")  # noqa: S108


### [account] accept terms of service


def test_tos() -> None:
    config = parse("""
        [account]
        dir = /tmp/test
        accept-terms-of-service = yes
        [mgmt]
        """)
    assert config.account.accept_terms_of_service is True


### [account] unknown option


def test_warning_on_unknown_account_option() -> None:
    with pytest.warns(config.UnusedOptionWarning) as w:
        parse("""
            [account]
            dir = /tmp/dir
            acme_server = https://acme.example.org/directory
            [mgmt]
            """)
    assert "acme_server" in str(w[-1].message)
    assert "https://acme.example.org/directory" in str(w[-1].message)


### [mgmt] mgmt


def test_simple_mgmt_listener() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        acme-server = https://acme.example.org/directory
        [mgmt]
        listener=127.0.0.1:13
        listener=[fe80::abba:abba%lo]:1380
        """)
    assert config.mgmt.listeners == ["127.0.0.1:13", "[fe80::abba:abba%lo]:1380"]


def test_default_mgmt_listener() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        """)
    assert config.mgmt.listeners == ["127.0.0.1:1313", "[::1]:1313"]


### [mgmt] max size


def test_default_max_size_options() -> None:
    p = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        """)
    assert p.mgmt.max_size == 4096


def test_max_size_options_in_bytes() -> None:
    p = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        max-size = 2394
        """)
    assert p.mgmt.max_size == 2394


def test_max_size_options_in_kbytes() -> None:
    p = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        max-size = 4k
        """)
    assert p.mgmt.max_size == 4000


def test_max_size_options_in_mbytes() -> None:
    p = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        max-size = 1m
        """)
    assert p.mgmt.max_size == 1_000_000


### [mgmt] unknown option


def test_warning_on_unknown_mgmt_option() -> None:
    with pytest.warns(config.UnusedOptionWarning) as w:
        parse("""
            [account]
            dir = /tmp/dir
            [mgmt]
            manager = https://acme.example.org/directory
            """)
    assert "manager" in str(w[-1].message)
    assert "https://acme.example.org/directory" in str(w[-1].message)


### unknown section


def test_warning_on_unknown_section() -> None:
    with pytest.warns(config.UnusedSectionWarning) as w:
        parse("""
            [account]
            dir = /tmp/dir
            [mgmt]
            [unknown]
            """)
    assert "unknown" in str(w[-1].message)


### http verification


def test_simple_http_listener() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=http
        [verification "http"]
        type=http01
        listener=127.0.0.1:80
        listener=[::]:80
        """)
    assert tuple(config.validators.keys()) == ("http",)
    http = cast(challenges.HttpChallengeImplementor, config.validators["http"])
    assert http.config.listeners == ["127.0.0.1:80", "[::]:80"]


### dns verification


def test_dns01_listener_default_options() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=dns
        [verification "dns"]
        type=dns01-dnsUpdate
        """)
    assert tuple(config.validators.keys()) == ("dns",)
    v = config.validators["dns"]
    v = cast(challenges.DnsChallengeDnsUpdateImplementor, config.validators["dns"])
    assert v.config.dns_server == "127.0.0.1"
    assert v.config.timeout == 5
    assert v.config.ttl == 60


def test_dns01_listener_with_explicit_options() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=
        [verification "dns"]
        type=dns01-dnsUpdate
        dns-server = 127.0.0.2
        timeout = 6
        ttl = 61
        """)
    assert tuple(config.validators.keys()) == ("dns",)
    v = cast(challenges.DnsChallengeDnsUpdateImplementor, config.validators["dns"])
    assert v.config.dns_server == "127.0.0.2"
    assert v.config.timeout == 6
    assert v.config.ttl == 61


#### default verification


def test_default_http_listener() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        """)
    assert tuple(config.validators.keys()) == ("http",)
    validator = cast(challenges.HttpChallengeImplementor, config.validators["http"])
    assert validator.config.listeners == ["0.0.0.0:1380", "[::]:1380"]


def test_disable_http_listener() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        default-verification=
        """)
    assert config.default_validator is None


def test_use_single_verification_as_default() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        [verification "http234"]
        type = http01
        """)
    assert tuple(config.validators.keys()) == ("http234",)
    assert config.default_validator is config.validators["http234"]


### storages


def test_explict_none_storage() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-storage = ntest
        [storage "ntest"]
        type = none
        """)
    assert set(config.storages) == {"ntest"}
    assert type(config.storages["ntest"]) is storages.NoneStorageImplementor


def test_not_other_none_storage_options() -> None:
    with pytest.warns(config.UnusedOptionWarning):
        parse("""
            [account]
            dir = /tmp/dir
            acme-server = https://acme.example.org/directory
            [mgmt]
            default-storage = ntest
            [storage "ntest"]
            type = none
            other = test
            """)


def test_implicit_default_storage() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        acme-server = https://acme.example.org/directory
        [mgmt]
        """)
    assert set(config.storages) == {"none"}


def test_use_single_stroage_as_default() -> None:
    config = parse("""
        [account]
        dir = /tmp/dir
        [mgmt]
        [storage "io"]
        type = file
        directory = /tmp
        """)
    assert tuple(config.storages.keys()) == ("io",)
    assert config.default_storage is config.storages["io"]
