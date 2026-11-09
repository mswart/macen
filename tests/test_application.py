from unittest.mock import Mock

import pytest

from macen.application import Application, build_components
from macen.config import validate_config
from macen.manager import ACMEManager


def test_application_closes_listeners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ACMEManager, "connect", lambda self: None)
    components = build_components(
        validate_config(
            {
                "account": {"dir": "."},
                "mgmt": {"listener": "127.0.0.1:0"},
                "verification": {"type": "http01", "listener": "127.0.0.1:0"},
            }
        )
    )
    app = Application(components)
    app.start()
    provider = components.default_validator
    challenge_server = provider._services[0][0]
    threads = list(app.threads) + [thread for _, thread in provider._services]
    app.close()
    assert challenge_server.socket.fileno() == -1
    assert all(not thread.is_alive() for thread in threads)
    app.close()  # Idempotent, including after partially failed startup.


def test_failed_start_rolls_back_started_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ACMEManager, "connect", lambda self: None)
    components = build_components(validate_config({"account": {"dir": "."}}))
    first, second = Mock(), Mock()
    second.start.side_effect = RuntimeError("bind failed")
    components.validators = {"first": first, "second": second}
    app = Application(components)
    with pytest.raises(RuntimeError, match="bind failed"):
        app.start()
    first.stop.assert_called_once()
    second.stop.assert_called_once()
    assert not app.threads
