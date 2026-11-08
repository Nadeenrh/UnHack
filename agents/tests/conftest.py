"""Every test is offline, independent of the developer's shell configuration."""

import socket

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.setenv("NIGHTWATCH_LIVE_CALLS_ENABLED", "false")
    monkeypatch.setenv("NIGHTWATCH_INTEL_ENABLED", "false")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    def blocked(*args, **kwargs):
        raise AssertionError("Offline tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", blocked)
