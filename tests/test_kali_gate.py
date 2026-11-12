"""Live-host gate: real/host execution must only unlock on Kali Linux (safety.py),
with an explicit AGENTPENTEST_ALLOW_NON_KALI override for authorized dev/CI."""
from __future__ import annotations

import pytest

from agentpentest import safety
from agentpentest.safety import LiveHostError, assert_live_host
from agentpentest.sandbox import LocalSandbox


def test_refused_off_kali_without_override(monkeypatch):
    monkeypatch.setattr(safety, "is_kali", lambda: False)
    monkeypatch.delenv("AGENTPENTEST_ALLOW_NON_KALI", raising=False)
    with pytest.raises(LiveHostError, match="not a Kali Linux host"):
        assert_live_host("unit test")


def test_allowed_on_kali(monkeypatch):
    monkeypatch.setattr(safety, "is_kali", lambda: True)
    monkeypatch.delenv("AGENTPENTEST_ALLOW_NON_KALI", raising=False)
    assert_live_host("unit test")          # must not raise


def test_override_allows_off_kali(monkeypatch):
    monkeypatch.setattr(safety, "is_kali", lambda: False)
    monkeypatch.setenv("AGENTPENTEST_ALLOW_NON_KALI", "1")
    assert_live_host("unit test")          # must not raise


def test_localsandbox_exec_is_gated(monkeypatch):
    """The gate is wired at the real host-execution chokepoint, not just the helper."""
    monkeypatch.setattr(safety, "is_kali", lambda: False)
    monkeypatch.delenv("AGENTPENTEST_ALLOW_NON_KALI", raising=False)
    with pytest.raises(LiveHostError):
        LocalSandbox().exec(["echo", "hi"])
    with pytest.raises(LiveHostError):
        LocalSandbox().exec_full(["echo", "hi"])


def test_is_kali_returns_bool():
    # Parsing /etc/os-release (or its absence on Windows/macOS) always yields a bool.
    assert isinstance(safety.is_kali(), bool)
