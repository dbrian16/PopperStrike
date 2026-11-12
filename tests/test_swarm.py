"""Smoke tests for the specialized swarm roles (swarm.py). All signals are deterministic
and offline (no packets sent)."""
from __future__ import annotations

from agentpentest.ptt import Evidence
from agentpentest.swarm import Hypothesis, fuzzing_agent, protocol_expert, static_analyst


def _svc(name: str, port: int) -> dict:
    return {"name": name, "version": "", "port": port, "address": "10.0.0.5"}


def test_protocol_expert_maps_known_service():
    h = protocol_expert(_svc("http", 80))
    assert isinstance(h, Hypothesis)
    assert h.technique == "T1190" and h.role == "protocol"
    assert isinstance(h.evidence, Evidence)


def test_roles_return_none_for_unknown_service():
    unknown = _svc("totally-unknown-proto", 9999)
    assert protocol_expert(unknown) is None
    assert static_analyst(unknown) is None
    assert fuzzing_agent(unknown) is None


def test_fuzzing_agent_is_deterministic():
    svc = _svc("http", 80)
    assert fuzzing_agent(svc) == fuzzing_agent(svc)   # same input -> same signal
