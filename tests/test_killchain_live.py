"""Live KillChain actor: closes recon -> credential -> lateral move -> deterministic proof
-> harvest, advancing only on proof. Driven here with a FAKE execute (no real commands)."""
from __future__ import annotations

import pytest

from agentpentest import safety
from agentpentest.killchain import drive, live_actor
from agentpentest.knowledge_graph import KnowledgeGraph
from agentpentest.safety import LiveHostError
from agentpentest.verifiers import VerdictStatus

_PTH = {"user": "Administrator", "hash_nt": "a" * 32}
_PROOF = "uid=0(root) gid=0(root)"


def _graph(edges):
    g = KnowledgeGraph("lab")
    for src, dst, rel in edges:
        g.add_edge(src, dst, rel)
    return g


def test_hop_confirms_on_proof_output():
    g = _graph([("me", "host:10.0.0.5", "ADMIN_TO")])
    act = live_actor(lambda argv, target: _PROOF, seed_creds=[_PTH])
    verdict, evidence, creds = act("me", "host:10.0.0.5", "ADMIN_TO", g)
    assert verdict == VerdictStatus.CONFIRMED.value
    assert "uid=0(root)" in evidence


def test_hop_inconclusive_without_proof_or_creds():
    g = _graph([("me", "host:10.0.0.5", "ADMIN_TO")])
    # No credentials -> no move to attempt.
    none = live_actor(lambda argv, target: _PROOF, seed_creds=[])
    assert none("me", "host:10.0.0.5", "ADMIN_TO", g)[0] == VerdictStatus.INCONCLUSIVE.value
    # Credential present but output carries no proof -> not advanced.
    weak = live_actor(lambda argv, target: "connection refused", seed_creds=[_PTH])
    assert weak("me", "host:10.0.0.5", "ADMIN_TO", g)[0] == VerdictStatus.INCONCLUSIVE.value


def test_hop_harvests_and_registers_new_credentials():
    g = _graph([("me", "host:10.0.0.5", "ADMIN_TO")])
    dump = ("uid=0(root)\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            "8846f7eaee8fb117ad06bdd830b7586c:::")
    act = live_actor(lambda argv, target: dump, seed_creds=[_PTH])
    verdict, _ev, creds = act("me", "host:10.0.0.5", "ADMIN_TO", g)
    assert verdict == VerdictStatus.CONFIRMED.value
    assert "cred:Administrator" in creds
    assert g.nodes["cred:Administrator"].type == "identity"


def test_hop_refused_off_kali(monkeypatch):
    g = _graph([("me", "host:10.0.0.5", "ADMIN_TO")])
    monkeypatch.setattr(safety, "is_kali", lambda: False)
    monkeypatch.delenv("AGENTPENTEST_ALLOW_NON_KALI", raising=False)
    act = live_actor(lambda argv, target: _PROOF, seed_creds=[_PTH])
    with pytest.raises(LiveHostError):
        act("me", "host:10.0.0.5", "ADMIN_TO", g)


def test_drive_reaches_objective_with_live_actor():
    g = _graph([("me", "host:a", "LEADS_TO"), ("host:a", "host:DC", "ADMIN_TO")])
    act = live_actor(lambda argv, target: _PROOF, seed_creds=[_PTH])
    kc, trace = drive(g, "me", "host:DC", act)
    assert kc.reached
    assert [h.to for h in trace] == ["host:a", "host:DC"]
    assert all(h.verdict == VerdictStatus.CONFIRMED.value for h in trace)


def test_drive_live_one_call():
    from agentpentest.killchain import drive_live
    g = _graph([("me", "host:a", "LEADS_TO"), ("host:a", "host:DC", "ADMIN_TO")])
    kc, trace = drive_live(g, "me", "host:DC", lambda argv, target: _PROOF, seed_creds=[_PTH])
    assert kc.reached
    assert [h.to for h in trace] == ["host:a", "host:DC"]
