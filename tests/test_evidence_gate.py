"""Deterministic evidence tiering (evidence_gate.py): the falsification backbone that
decides which findings are proof-backed vs quarantined. Zero-LLM, fully deterministic."""
from __future__ import annotations

from agentpentest.evidence_gate import EvidenceTier, classify, gate, is_reportable
from agentpentest.verifiers import VerdictStatus


def test_verifier_verdict_wins():
    # A tier-2 verifier verdict overrides grounding heuristics.
    assert classify("none", "nothing", verdict=VerdictStatus.CONFIRMED) is EvidenceTier.CONFIRMED
    assert classify("grounded", "banner", verdict=VerdictStatus.FALSE_POSITIVE) is EvidenceTier.REFUTED


def test_inconclusive_verdict_falls_through_to_grounding():
    assert classify("grounded", "x", verdict=VerdictStatus.INCONCLUSIVE) is EvidenceTier.GROUNDED


def test_hard_proof_marker_confirms():
    assert classify("none", "uid=0(root) gid=0(root)") is EvidenceTier.CONFIRMED
    assert classify("none", "... flag{pwned} ...") is EvidenceTier.CONFIRMED


def test_grounded_quote_is_grounded_not_confirmed():
    # A grounded version banner is real text, but not proof of exploitability.
    assert classify("grounded", "Server: nginx 1.18.0") is EvidenceTier.GROUNDED


def test_ungrounded_claim_is_quarantined():
    assert classify("none", "the model thinks it is vulnerable") is EvidenceTier.CLAIMED
    assert classify("unresolved", "paraphrase not in output") is EvidenceTier.CLAIMED


def test_is_reportable_gates_at_grounded():
    assert is_reportable(EvidenceTier.CONFIRMED)
    assert is_reportable(EvidenceTier.GROUNDED)
    assert not is_reportable(EvidenceTier.CLAIMED)
    assert not is_reportable(EvidenceTier.REFUTED)


def test_autoloop_tags_confirmed_tier_on_proof_output():
    """End-to-end: the live loop attaches a deterministic tier, and output carrying a
    hard proof marker is recorded CONFIRMED regardless of the model's self-report."""
    from agentpentest.autonomous import autoloop

    plans = [
        '{"command":["curl","http://example.com/"],"target":"example.com","rationale":"fetch"}',
        '{"done":true}',
    ]

    class _LLM:
        def __init__(self):
            self.i = 0

        def ask(self, system, user):
            if "autonomous penetration tester" in system:
                p = plans[self.i] if self.i < len(plans) else '{"done":true}'
                self.i += 1
                return p
            return '{"notes":"ok","evidence_status":"none"}'

    transcript = autoloop("prove rce", {"example.com"}, _LLM(),
                          lambda argv, target: "uid=0(root) gid=0(root)",
                          allow_internal=True, max_steps=2)
    tiers = [s.facts.get("evidence_tier") for s in transcript]
    assert "confirmed" in tiers


def test_gate_partitions_and_fails_closed_on_untagged():
    findings = [
        {"name": "a", "evidence_tier": "confirmed"},
        {"name": "b", "evidence_tier": "grounded"},
        {"name": "c", "evidence_tier": "claimed"},
        {"name": "d"},                                   # untagged -> treated as CLAIMED
        {"name": "e", "evidence_tier": "bogus"},         # invalid -> treated as CLAIMED
    ]
    buckets = gate(findings)
    assert [f["name"] for f in buckets["confirmed"]] == ["a"]
    assert [f["name"] for f in buckets["grounded"]] == ["b"]
    assert {f["name"] for f in buckets["claimed"]} == {"c", "d", "e"}
