"""Smoke tests for lateral-movement candidate generation (lateral.py). Deterministic,
no packets sent."""
from __future__ import annotations

from agentpentest.lateral import build_lateral_argv, candidates_for_state


def test_build_lateral_argv_pth_from_nt_hash():
    cred = {"user": "Administrator", "hash_nt": "a" * 32}
    argvs = build_lateral_argv(cred, "10.0.0.5", domain="CORP")
    assert argvs and all(isinstance(a, list) and a for a in argvs)
    # Pass-the-hash path must carry the NT hash somewhere in a candidate command.
    assert any("a" * 32 in " ".join(a) for a in argvs)


def test_candidates_for_state_structured_and_deduped():
    creds = [{"user": "Administrator", "hash_nt": "b" * 32}]
    out = candidates_for_state(creds, ["10.0.0.5", "10.0.0.6"])
    assert isinstance(out, list) and out
    for c in out:
        assert set(c) >= {"argv", "user", "target", "method", "auth"}
        assert c["auth"] == "pth"            # NT hash -> pass-the-hash
    # No duplicate argv across the flattened table.
    keys = [tuple(c["argv"]) for c in out]
    assert len(keys) == len(set(keys))


def test_candidates_empty_without_creds():
    assert candidates_for_state([], ["10.0.0.5"]) == []
