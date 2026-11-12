"""Smoke test for the end-to-end simulated campaign (campaign.py). Exercises the full
recon -> tree -> EGATS -> report pipeline with zero network I/O (mock mode)."""
from __future__ import annotations

from agentpentest.campaign import run, simulated_oracle
from agentpentest.ptt import Evidence, PentestTree, PTTNode


def test_simulated_campaign_runs_offline():
    tree, md = run("lab.local", quiet=True)
    assert isinstance(tree, PentestTree)
    assert tree.root_id in tree.nodes
    assert isinstance(md, str) and md.strip()          # a report was generated


def test_simulated_oracle_scripts_t1190():
    ok, ev = simulated_oracle(PTTNode("n0", "exploit", None, technique="T1190"))
    assert ok is True and ev is Evidence.VERIFIED
    miss, ev2 = simulated_oracle(PTTNode("n1", "noop", None, technique=""))
    assert miss is False and ev2 is Evidence.SPECULATIVE
