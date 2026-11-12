"""Smoke tests for the Penetration Testing Tree (ptt.py): construction, trajectory
bookkeeping, and backtracking invariants."""
from __future__ import annotations

from agentpentest.ptt import Evidence, PentestTree, PTTNode


def test_tree_has_root_on_construction():
    tree = PentestTree("lab.local")
    root = tree.nodes[tree.root_id]
    assert isinstance(root, PTTNode)
    assert root.status == "root"
    assert "lab.local" in root.goal


def test_add_links_parent_and_child():
    tree = PentestTree("lab.local")
    child = tree.add("enumerate smb", tree.root_id, Evidence.SPECULATIVE, technique="T1210")
    assert tree.nodes[child].parent == tree.root_id
    assert child in tree.nodes[tree.root_id].children
    assert tree.nodes[child].technique == "T1210"


def test_record_tracks_success_and_fail_streak():
    tree = PentestTree("lab.local")
    n = tree.add("exploit", tree.root_id)
    tree.record(n, success=False)
    assert tree.nodes[n].fail_streak == 1 and tree.nodes[n].attempts == 1
    tree.record(n, success=True, command="curl http://lab.local")
    node = tree.nodes[n]
    assert node.successes == 1 and node.fail_streak == 0 and node.status == "success"
    assert node.commands == ["curl http://lab.local"]


def test_abandon_marks_subtree():
    tree = PentestTree("lab.local")
    parent = tree.add("branch", tree.root_id)
    child = tree.add("leaf", parent)
    tree.abandon(parent)
    assert tree.nodes[parent].status == "abandoned"
    assert tree.nodes[child].status == "abandoned"
