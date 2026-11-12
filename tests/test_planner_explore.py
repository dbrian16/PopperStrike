"""Smarter planner: an opt-in UCB exploration bonus on EGATS frontier ranking, so greedy
best-first does not tunnel-vision on one branch while a promising untried branch starves.
Default (explore=0) is unchanged — pure exploitation."""
from __future__ import annotations

from agentpentest.brain import EGATS, assess, exploration_bonus
from agentpentest.ptt import Evidence, PentestTree, PTTNode


def test_exploration_bonus_is_off_by_default_and_decreases_with_attempts():
    untried = PTTNode("a", "g", None)
    tried = PTTNode("b", "g", None)
    tried.attempts = 30
    assert exploration_bonus(untried, 100, 0.0) == 0.0          # off by default (c=0)
    assert exploration_bonus(untried, 100, 1.0) > exploration_bonus(tried, 100, 1.0)
    assert exploration_bonus(tried, 100, 1.0) > 0.0


def test_explore_lifts_the_starved_branch_over_a_well_tried_one():
    tree = PentestTree("lab")
    a = tree.add("heavily-tried branch", tree.root_id, Evidence.CONFIRMED)
    b = tree.add("untried branch", tree.root_id, Evidence.SPECULATIVE)
    tree.nodes[a].attempts = 50
    tree.nodes[a].successes = 50                                # proven -> high feasibility

    fa = assess(tree.nodes[a], tree, 1).feasibility
    fb = assess(tree.nodes[b], tree, 1).feasibility

    # Greedy best-first orders purely by feasibility (self-consistent, formula-agnostic).
    greedy = [n.id for _, n in EGATS(tree, object())._ranked()]
    assert greedy == ([a, b] if fa >= fb else [b, a])

    # A large exploration weight lifts the untried branch to the top regardless of the gap.
    explorer = EGATS(tree, object(), explore=10.0)._ranked()
    assert explorer[0][1].id == b


def test_explore_zero_preserves_greedy_order():
    tree = PentestTree("lab")
    a = tree.add("A", tree.root_id, Evidence.PLAUSIBLE)
    b = tree.add("B", tree.root_id, Evidence.CONFIRMED)
    greedy = [n.id for _, n in EGATS(tree, object())._ranked()]
    explore0 = [n.id for _, n in EGATS(tree, object(), explore=0.0)._ranked()]
    assert greedy == explore0                                   # default path unchanged
