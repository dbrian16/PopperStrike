"""Test-session setup. The suite runs on authorized dev/CI machines that are not Kali,
so the live-host gate is overridden here. test_kali_gate.py removes this override to
verify the gate itself refuses off-Kali."""
import os

os.environ.setdefault("AGENTPENTEST_ALLOW_NON_KALI", "1")
