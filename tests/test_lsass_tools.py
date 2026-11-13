"""Structured LSASS credential-dump tools (lsassy / pypykatz): argv construction and
deterministic parsing of real dumper output into credential dicts. Parity with secrets_dump.
Execution itself is Kali-gated; these tests exercise only build + parse (no commands run)."""
from __future__ import annotations

from agentpentest import tools
from agentpentest.tools import REGISTRY, _parse_lsass


def test_lsassy_argv_password_and_pth():
    argv = tools.resolve("lsass_dump", {"target": "10.0.0.5", "domain": "LAB",
                                        "user": "svc", "password": "pw"})
    assert argv[0] == "lsassy" and "10.0.0.5" in argv and "-p" in argv
    pth = tools.resolve("lsass_dump", {"target": "10.0.0.5", "domain": "LAB",
                                       "user": "svc", "hash_nt": "a" * 32})
    assert "-H" in pth and "a" * 32 in pth          # pass-the-hash path, no plaintext


def test_pypykatz_argv_parses_a_dumpfile():
    argv = tools.resolve("lsass_parse", {"dumpfile": "/tmp/lsass.dmp"})
    assert argv == ["pypykatz", "lsa", "minidump", "/tmp/lsass.dmp"]


def test_parse_lsassy_output_extracts_creds_and_skips_empty_hash():
    out = REGISTRY["lsass_dump"].mock
    parsed = _parse_lsass(out, {})
    users = {c["user"]: c["hash_nt"] for c in parsed["credentials"]}
    assert users.get("Administrator") == "8846f7eaee8fb117ad06bdd830b7586c"
    assert "svc_sql" not in users                    # empty-password NT hash dropped
    assert parsed["findings"] and parsed["findings"][0]["severity"] == "critical"


def test_parse_pypykatz_pairs_username_with_nt():
    out = REGISTRY["lsass_parse"].mock
    creds = _parse_lsass(out, {})["credentials"]
    assert {"user": "Administrator", "hash_nt": "8846f7eaee8fb117ad06bdd830b7586c",
            "source": "lsass"} in creds


def test_parse_lsass_empty_on_clean_output():
    assert _parse_lsass("no secrets here\n[*] done", {})["credentials"] == []


def test_lsass_tools_are_registered():
    assert {"lsass_dump", "lsass_parse"} <= set(REGISTRY)
