"""amass passive subdomain enumeration is a first-class tool with structured parsing."""
from __future__ import annotations

from agentpentest import tools
from agentpentest.tools import REGISTRY


def test_amass_builds_passive_enum_argv():
    argv = tools.resolve("amass_enum", {"target": "example.com"})
    assert argv[0] == "amass" and "enum" in argv and "example.com" in argv


def test_amass_parses_subdomains_from_output():
    parsed = REGISTRY["amass_enum"].parse(REGISTRY["amass_enum"].mock, {})
    assert "cdn.example.com" in parsed["subdomains"]
    assert all("." in s for s in parsed["subdomains"])
