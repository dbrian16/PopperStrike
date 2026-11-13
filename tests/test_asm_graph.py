"""ASM/CT-log discovery must flow into the KnowledgeGraph the engine reasons over, not
stay a flat list of strings. Offline — the CT fetcher is injected."""
from __future__ import annotations

from agentpentest.asm import graph_from_ct
from agentpentest.knowledge_graph import KnowledgeGraph


def test_ingest_subdomains_adds_hosts_and_edges():
    g = KnowledgeGraph("example.com")
    ids = g.ingest_subdomains("example.com", ["a.example.com", "A.EXAMPLE.COM", "b.example.com"])
    assert ids == ["host:a.example.com", "host:b.example.com"]        # deduped, sorted
    assert g.nodes["domain:example.com"].type == "domain"
    for hid in ids:
        assert g.nodes[hid].type == "host"
    subs = [n.id for n in g.neighbors("domain:example.com", "HAS_SUBDOMAIN")]
    assert set(subs) == set(ids)


def test_graph_from_ct_bridges_discovery_into_graph():
    ct_json = ('[{"name_value":"a.example.com\\n*.b.example.com"},'
               '{"name_value":"example.com"},'
               '{"name_value":"notmine.org"}]')
    g = graph_from_ct("example.com", fetcher=lambda url: ct_json)
    hosts = {n.name for n in g.match(type="host")}
    assert {"a.example.com", "b.example.com"} <= hosts
    assert "notmine.org" not in hosts                                 # out-of-domain dropped
    # the discovered hosts are reachable from the domain node, so path-finding can use them
    assert g.neighbors("domain:example.com", "HAS_SUBDOMAIN")


def test_graph_from_ct_empty_on_no_results():
    g = graph_from_ct("example.com", fetcher=lambda url: "[]")
    assert g.match(type="host") == []
