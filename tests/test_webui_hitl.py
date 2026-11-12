"""HITL edit flow: operator-edited argv must flow back through confirm()."""
import threading
import time

from agentpentest.webui import App


def _run_confirm(app, argv, done):
    done["ok"] = app.confirm(argv, "example.com", "test")


def test_decide_without_edit_leaves_argv():
    app = App()
    argv = ["whatweb", "http://example.com"]
    done = {}
    t = threading.Thread(target=_run_confirm, args=(app, argv, done))
    t.start()
    while app.pending is None:
        time.sleep(0.01)
    app.decide(True)
    t.join(timeout=2)
    assert done["ok"] is True
    assert argv == ["whatweb", "http://example.com"]


def test_decide_with_edit_mutates_argv():
    app = App()
    argv = ["nmap", "-sV", "example.com"]
    done = {}
    t = threading.Thread(target=_run_confirm, args=(app, argv, done))
    t.start()
    while app.pending is None:
        time.sleep(0.01)
    app.decide(True, ["nmap", "-sC", "-sV", "example.com"])
    t.join(timeout=2)
    assert done["ok"] is True
    assert argv == ["nmap", "-sC", "-sV", "example.com"]


def test_decide_reject_ignores_edit():
    app = App()
    argv = ["dig", "example.com"]
    done = {}
    t = threading.Thread(target=_run_confirm, args=(app, argv, done))
    t.start()
    while app.pending is None:
        time.sleep(0.01)
    app.decide(False, ["dig", "evil.com"])
    t.join(timeout=2)
    assert done["ok"] is False
    assert argv == ["dig", "example.com"]


def test_chat_context_carries_engagement_state():
    """_chat_context must carry the question plainly and the target-derived state fenced."""
    from agentpentest import webui
    webui.APP.plan = {"target": "10.0.0.5",
                      "steps": [{"action": "nmap -sV 10.0.0.5"}]}
    webui.APP.recon = {"services": [{"port": 445, "name": "microsoft-ds"}]}
    webui.APP.summary = {"findings": [{"title": "SMB exposed", "severity": "Medium"}]}
    try:
        out = webui._chat_context("what next?")
    finally:
        webui.APP.plan = webui.APP.recon = webui.APP.summary = None
    assert out.startswith("Operator question: what next?")   # question is NOT fenced as untrusted
    assert "UNTRUSTED TARGET OUTPUT" in out                  # state IS fenced
    for needle in ("10.0.0.5", "nmap -sV 10.0.0.5", "445", "Medium"):
        assert needle in out


def test_stop_releases_pending_approval():
    app = App()
    done = {}
    worker = threading.Thread(target=_run_confirm,
                              args=(app, ["dig", "example.com"], done), daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while app.pending is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert app.pending is not None
        app.stop()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert done["ok"] is False
        assert app.pending is None
    finally:
        app.stop()
        worker.join(timeout=2)


def test_stale_or_duplicate_decision_is_rejected():
    app = App()
    gate = {"decision": None, "edit": None, "event": threading.Event()}
    app._gates[2] = gate
    app.pending = {"id": 2}
    assert app.decide(True, gate_id=1) is False
    assert gate["decision"] is None
    assert app.decide(False, gate_id=2) is True
    assert app.decide(True, gate_id=2) is False
    assert gate["decision"] is False


def test_api_edits_first_plan_step(monkeypatch):
    from agentpentest import webui
    app = App()
    app.plan = {"steps": [{"action": "old"}]}
    monkeypatch.setattr(webui, "APP", app)
    handler = object.__new__(webui.Handler)
    handler.path = "/api/plan/edit"
    handler._same_origin = lambda: True
    handler._body = lambda: {"index": 0, "action": "updated"}
    handler._send = lambda status, body: (status, body)
    assert handler.do_POST()[0] == 200
    assert app.plan["steps"][0]["action"] == "updated"


def test_api_rejects_wrong_types_before_dispatch():
    from agentpentest import webui
    handler = object.__new__(webui.Handler)
    handler.path = "/api/decision"
    handler._same_origin = lambda: True
    handler._send = lambda status, body: (status, body)
    for payload in ({"approve": "false"}, {"index": "bad"},
                    {"rate": float("nan")}, {"rate": -1}, {"target": []}):
        handler._body = lambda: payload
        assert handler.do_POST()[0] == 400
