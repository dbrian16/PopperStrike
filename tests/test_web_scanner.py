"""Unit tests for the Web Application Attack Surface & Vulnerability Scanner (Chapter 5)."""
import pytest

from agentpentest.web_scanner import (
    FormInput,
    WebAttackSurface,
    WebForm,
    XSSFinding,
    SQLiFinding,
    SSTIFinding,
    SSRFFinding,
    XXEFinding,
    IDORFinding,
    HeaderFinding,
    JWTFinding,
    GraphQLFinding,
    format_web_report,
    map_web_surface,
    run_web_assessment,
    scan_dom_xss,
    scan_graphql,
    scan_header_bypass,
    scan_idor,
    scan_jwt_confusion,
    scan_reflected_xss,
    scan_sqli,
    scan_ssrf,
    scan_ssti,
    scan_xxe,
    _forge_none_jwt,
    _decode_jwt_header,
)


SAMPLE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Acme Test Portal</title>
</head>
<body>
    <h1>Welcome</h1>
    <a href="/products.php?cat=1">Products</a>
    <a href="https://external.com/faq">External FAQ</a>
    
    <form action="/login.php" method="POST">
        <input type="text" name="uname" id="user_id" value="admin">
        <input type="password" name="pass">
        <input type="hidden" name="csrf_token" value="abc123xyz">
    </form>

    <script>
        // DOM XSS vulnerable pattern
        function loadContent() {
            var term = location.hash.substring(1);
            document.getElementById('output').innerHTML = "Search: " + term;
        }
    </script>
</body>
</html>
"""


def test_map_web_surface_parsing():
    surface = map_web_surface("http://test.corp.com/index.php?page=home&debug=1", html_content=SAMPLE_HTML)
    assert surface.title == "Acme Test Portal"
    assert surface.url_params == {"page": "home", "debug": "1"}
    assert len(surface.forms) == 1

    form = surface.forms[0]
    assert form.action == "/login.php"
    assert form.method == "POST"
    assert len(form.inputs) == 3

    input_names = [i.name for i in form.inputs]
    assert "uname" in input_names
    assert "pass" in input_names
    assert "csrf_token" in input_names

    # Check same-domain vs external links
    assert "http://test.corp.com/products.php?cat=1" in surface.same_domain_links
    assert not any("external.com" in link for link in surface.same_domain_links)

    # Check inline script extraction
    assert len(surface.inline_scripts) == 1
    assert "location.hash" in surface.inline_scripts[0]


def test_scan_reflected_xss_vulnerable():
    import urllib.parse
    # Mock client that reflects the parameter value unencoded
    def mock_reflected_client(url: str) -> str:
        unquoted = urllib.parse.unquote_plus(url)
        if '<script>alert("XSS")</script>' in unquoted:
            return "<html><body>Search results for: <script>alert(\"XSS\")</script></body></html>"
        return "<html><body>Normal page</body></html>"

    findings = scan_reflected_xss(
        "http://test.corp.com/search.php?q=apple",
        http_client=mock_reflected_client
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "REFLECTED_XSS"
    assert f.parameter == "q"
    assert '<script>alert("XSS")</script>' in f.payload
    assert f.severity == "HIGH"


def test_scan_reflected_xss_safe():
    # Mock client that HTML-encodes output
    def mock_safe_client(url: str) -> str:
        return "<html><body>Search results for: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;</body></html>"

    findings = scan_reflected_xss(
        "http://test.corp.com/search.php?q=apple",
        http_client=mock_safe_client
    )
    assert len(findings) == 0


def test_scan_dom_xss_static_and_dynamic():
    script_source = """
    function renderQuery() {
        var query = decodeURIComponent(location.hash.substring(1));
        document.getElementById('results').innerHTML = '<p>' + query + '</p>';
    }
    """
    # 1. Static detection
    findings_static = scan_dom_xss(
        "http://localhost/dom.html",
        inline_scripts=[script_source],
    )
    assert len(findings_static) >= 1
    f = findings_static[0]
    assert f.vuln_type == "DOM_XSS_STATIC"
    assert "location.hash" in f.payload
    assert "innerHTML" in f.payload

    # 2. Dynamic detection mock
    mock_hash_client = lambda u: "<html><body><img src=x onerror=alert(1)></body></html>" if "#<img src=x onerror=alert(1)>" in u else "<html><body></body></html>"
    findings_dynamic = scan_dom_xss(
        "http://localhost/dom.html",
        inline_scripts=[],
        http_client=mock_hash_client,
    )
    assert any(d.vuln_type == "DOM_XSS_DYNAMIC" for d in findings_dynamic)


def test_scan_sqli_error_based():
    # Mock client returning MySQL syntax error on single quote
    def mock_sqli_client(url: str) -> tuple[str, float]:
        if "id=10%27" in url or "id=10'" in url:
            return "Warning: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", 0.05
        return "Item description: Book #10", 0.05

    findings = scan_sqli(
        "http://test.corp.com/items.php?id=10",
        http_client=mock_sqli_client,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.technique == "ERROR_BASED"
    assert f.parameter == "id"
    assert "MySQL" in f.dbms
    assert f.severity == "CRITICAL"


def test_scan_sqli_boolean_and_time_based():
    # Mock client with boolean differential and time delay
    def mock_advanced_client(url: str) -> tuple[str, float]:
        if "cat=1%27+OR+%271%27%3D%271" in url or "cat=1' OR '1'='1" in url:
            # Huge content length difference (all products returned)
            return "<html><body>" + ("Product Card<br>" * 80) + "</body></html>", 0.05
        if "SLEEP" in url:
            return "<html><body>Delayed page</body></html>", 3.1
        return "<html><body>One Product Card</body></html>", 0.05

    # 1. Boolean test
    findings_bool = scan_sqli(
        "http://test.corp.com/products.php?cat=1",
        test_time_based=False,
        http_client=mock_advanced_client,
    )
    assert any(f.technique == "BOOLEAN_BASED" for f in findings_bool)

    # 2. Time-based test
    findings_time = scan_sqli(
        "http://test.corp.com/products.php?cat=1",
        test_time_based=True,
        http_client=mock_advanced_client,
    )
    assert any(f.technique == "TIME_BASED" for f in findings_time)


def test_findings_carry_confidence_and_recommendation():
    # Chapter-7 iterative loop: every finding tells the agent its next escalation step.
    err = SQLiFinding(technique="ERROR_BASED", parameter="id", payload="'", dbms="MySQL")
    assert err.confidence == "HIGH"
    assert "UNION SELECT" in err.recommendation

    boolean = SQLiFinding(technique="BOOLEAN_BASED", parameter="id", payload="x", dbms="?")
    assert boolean.confidence == "MEDIUM"          # length-delta only -> less certain
    assert "time-based" in boolean.recommendation.lower()

    xss = XSSFinding(vuln_type="REFLECTED_XSS", parameter="q", payload="<script>")
    assert xss.confidence == "HIGH" and xss.recommendation

    # Explicit values are never overwritten by the post-init defaults.
    pinned = SQLiFinding(technique="ERROR_BASED", parameter="id", payload="'", dbms="MySQL",
                         confidence="LOW", recommendation="stop")
    assert pinned.confidence == "LOW" and pinned.recommendation == "stop"

    # Reaches to_dict() so MCP/report consumers see it.
    assert err.to_dict()["recommendation"] == err.recommendation


def test_run_web_assessment_end_to_end():
    mock_text = lambda u: "<html><body><form action='/post.php' method='POST'><input name='search'></form>Result: <script>alert(\"XSS\")</script> syntax error near MySQL</body></html>"
    results = run_web_assessment(
        "http://test.corp.com/page.php?test=1",
        http_text_client=mock_text,
    )
    assert results["forms_count"] == 1
    assert len(results["xss_findings"]) >= 1
    assert len(results["sqli_findings"]) >= 1

    report_md = format_web_report(results)
    assert "Web Application Security Assessment" in report_md
    assert "SQL Injection" in report_md
    assert "Cross-Site Scripting" in report_md


def test_web_assessment_allow_internal_param():
    """Verify allow_internal flag is properly accepted and forwarded."""
    mock_text = lambda u: "<html><body><p>Hello internal</p></body></html>"
    results = run_web_assessment(
        "http://127.0.0.1:8888/test?q=val",
        allow_internal=True,
        http_text_client=mock_text,
    )
    assert results["target"] == "http://127.0.0.1:8888/test?q=val"


# =============================================================================
# SSTI tests
# =============================================================================

def test_scan_ssti_detects_jinja2():
    from agentpentest.web_scanner import _SSTI_EXPECTED
    def client(url: str) -> str:
        if "2311" in url:
            return f"<html>Result: {_SSTI_EXPECTED}</html>"
        return "<html>Normal</html>"
    findings = scan_ssti("http://test.corp.com/page?name=hello", http_client=client, allow_internal=True)
    assert len(findings) == 1
    assert findings[0].engine == "Jinja2/Twig"
    assert findings[0].parameter == "name"
    assert _SSTI_EXPECTED in findings[0].evidence


def test_scan_ssti_no_finding():
    findings = scan_ssti("http://test.corp.com/page?name=hello",
                         http_client=lambda u: "<html>safe</html>", allow_internal=True)
    assert findings == []


def test_scan_ssti_no_params():
    findings = scan_ssti("http://test.corp.com/page", http_client=lambda u: "", allow_internal=True)
    assert findings == []


# =============================================================================
# IDOR tests
# =============================================================================

def test_scan_idor_detects_different_content():
    def client(url: str) -> tuple[int, str]:
        import urllib.parse
        p = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        uid = p.get("user_id", "5")
        if uid == "5":
            return 200, "A" * 500
        if uid == "6":
            return 200, "B" * 600  # different content = potential IDOR
        return 404, ""
    findings = scan_idor("http://test.corp.com/profile?user_id=5",
                         http_client=client, allow_internal=True)
    assert len(findings) >= 1
    assert findings[0].original_id == "5"
    assert findings[0].tested_id == "6"


def test_scan_idor_no_numeric_params():
    findings = scan_idor("http://test.corp.com/page?name=alice",
                         http_client=lambda u: (200, "x" * 300), allow_internal=True)
    assert findings == []


def test_scan_idor_non_200_baseline():
    findings = scan_idor("http://test.corp.com/page?id=5",
                         http_client=lambda u: (403, ""), allow_internal=True)
    assert findings == []


# =============================================================================
# Header injection tests
# =============================================================================

def test_scan_header_bypass_detects_403_to_200():
    def client(url: str, headers: dict) -> tuple[int, str]:
        if "X-Forwarded-For" in headers:
            return 200, "admin panel content here ok"
        return 403, "Forbidden"
    findings = scan_header_bypass("http://test.corp.com/admin",
                                  http_client=client, allow_internal=True)
    assert len(findings) >= 1
    assert findings[0].baseline_status == 403
    assert findings[0].bypassed_status == 200
    assert "X-Forwarded-For" in findings[0].headers_injected


def test_scan_header_bypass_no_change():
    findings = scan_header_bypass("http://test.corp.com/page",
                                  http_client=lambda u, h: (200, "same content"), allow_internal=True)
    assert findings == []


# =============================================================================
# JWT tests
# =============================================================================

def _make_test_jwt() -> str:
    import base64, json
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234", "role": "user"}).encode()).rstrip(b"=").decode()
    return f"{hdr}.{payload}.fakesig"


def test_decode_jwt_header():
    token = _make_test_jwt()
    hdr = _decode_jwt_header(token)
    assert hdr is not None
    assert hdr["alg"] == "RS256"


def test_forge_none_jwt_removes_signature():
    token = _make_test_jwt()
    forged = _forge_none_jwt(token)
    assert forged.endswith(".")
    hdr = _decode_jwt_header(forged)
    assert hdr is not None
    assert hdr["alg"] == "none"


def test_scan_jwt_confusion_detects_alg_none():
    import urllib.parse, base64, json as _json
    token = _make_test_jwt()

    def client(url: str) -> tuple[int, str]:
        p = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        t = p.get("token", "")
        hdr = _decode_jwt_header(t)
        if hdr and hdr.get("alg") == "none":
            return 200, "admin data"  # server accepts unsigned token
        return 200, "user data"

    target = f"http://test.corp.com/api?token={urllib.parse.quote(token)}"
    findings = scan_jwt_confusion(target, http_client=client, allow_internal=True)
    assert len(findings) == 1
    assert findings[0].technique == "ALG_NONE"
    assert findings[0].parameter == "token"


def test_scan_jwt_no_jwt_params():
    findings = scan_jwt_confusion("http://test.corp.com/page?q=hello",
                                  http_client=lambda u: (200, "ok"), allow_internal=True)
    assert findings == []


# =============================================================================
# GraphQL tests
# =============================================================================

def test_scan_graphql_detects_introspection():
    import json as _json
    schema_response = _json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"name": "Query", "kind": "OBJECT"},
                    {"name": "Mutation", "kind": "OBJECT"},
                    {"name": "User", "kind": "OBJECT"},
                    {"name": "String", "kind": "SCALAR"},
                ]
            }
        }
    })

    def poster(url: str, body: str) -> tuple[int, str]:
        if "graphql" in url:
            return 200, schema_response
        return 404, ""

    findings = scan_graphql("http://test.corp.com", http_client=poster, allow_internal=True)
    assert any(f.finding_type == "INTROSPECTION_ENABLED" for f in findings)
    assert any(f.finding_type == "MUTATION_AVAILABLE" for f in findings)


def test_scan_graphql_no_endpoint():
    findings = scan_graphql("http://test.corp.com",
                            http_client=lambda u, b: (404, ""), allow_internal=True)
    assert findings == []


# =============================================================================
# SSRF + XXE (mock OOB listener)
# =============================================================================

class _MockOOBListener:
    """Minimal OOB listener stub for unit tests."""
    def __init__(self):
        self.base_url = "http://oob.test.local:12345"
        self._hits: dict[str, list] = {}

    def register(self) -> str:
        from agentpentest.oob import generate_token
        t = generate_token()
        self._hits[t] = []
        return t

    def check(self, token: str, timeout: float = 0) -> list:
        return self._hits.get(token, [])

    def start(self): pass
    def stop(self): pass

    def inject_hit(self, token: str, remote: str = "1.2.3.4", path: str = "/"):
        from dataclasses import dataclass
        @dataclass
        class Hit:
            remote: str; path: str; timestamp: float = 0.0
            method: str = "GET"; headers: dict = None; body: bytes = b""
            def __post_init__(self):
                if self.headers is None:
                    self.headers = {}
        self._hits.setdefault(token, []).append(Hit(remote=remote, path=f"/{token}"))


def test_scan_ssrf_detects_oob_callback():
    listener = _MockOOBListener()

    def client(url: str) -> str:
        # Simulate server fetching the injected URL and listener receiving a callback
        import urllib.parse
        p = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        redirect_val = p.get("redirect", "")
        # Extract token from injected URL and inject a hit
        if "oob.test.local" in redirect_val:
            token = redirect_val.split("/")[-1]
            listener.inject_hit(token)
        return ""

    findings = scan_ssrf(
        "http://test.corp.com/page?redirect=http://safe.com",
        oob_listener=listener,
        http_client=client,
        allow_internal=True,
    )
    assert len(findings) == 1
    assert findings[0].parameter == "redirect"


def test_scan_ssrf_no_candidate_params():
    listener = _MockOOBListener()
    findings = scan_ssrf(
        "http://test.corp.com/page?q=hello&id=5",
        oob_listener=listener,
        http_client=lambda u: "",
        allow_internal=True,
    )
    assert findings == []


def test_scan_xxe_detects_error_based():
    def poster(url: str, body: str, headers: dict) -> tuple[int, str]:
        if "SYSTEM" in body and "etc/passwd" in body:
            return 200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon"
        return 200, "<result>ok</result>"

    listener = _MockOOBListener()
    findings = scan_xxe(
        "http://test.corp.com/api/xml",
        oob_listener=listener,
        http_client=poster,
        allow_internal=True,
    )
    assert len(findings) >= 1
    assert any(f.technique == "ERROR_BASED" for f in findings)


def test_scan_xxe_detects_oob():
    import re as _re
    def poster(url: str, body: str, headers: dict) -> tuple[int, str]:
        m = _re.search(r'oob\.test\.local:\d+/([A-Za-z0-9_-]+)', body)
        if m:
            listener.inject_hit(m.group(1))
        return 200, "<result>ok</result>"

    listener = _MockOOBListener()
    findings = scan_xxe(
        "http://test.corp.com/api/xml",
        oob_listener=listener,
        http_client=poster,
        allow_internal=True,
    )
    assert any(f.technique == "OOB" for f in findings)


# =============================================================================
# format_web_report covers new finding types
# =============================================================================

def test_format_report_includes_new_finding_sections():
    results = {
        "target": "http://test.corp.com/",
        "title": "Test",
        "forms_count": 0,
        "links_count": 0,
        "url_params": {},
        "xss_findings": [],
        "sqli_findings": [],
        "ssti_findings": [{"parameter": "tpl", "engine": "Jinja2/Twig",
                           "payload": "{{2311*1973}}", "evidence": "4560803 evaluated",
                           "severity": "CRITICAL", "confidence": "HIGH",
                           "recommendation": "escalate", "remediation": "fix"}],
        "ssrf_findings": [],
        "xxe_findings": [],
        "idor_findings": [],
        "header_findings": [],
        "jwt_findings": [],
        "graphql_findings": [],
    }
    md = format_web_report(results)
    assert "Server-Side Template Injection" in md
    assert "Jinja2/Twig" in md
