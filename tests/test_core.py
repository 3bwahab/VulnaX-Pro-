"""Offline unit tests for the kernel: models, scope, store, versions, payloads."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.models import Asset, Confidence, Evidence, Finding, Severity  # noqa: E402
from core.scope import Scope, load_scope  # noqa: E402
from core.store import Store  # noqa: E402
from utils.version import version_lt, version_lte  # noqa: E402
from utils.net import normalize_url, url_signature  # noqa: E402
from utils.text import extract_endpoints, extract_secrets  # noqa: E402


def test_scope_wildcard_and_exclude():
    sc = Scope({"scope": {
        "in_scope": {"domains": ["example.com", "*.example.com"]},
        "out_of_scope": {"domains": ["secret.example.com"]},
    }})
    assert sc.is_in_scope("example.com")
    assert sc.is_in_scope("www.example.com")
    assert sc.is_in_scope("https://api.example.com/path")
    assert not sc.is_in_scope("secret.example.com")
    assert not sc.is_in_scope("evil.com")


def test_scope_cidr():
    sc = Scope({"scope": {"in_scope": {"cidrs": ["203.0.113.0/24"]}}})
    assert sc.is_in_scope("203.0.113.5")
    assert not sc.is_in_scope("198.51.100.1")


def test_domain_scope_roots():
    sc = load_scope(domain="example.com")
    assert "example.com" in sc.roots


def test_finding_requires_evidence_invariant():
    # A finding *can* be constructed empty, but our pipeline treats evidence as
    # mandatory; assert the model carries the structure we rely on.
    f = Finding(title="x", evidence=[Evidence(kind="config", summary="s")])
    assert f.evidence and f.id


def test_store_status_progression_regression():
    """Regression for BUG-001: status must progress candidate -> live."""
    store = Store(ROOT / "artifacts" / "test")
    store.add(Asset(host="a.example.com", status="candidate"))
    store.add(Asset(host="a.example.com", status="live", ips=["1.2.3.4"]))
    live = store.assets(status="live")
    assert len(live) == 1
    assert live[0].ips == ["1.2.3.4"]


def test_store_merges_lists():
    store = Store(ROOT / "artifacts" / "test")
    store.add(Asset(host="b.example.com", tags=["x"]))
    store.add(Asset(host="b.example.com", tags=["y"]))
    a = store.assets()[0]
    assert set(a.tags) == {"x", "y"}


def test_version_compare():
    assert version_lt("1.20.0", "1.20.1")
    assert not version_lt("2.4.50", "2.4.49")
    assert version_lte("2.4.49", "2.4.49")


def test_url_normalize_and_signature():
    assert normalize_url("HTTP://Example.com:80/a?b=2&a=1").startswith("http://example.com/a")
    s1 = url_signature("https://x.com/p?a=1&b=2")
    s2 = url_signature("https://x.com/p?a=9&b=8")
    assert s1 == s2  # same path + param keys


def test_extract_endpoints_and_secrets():
    js = '''var x="/api/v1/users";fetch("/admin/panel");
            const k="AKIAIOSFODNN7EXAMPLE";'''
    eps = extract_endpoints(js)
    assert "/api/v1/users" in eps
    secrets = extract_secrets(js)
    assert any(kind == "aws_access_key" for kind, _ in secrets)


def test_severity_rank_order():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_parameter_classification():
    from engines.parameter_intelligence import _classify
    assert _classify("redirect") == ("redirect", "high")
    assert _classify("id")[0] == "object_reference"
    assert _classify("page") == ("pagination", "low")
    assert _classify("q") == ("search", "medium")
    assert _classify("redirect_uri")[0] == "redirect"   # substring fallback
    assert _classify("totallyrandomxyz") == ("unknown", "info")


def test_confidence_increases_with_corroboration():
    from core.confidence import ConfidenceSignals, score_confidence, level_name
    low = score_confidence(ConfidenceSignals(base=0.5, evidence_count=1,
                                             independent_sources=1))
    high = score_confidence(ConfidenceSignals(base=0.5, evidence_count=3,
                                              independent_sources=3,
                                              fingerprint_match=True))
    assert high.score > low.score
    assert level_name(0.92) == "critical" and level_name(0.3) == "low"


def test_finding_correlation_root_cause():
    from engines.finding_correlation import _root_cause
    assert _root_cause("Missing HSTS header", "misconfig").startswith("Incomplete")
    assert "Secrets" in _root_cause("Exposed secret in JavaScript (jwt)", "secret")
    assert "CVE" in _root_cause("nginx vulnerable to CVE-2021-23017", "vuln")


def test_assessment_plan_summary():
    from core.orchestration import AssessmentPlan
    p = AssessmentPlan(tech_modules=["laravel"], xss_targets=["u"], sqli_targets=[])
    assert "xss=1" in p.summary()


def test_mitre_kb_loads():
    from mitre.knowledge_base import load_kb
    kb = load_kb()
    assert len(kb.ordered_tactics()) == 14
    t = kb.technique("T1190")
    assert t and "Exploit" in t["name"]
    assert kb.primary_tactic("T1190") == "TA0001"
    assert any(m["id"].startswith("M") for m in kb.mitigations_for("T1190"))


def test_mitre_mapping_rules():
    from mitre.mapping import map_finding
    from core.models import Confidence, Evidence, Finding

    def mk(cat, title, cve=None):
        return Finding(title=title, category=cat,
                       confidence=Confidence(score=0.8),
                       evidence=[Evidence(kind="config", summary="x")],
                       cve_ids=cve or [])

    assert any(t == "T1552.001" for t, _, _ in
               map_finding(mk("secret", "Exposed secret in JavaScript (jwt)")))
    assert any(t == "T1190" for t, _, _ in
               map_finding(mk("vuln", "nginx vulnerable to CVE-2021-23017",
                              ["CVE-2021-23017"])))
    assert any(t == "T1213.003" for t, _, _ in
               map_finding(mk("exposure", "Exposed Git repository")))
    assert any(t == "T1059.007" for t, _, _ in
               map_finding(mk("vuln", "Reflected XSS (reflected)")))


def test_recon_memory_diff():
    from core.recon_memory import diff_snapshots
    prev = {"scan_id": "s1", "all_assets": ["a.com", "b.com"], "endpoints": ["u1"],
            "parameters": [], "technologies": ["nginx"], "services": [],
            "apis": [], "findings": []}
    cur = {"scan_id": "s2", "all_assets": ["b.com", "c.com"], "endpoints": ["u1", "u2"],
           "parameters": ["q"], "technologies": ["nginx", "php"], "services": [],
           "apis": [], "findings": ["high|X|t"]}
    d = diff_snapshots(prev, cur)
    assert d["has_baseline"] and d["assets"]["added"] == ["c.com"]
    assert d["assets"]["removed"] == ["a.com"]
    assert d["endpoints"]["added"] == ["u2"]
    assert d["technologies"]["added"] == ["php"]
    assert d["findings"]["added"] == ["high|X|t"]


def test_recon_memory_no_baseline():
    from core.recon_memory import diff_snapshots
    d = diff_snapshots(None, {"all_assets": ["a"], "endpoints": [], "parameters": [],
                              "technologies": [], "services": [], "apis": [],
                              "findings": []})
    assert d["has_baseline"] is False


def test_criticality_and_posture_bands():
    from engines.asset_criticality import _band
    from engines.security_posture import _grade
    assert _band(85) == "critical" and _band(5) == "info"
    assert _grade(95) == "A" and _grade(50) == "F"
