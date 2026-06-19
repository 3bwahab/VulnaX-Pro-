"""Finding -> ATT&CK technique mapping rules.

Returns (technique_id, base_confidence, reasoning) tuples per finding, based on
category, title keywords, CWE, and CVE presence. The knowledge base resolves
technique names, tactics, and mitigations.
"""
from __future__ import annotations


def _kw(title: str, *words: str) -> bool:
    return any(w in title for w in words)


def map_finding(finding) -> list[tuple[str, float, str]]:
    title = (finding.title or "").lower()
    cat = finding.category
    out: list[tuple[str, float, str]] = []

    def add(tid: str, conf: float, reason: str) -> None:
        out.append((tid, conf, reason))

    if cat == "secret":
        add("T1552.001", 0.8, "Exposed secret = unsecured credentials in files")
        if _kw(title, "private key", "aws_secret", "aws_access"):
            add("T1552.004", 0.7, "Exposed private key material")

    elif cat == "exposure":
        if _kw(title, "git", "code repo"):
            add("T1213.003", 0.8, "Exposed source repository enables data mining")
            add("T1552.001", 0.7, "Source repos commonly contain credentials")
        elif _kw(title, "cloud", "bucket", "s3", "blob", "gcs"):
            add("T1530", 0.7, "Reachable cloud storage data")
        elif _kw(title, "registry", "kubernetes", "container", "docker"):
            add("T1613", 0.7, "Exposed container/orchestration discovery surface")
            add("T1552.007", 0.6, "Container APIs leak secrets")
            add("T1610", 0.5, "Exposed orchestration may allow container deploy")
        elif _kw(title, "admin", "administrative", "panel", "console"):
            add("T1133", 0.6, "Exposed administrative remote service")
        elif _kw(title, "directory listing"):
            add("T1083", 0.7, "Directory listing aids file/dir discovery")
        elif _kw(title, "metrics", "info", "disclosure"):
            add("T1592", 0.6, "Information disclosure aids host profiling")
        elif _kw(title, ".env", "config", "backup", "artifact", "dockerfile"):
            add("T1552.001", 0.7, "Exposed config/artifacts leak credentials")
        else:
            add("T1592", 0.4, "Generic information exposure")

    elif cat == "misconfig":
        if _kw(title, "cors"):
            add("T1539", 0.6, "Permissive CORS enables session theft")
        elif _kw(title, "tls", "certificate"):
            add("T1557", 0.6, "Weak transport enables adversary-in-the-middle")
        elif _kw(title, "jwt", "cookie", "session"):
            add("T1606.001", 0.6, "Weak cookie/JWT signing enables forged credentials")
            add("T1539", 0.55, "Session cookie weaknesses enable theft")
        elif _kw(title, "oauth", "token"):
            add("T1528", 0.6, "Token weakness enables access-token theft")
        elif _kw(title, "graphql", "introspection"):
            add("T1592", 0.6, "Schema disclosure aids reconnaissance")
            add("T1213", 0.5, "API schema enables data-repository mining")
        elif _kw(title, "header", "clickjack"):
            add("T1189", 0.4, "Missing client protections enable drive-by/clickjacking")
        else:
            add("T1190", 0.4, "Misconfiguration may be exploitable")

    elif cat == "vuln":
        if _kw(title, "xss", "cross-site scripting"):
            add("T1059.007", 0.7, "XSS executes attacker JavaScript")
        elif _kw(title, "sql injection", "sqli"):
            add("T1190", 0.85, "SQL injection exploits a public-facing app")
        elif _kw(title, "cve", "vulnerable to") or finding.cve_ids:
            add("T1190", 0.8, "Known CVE on a public-facing application")
        else:
            add("T1190", 0.6, "Exploitable public-facing application weakness")

    elif cat == "indicator":
        if _kw(title, "redirect"):
            add("T1566", 0.4, "Open redirect aids phishing")
            add("T1204", 0.3, "Relies on user execution")
        elif _kw(title, "traversal", "file inclusion"):
            add("T1190", 0.5, "Path traversal / LFI exploitation")
            add("T1083", 0.4, "Traversal enables file discovery")
        elif _kw(title, "template injection"):
            add("T1190", 0.5, "SSTI can lead to remote code execution")
        elif _kw(title, "idor", "access-control"):
            add("T1190", 0.4, "Broken object-level authorization")
        elif _kw(title, "ssrf", "command"):
            add("T1552.005", 0.45, "SSRF can reach cloud metadata credentials")
            add("T1190", 0.4, "Server-side request forgery exploitation")
        elif _kw(title, "enumeration", "rate-limit", "authentication surface"):
            add("T1110", 0.4, "Missing rate limiting enables brute force/enumeration")
        else:
            add("T1190", 0.3, "Potential public-facing weakness")

    else:
        add("T1190", 0.3, "Generic public-facing exploitation")

    return out
