"""Recon Knowledge / project memory: persist inventory snapshots per project and
diff successive assessments. Enables "what changed / appeared / disappeared".
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEM_DIR = ROOT / "recon_memory"


def project_id(roots: list[str]) -> str:
    raw = ",".join(sorted(r.lower() for r in roots))
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _proj_dir(roots: list[str]) -> Path:
    d = MEM_DIR / project_id(roots)
    d.mkdir(parents=True, exist_ok=True)
    return d


def build_snapshot(store, scan_id: str, roots: list[str]) -> dict:
    """Capture the inventory we want to track between assessments."""
    return {
        "scan_id": scan_id,
        "project": project_id(roots),
        "roots": roots,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "assets": sorted({a.host for a in store.assets(status="live")}),
        "all_assets": sorted({a.host for a in store.assets()}),
        "endpoints": sorted({e.url for e in store.endpoints()}),
        "parameters": sorted({p.name for p in store.parameters()}),
        "technologies": sorted({t.name for t in store.technologies()}),
        "services": sorted({f"{s.host}:{s.port}" for s in store.services()}),
        "apis": sorted({a.path for a in store.api_endpoints()}),
        "findings": sorted({f"{f.severity.value}|{f.title}|{f.target}"
                            for f in store.findings() if f.status == "validated"}),
    }


def load_latest(roots: list[str]) -> dict | None:
    latest = _proj_dir(roots) / "latest.json"
    if latest.exists():
        try:
            return json.loads(latest.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_snapshot(snapshot: dict, roots: list[str]) -> None:
    d = _proj_dir(roots)
    (d / f"{snapshot['scan_id']}.json").write_text(
        json.dumps(snapshot, indent=2), encoding="utf-8")
    (d / "latest.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def append_trend(snapshot: dict, sev_counts: dict, roots: list[str]) -> list[dict]:
    d = _proj_dir(roots)
    tfile = d / "trends.json"
    trends = []
    if tfile.exists():
        try:
            trends = json.loads(tfile.read_text(encoding="utf-8"))
        except Exception:
            trends = []
    trends.append({
        "scan_id": snapshot["scan_id"],
        "captured_at": snapshot["captured_at"],
        "live_assets": len(snapshot["assets"]),
        "endpoints": len(snapshot["endpoints"]),
        "parameters": len(snapshot["parameters"]),
        "services": len(snapshot["services"]),
        "findings": len(snapshot["findings"]),
        "severity": sev_counts,
    })
    tfile.write_text(json.dumps(trends[-50:], indent=2), encoding="utf-8")
    return trends[-50:]


def diff_snapshots(prev: dict | None, cur: dict) -> dict:
    """Compute additions/removals across the tracked inventory fields."""
    def delta(field: str) -> dict:
        p = set((prev or {}).get(field, []))
        c = set(cur.get(field, []))
        return {"added": sorted(c - p), "removed": sorted(p - c)}

    return {
        "has_baseline": prev is not None,
        "previous_scan": (prev or {}).get("scan_id"),
        "assets": delta("all_assets"),
        "endpoints": delta("endpoints"),
        "parameters": delta("parameters"),
        "technologies": delta("technologies"),
        "services": delta("services"),
        "apis": delta("apis"),
        "findings": delta("findings"),
    }
