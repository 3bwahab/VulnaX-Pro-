"""ATT&CK knowledge base: load, normalize, cache, and look up ATT&CK data.

Ships a curated offline dataset (mitre/data/attack_core.json). An updater can
ingest the official STIX bundle (enterprise-attack.json) if placed alongside it.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "data"
_CORE = _DATA_DIR / "attack_core.json"
_STIX = _DATA_DIR / "enterprise-attack.json"  # optional official bundle


class AttackKnowledgeBase:
    def __init__(self, data: dict):
        self.version = data.get("version", "unknown")
        self.tactics = {t["id"]: t for t in data.get("tactics", [])}
        self.tactics_by_name = {t["name"].lower(): t for t in self.tactics.values()}
        self.mitigations = data.get("mitigations", {})
        self.techniques = {t["id"]: t for t in data.get("techniques", [])}

    # ---- lookups ---------------------------------------------------------
    def technique(self, tid: str) -> dict | None:
        return self.techniques.get(tid)

    def tactic(self, tactic_id: str) -> dict | None:
        return self.tactics.get(tactic_id)

    def tactic_name(self, tactic_id: str) -> str:
        t = self.tactics.get(tactic_id)
        return t["name"] if t else tactic_id

    def tactic_order(self, tactic_id: str) -> int:
        t = self.tactics.get(tactic_id)
        return t["order"] if t else 99

    def ordered_tactics(self) -> list[dict]:
        return sorted(self.tactics.values(), key=lambda t: t["order"])

    def mitigation_name(self, mid: str) -> str:
        return self.mitigations.get(mid, mid)

    def mitigations_for(self, tid: str) -> list[dict]:
        tech = self.technique(tid)
        if not tech:
            return []
        return [{"id": m, "name": self.mitigation_name(m)}
                for m in tech.get("mitigations", [])]

    def primary_tactic(self, tid: str) -> str:
        tech = self.technique(tid)
        if not tech or not tech.get("tactics"):
            return ""
        # Earliest tactic in the kill chain is the "entry" tactic.
        return min(tech["tactics"], key=self.tactic_order)


@lru_cache(maxsize=1)
def load_kb() -> AttackKnowledgeBase:
    """Load curated core; merge optional STIX bundle techniques if present."""
    data = json.loads(_CORE.read_text(encoding="utf-8"))
    if _STIX.exists():
        try:
            data = _merge_stix(data, json.loads(_STIX.read_text(encoding="utf-8")))
        except Exception:
            pass
    return AttackKnowledgeBase(data)


def _merge_stix(core: dict, stix: dict) -> dict:
    """Best-effort normalization of an official STIX bundle into our shape.

    Only adds techniques/names not already present; the curated mappings still
    drive finding correlation. Keeps the framework offline-first.
    """
    known = {t["id"] for t in core["techniques"]}
    tactic_shortname_to_id = {
        "reconnaissance": "TA0043", "resource-development": "TA0042",
        "initial-access": "TA0001", "execution": "TA0002",
        "persistence": "TA0003", "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005", "credential-access": "TA0006",
        "discovery": "TA0007", "lateral-movement": "TA0008",
        "collection": "TA0009", "command-and-control": "TA0011",
        "exfiltration": "TA0010", "impact": "TA0040",
    }
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext.get("external_id", "")
        if not tid or tid in known:
            continue
        tactics = [tactic_shortname_to_id.get(p.get("phase_name"), "")
                   for p in obj.get("kill_chain_phases", [])]
        core["techniques"].append({
            "id": tid, "name": obj.get("name", tid),
            "tactics": [t for t in tactics if t], "criticality": 0.5,
            "mitigations": [], "description": (obj.get("description") or "")[:200],
        })
        known.add(tid)
    core["version"] = core.get("version", "") + "+stix"
    return core
