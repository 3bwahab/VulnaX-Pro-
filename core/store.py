"""Embedded store: in-memory typed index during scan, persisted to SQLite + JSON.

Engines read prior results and write their own here — the single source of truth.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Iterable, TypeVar

from pydantic import BaseModel

from .models import (
    ApiEndpoint, Asset, AssetCriticality, AttackPath, AuthSurface, CVEMatch,
    Endpoint, ExposureDelta, Finding, FindingGroup, InterfaceAsset, JsAsset,
    MitreMapping, Parameter, Relationship, Risk, Service, Technology,
    ThreatScenario,
)

T = TypeVar("T", bound=BaseModel)

_COLLECTIONS = {
    Asset: "assets",
    Service: "services",
    Technology: "technologies",
    Endpoint: "endpoints",
    JsAsset: "js_assets",
    ApiEndpoint: "api_endpoints",
    AuthSurface: "auth_surfaces",
    Parameter: "parameters",
    CVEMatch: "cve_matches",
    Finding: "findings",
    FindingGroup: "finding_groups",
    Risk: "risks",
    Relationship: "relationships",
    AttackPath: "attack_paths",
    MitreMapping: "mitre_mappings",
    ThreatScenario: "threat_scenarios",
    AssetCriticality: "asset_criticality",
    ExposureDelta: "exposure_deltas",
    InterfaceAsset: "interface_assets",
}


class Store:
    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir
        self._data: dict[str, dict[str, BaseModel]] = {
            name: {} for name in _COLLECTIONS.values()
        }
        self._lock = threading.RLock()

    # ---- write -----------------------------------------------------------
    def add(self, model: BaseModel) -> None:
        coll = _COLLECTIONS.get(type(model))
        if coll is None:
            raise TypeError(f"Unknown model type: {type(model)}")
        with self._lock:
            key = getattr(model, "id", None) or str(len(self._data[coll]))
            existing = self._data[coll].get(key)
            if existing is not None:
                self._data[coll][key] = self._merge(existing, model)
            else:
                self._data[coll][key] = model

    def add_all(self, models: Iterable[BaseModel]) -> int:
        n = 0
        for m in models:
            self.add(m)
            n += 1
        return n

    # Lifecycle fields where a later value should supersede an earlier one.
    _STATUS_PRIORITY = {"candidate": 1, "dead": 2, "live": 3}

    @classmethod
    def _merge(cls, old: BaseModel, new: BaseModel) -> BaseModel:
        """Union list fields / fill missing scalars (provenance-preserving).

        Status fields progress (candidate -> dead -> live) rather than freeze.
        """
        merged = old.model_copy(deep=True)
        for field_name in type(new).model_fields:
            nv = getattr(new, field_name)
            ov = getattr(merged, field_name)
            if field_name == "status" and isinstance(nv, str) and isinstance(ov, str):
                if cls._STATUS_PRIORITY.get(nv, 0) > cls._STATUS_PRIORITY.get(ov, 0):
                    setattr(merged, field_name, nv)
            elif isinstance(ov, list) and isinstance(nv, list):
                seen = {json.dumps(x, default=str, sort_keys=True) for x in
                        [i.model_dump() if isinstance(i, BaseModel) else i for i in ov]}
                for item in nv:
                    sig = json.dumps(
                        item.model_dump() if isinstance(item, BaseModel) else item,
                        default=str, sort_keys=True,
                    )
                    if sig not in seen:
                        ov.append(item)
                        seen.add(sig)
            elif ov in (None, "", 0, [], {}) and nv not in (None, "", 0, [], {}):
                setattr(merged, field_name, nv)
        return merged

    # ---- read ------------------------------------------------------------
    def _coll(self, model_type: type[T]) -> list[T]:
        with self._lock:
            return list(self._data[_COLLECTIONS[model_type]].values())  # type: ignore

    def assets(self, status: str | None = None) -> list[Asset]:
        out = self._coll(Asset)
        return [a for a in out if status is None or a.status == status]

    def services(self) -> list[Service]:
        return self._coll(Service)

    def technologies(self) -> list[Technology]:
        return self._coll(Technology)

    def endpoints(self) -> list[Endpoint]:
        return self._coll(Endpoint)

    def js_assets(self) -> list[JsAsset]:
        return self._coll(JsAsset)

    def api_endpoints(self) -> list[ApiEndpoint]:
        return self._coll(ApiEndpoint)

    def auth_surfaces(self) -> list[AuthSurface]:
        return self._coll(AuthSurface)

    def parameters(self) -> list[Parameter]:
        return self._coll(Parameter)

    def finding_groups(self) -> list[FindingGroup]:
        return self._coll(FindingGroup)

    def cve_matches(self) -> list[CVEMatch]:
        return self._coll(CVEMatch)

    def findings(self) -> list[Finding]:
        return self._coll(Finding)

    def risks(self) -> list[Risk]:
        return self._coll(Risk)

    def relationships(self) -> list[Relationship]:
        return self._coll(Relationship)

    def attack_paths(self) -> list[AttackPath]:
        return self._coll(AttackPath)

    def mitre_mappings(self) -> list[MitreMapping]:
        return self._coll(MitreMapping)

    def threat_scenarios(self) -> list[ThreatScenario]:
        return self._coll(ThreatScenario)

    def asset_criticality(self) -> list[AssetCriticality]:
        return self._coll(AssetCriticality)

    def exposure_deltas(self) -> list[ExposureDelta]:
        return self._coll(ExposureDelta)

    def interface_assets(self) -> list[InterfaceAsset]:
        return self._coll(InterfaceAsset)

    def technologies_for(self, asset_id: str) -> list[Technology]:
        return [t for t in self.technologies() if t.asset_id == asset_id]

    def count(self, model_type: type) -> int:
        return len(self._data[_COLLECTIONS[model_type]])

    # ---- persist ---------------------------------------------------------
    def bundle(self) -> dict:
        with self._lock:
            return {
                name: [m.model_dump(mode="json") for m in coll.values()]
                for name, coll in self._data.items()
            }

    def persist_sqlite(self, db_path: Path) -> None:
        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.cursor()
            for name in _COLLECTIONS.values():
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {name} "
                    f"(id TEXT PRIMARY KEY, data TEXT)"
                )
            for name, coll in self._data.items():
                rows = [
                    (getattr(m, "id", str(i)), m.model_dump_json())
                    for i, m in enumerate(coll.values())
                ]
                cur.executemany(
                    f"INSERT OR REPLACE INTO {name} (id, data) VALUES (?, ?)", rows
                )
            conn.commit()
        finally:
            conn.close()
