"""Index of available resources (wordlists / templates) on disk, if present."""
from __future__ import annotations

from pathlib import Path


class ResourceCatalog:
    def __init__(self, root: Path):
        self.root = root
        self.wordlists: dict[str, Path] = {}
        self._index()

    def _index(self) -> None:
        wl = self.root / "wordlists"
        if wl.exists():
            for p in wl.rglob("*.txt"):
                self.wordlists[p.stem.lower()] = p

    def find_wordlist(self, *hints: str) -> Path | None:
        for h in hints:
            for name, path in self.wordlists.items():
                if h.lower() in name:
                    return path
        return None
