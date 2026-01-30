#!/usr/bin/env python3
"""
Seed Pool for feedback-guided fuzzing.

Stores interesting inputs and reuses them as mutation seeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import copy
import json
import logging
import random
from typing import Any

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SeedEntry:
    """Stored seed entry with signature and score."""

    data: dict[str, Any]
    signature: str
    score: float


class SeedPool:
    """Lightweight per-key seed pool with deduplication."""

    def __init__(
        self,
        *,
        max_per_key: int = 40,
        reseed_ratio: float = 0.3,
        storage_dir: Path | None = None,
        autosave: bool = True,
        rng: random.Random | None = None,
    ):
        self._max_per_key = max(1, max_per_key)
        self._reseed_ratio = max(0.0, min(1.0, reseed_ratio))
        self._storage_dir = storage_dir
        self._autosave = autosave
        self._rng = rng or random.Random()
        self._seeds: dict[str, list[SeedEntry]] = {}
        self._signatures: dict[str, set[str]] = {}
        if self._storage_dir:
            self.load_from_dir(self._storage_dir)

    @property
    def reseed_ratio(self) -> float:
        return self._reseed_ratio

    def add_seed(
        self,
        key: str,
        seed: dict[str, Any],
        *,
        signature: str,
        score: float = 1.0,
    ) -> bool:
        if not key or not signature:
            return False
        sigs = self._signatures.setdefault(key, set())
        if signature in sigs:
            return False
        entry = SeedEntry(data=seed, signature=signature, score=max(0.1, score))
        self._seeds.setdefault(key, []).append(entry)
        sigs.add(signature)
        self._trim(key)
        if self._storage_dir and self._autosave:
            self.save_key(key)
        return True

    def pick_seed(self, key: str) -> dict[str, Any] | None:
        entries = self._seeds.get(key, [])
        if not entries:
            return None
        if len(entries) == 1:
            return copy.deepcopy(entries[0].data)
        weights = [entry.score for entry in entries]
        return copy.deepcopy(self._rng.choices(entries, weights=weights, k=1)[0].data)

    def should_reseed(self, ratio_override: float | None = None) -> bool:
        ratio = self._reseed_ratio if ratio_override is None else ratio_override
        return self._rng.random() < ratio

    def _trim(self, key: str) -> None:
        entries = self._seeds.get(key, [])
        if len(entries) <= self._max_per_key:
            return
        entries.sort(key=lambda e: e.score, reverse=True)
        trimmed = entries[: self._max_per_key]
        self._seeds[key] = trimmed
        self._signatures[key] = {entry.signature for entry in trimmed}

    def load_from_dir(self, storage_dir: Path) -> None:
        storage_dir.mkdir(parents=True, exist_ok=True)
        autosave = self._autosave
        self._autosave = False
        for path in storage_dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text())
            except Exception:
                continue
            key = payload.get("key")
            entries = payload.get("entries", [])
            if not isinstance(key, str) or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("data")
                signature = entry.get("signature")
                score = entry.get("score", 1.0)
                if isinstance(data, dict) and isinstance(signature, str):
                    try:
                        score_value = float(score)
                    except (TypeError, ValueError):
                        _logger.debug(
                            "Invalid seed score for %s: %r", key, score
                        )
                        score_value = 1.0
                    self.add_seed(key, data, signature=signature, score=score_value)
        self._autosave = autosave

    def save_key(self, key: str) -> None:
        if not self._storage_dir:
            return
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        entries = self._seeds.get(key, [])
        payload = {
            "key": key,
            "entries": [
                {
                    "data": entry.data,
                    "signature": entry.signature,
                    "score": entry.score,
                }
                for entry in entries
            ],
        }
        filename = self._storage_dir / f"{_safe_filename(key)}.json"
        filename.write_text(json.dumps(payload, ensure_ascii=True, indent=2))


def _safe_filename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value)
    cleaned = cleaned.strip("._") or "seed"
    return cleaned[:120]
