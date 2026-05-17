"""
pipeline_cache.py  –  Simple JSON-backed cache for LLM and API calls.

Cache key format: "{pkg}:{sha12}:{stage}"
  where stage is e.g. "stage1", "stage2", "cve_lookup", "apt_source"

Cache file: data/findings/pipeline_cache_v2.json
  (v2 is a fresh cache; does NOT read v1 data)

Public API
----------
load_cache(path)           → dict
get_cached(cache, key)     → value or None
set_cached(cache, key, v)  → None (mutates dict in place)
save_cache(cache, path)    → None
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


def load_cache(path: Path) -> dict:
    """Load cache from a JSON file. Returns empty dict on missing / corrupt file."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("[cache] load failed (%s): %s — starting with empty cache", path, exc)
        return {}


def get_cached(cache: dict, key: str) -> Optional[Any]:
    """Return cached value for key, or None if not present."""
    return cache.get(key)


def set_cached(cache: dict, key: str, value: Any) -> None:
    """Store value under key in the cache dict (mutates in place)."""
    cache[key] = value


def save_cache(cache: dict, path: Path) -> None:
    """Persist cache dict to a JSON file, creating parent directories as needed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        log.warning("[cache] save failed (%s): %s", path, exc)
