#!/usr/bin/env python3
"""Resolve the strongest Codex model exposed by the logged-in CLI account.

This reads Codex's local model catalogue and makes no API request. Explicit
environment overrides remain available for another account or future models.
"""
import json
import os
from pathlib import Path
from paths import WORKSPACE


MODEL_CACHE = Path(
    os.environ.get(
        "CTF_CODEX_MODEL_CACHE",
        str(Path.home() / ".codex" / "models_cache.json"),
    )
).expanduser()
PREFERRED_MODELS = (
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
    "gpt-5.5",
    "gpt-5.4",
    "gpt-5.3-codex-spark",
    "gpt-5.4-mini",
)
REASONING_ORDER = ("ultra", "max", "xhigh", "high", "medium", "low")
PROFILE_CONFIG = WORKSPACE / "data" / "runtime" / "codex_profile.json"


def _catalogue():
    try:
        data = json.loads(MODEL_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {
        item.get("slug"): item
        for item in data.get("models", [])
        if isinstance(item, dict)
        and item.get("slug")
        and item.get("visibility", "list") != "hide"
    }


def available_models():
    """Return visible models in a stable, quality-first UI order."""
    catalogue = _catalogue()
    ordered = [slug for slug in PREFERRED_MODELS if slug in catalogue]
    ordered.extend(slug for slug in catalogue if slug not in ordered)
    return [catalogue[slug] for slug in ordered]


def _saved_profile():
    try:
        value = json.loads(PROFILE_CONFIG.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def resolve_profile():
    catalogue = _catalogue()
    saved = _saved_profile()
    requested = os.environ.get("CTF_CODEX_MODEL", "").strip() or str(saved.get("model", "")).strip()
    if requested:
        model = requested
        entry = catalogue.get(model, {})
    else:
        model = next((slug for slug in PREFERRED_MODELS if slug in catalogue), "gpt-5.6-sol")
        entry = catalogue.get(model, {})

    supported = {
        item.get("effort")
        for item in entry.get("supported_reasoning_levels", [])
        if isinstance(item, dict) and item.get("effort")
    }
    requested_reasoning = (
        os.environ.get("CTF_CODEX_REASONING", "").strip().lower()
        or str(saved.get("reasoning", "")).strip().lower()
    )
    reasoning = requested_reasoning or next(
        (level for level in REASONING_ORDER if level in supported), "max"
    )
    if supported and reasoning not in supported:
        reasoning = next((level for level in REASONING_ORDER if level in supported), "max")

    return {
        "model": model,
        "display_name": entry.get("display_name", model),
        "reasoning": reasoning,
        "catalogue_hit": bool(entry),
    }


def reasoning_options(model=None):
    """Return supported reasoning levels, strongest first, for one model."""
    entry = _catalogue().get(model or resolve_profile()["model"], {})
    supported = {
        item.get("effort")
        for item in entry.get("supported_reasoning_levels", [])
        if isinstance(item, dict) and item.get("effort")
    }
    return [level for level in REASONING_ORDER if level in supported] or ["max", "high", "medium", "low"]


def save_profile(model, reasoning):
    """Persist UI-selected profile for this CTF workspace only."""
    catalogue = _catalogue()
    if model not in catalogue:
        raise ValueError(f"사용할 수 없는 모델: {model}")
    choices = reasoning_options(model)
    if reasoning not in choices:
        raise ValueError(f"{model}에서 지원하지 않는 추론 단계: {reasoning}")
    PROFILE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    temp = PROFILE_CONFIG.with_name(f".{PROFILE_CONFIG.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps({"model": model, "reasoning": reasoning}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, PROFILE_CONFIG)
    return resolve_profile()


def label(profile=None):
    profile = profile or resolve_profile()
    return f"{profile['display_name']} / 추론 {profile['reasoning']}"


if __name__ == "__main__":
    print(json.dumps(resolve_profile(), ensure_ascii=False))
