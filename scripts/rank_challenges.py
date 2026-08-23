#!/usr/bin/env python3
"""Cheap first-pass ranking: identify likely fast solves before invoking Codex."""
import json
import re
from pathlib import Path
from paths import WORKSPACE

ROOT = WORKSPACE
INDEX = ROOT / "data" / "raw" / "challenge_index.json"
DETAILS = ROOT / "data" / "raw" / "challenge_details.json"

EASY = {
    "intro": 8, "read": 5, "join": 5, "login": 5, "bypass": 6,
    "guest": 4, "simple": 6, "starter": 6, "oldtimer": 3, "qr": 3,
    "dashboard": 3, "message": 3, "archaeology": 2, "presenting": 2,
    "serving": 2, "needle": 2, "imitation": 3, "update": 3,
}
HARD = {
    "reforged": -8, "stolen": -5, "schematic": -5, "crypt": -5,
    "whispers": -4, "recycle": -4, "degraded": -4, "compromised": -5,
    "malicious": -5, "level 2": -4, "level 3": -6, "deep": -4,
}


def rank(c, detail):
    text = f"{c.get('name', '')} {detail.get('description', '')}".lower()
    score = 0.0
    reasons = []
    for word, points in EASY.items():
        if re.search(rf"\b{re.escape(word)}\b", text):
            score += points
            reasons.append(f"+{word}")
    for word, points in HARD.items():
        if word in text:
            score += points
            reasons.append(f"{points}{word}")
    solves = c.get("solves") or 0
    score += min(solves / 10, 10)
    score += min((c.get("value") or 0) / 200, 2)
    files = len(detail.get("files") or [])
    score -= files * 0.8
    if files:
        reasons.append(f"-{files} files")
    return score, reasons


def main():
    index = json.loads(INDEX.read_text())
    details = {x.get("id"): x for x in json.loads(DETAILS.read_text())}
    ranked = []
    for c in index:
        score, reasons = rank(c, details.get(c.get("id"), {}))
        ranked.append({**c, "title": c.get("name"), "fast_score": round(score, 2), "reasons": reasons})
    ranked.sort(key=lambda x: x["fast_score"], reverse=True)
    for i, c in enumerate(ranked, 1):
        print(f"[우선순위 {i}] 점수 {c['fast_score']:>5} / {c.get('name')} / {' '.join(c['reasons'])}", flush=True)
    (ROOT / "data" / "raw" / "fast_priority.json").write_text(json.dumps(ranked, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
