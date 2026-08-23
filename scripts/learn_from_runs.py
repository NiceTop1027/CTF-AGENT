#!/usr/bin/env python3
"""Turn completed Codex reports into small reusable heuristics for later runs."""
import json
import re
from pathlib import Path
from paths import WORKSPACE

ROOT = WORKSPACE
RUNS = ROOT / "data" / "raw" / "agent_runs"
OUT = ROOT / "data" / "raw" / "learned_patterns.json"


def main():
    patterns = []
    details_path = ROOT / "data" / "raw" / "challenge_details.json"
    details = {x.get("id"): x for x in json.loads(details_path.read_text())} if details_path.exists() else {}
    # `challenge-N.jsonl` is always the latest attempt. Archived retries use
    # `challenge-N-attempt-M.jsonl` and are evidence for deduplication only.
    for path in sorted(RUNS.glob("challenge-*.jsonl")):
        text = path.read_text(errors="replace")
        cid = re.fullmatch(r"challenge-(\d+)", path.stem)
        if not cid:
            continue
        # Only trust the report's explicit candidate section. Do not treat
        # challenge examples such as TDHT{...} as discovered flags.
        candidate_parts = re.findall(
            r"candidate flags?\s*:?[ \t]*(.*?)(?=\n\s*(?:confidence|single best next step|observations|commands run)\b|\Z)",
            text, flags=re.IGNORECASE | re.DOTALL,
        )
        flags = []
        for part in candidate_parts:
            flags.extend(re.findall(r"\b[A-Z0-9_]{2,20}\{[^}\n]{1,200}\}", part))
        flags = sorted({flag for flag in flags if "..." not in flag})
        previous_flags = set()
        for previous_path in RUNS.glob(f"challenge-{cid.group(1)}-attempt-*.jsonl"):
            previous_text = previous_path.read_text(errors="replace")
            previous_parts = re.findall(
                r"candidate flags?\s*:?[ \t]*(.*?)(?=\n\s*(?:confidence|single best next step|observations|commands run)\b|\Z)",
                previous_text,
                flags=re.IGNORECASE | re.DOTALL,
            )
            for part in previous_parts:
                previous_flags.update(re.findall(r"\b[A-Z0-9_]{2,20}\{[^}\n]{1,200}\}", part))
        repeated_flags = sorted(set(flags) & previous_flags)
        flags = sorted(set(flags) - previous_flags)
        tags = []
        for word in ("SQLi", "XSS", "SSRF", "JWT", "CSRF", "IDOR", "LFI", "RCE", "API token", "command injection"):
            if word.lower() in text.lower():
                tags.append(word)
        patterns.append({
            "challenge_title": details.get(int(cid.group(1)), {}).get("name") if cid else None,
            "challenge_id": int(cid.group(1)) if cid else None,
            "source": str(path.relative_to(ROOT)),
            "candidate_count": len(flags),
            "candidate_flags": flags,
            "reanalysis": bool(previous_flags),
            "repeated_candidate_flags": repeated_flags,
            "technique_tags": tags,
            "status": "candidate" if flags else "blocked_or_unsolved",
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(patterns, indent=2, ensure_ascii=False) + "\n")
    print(f"[학습 갱신] 보고서 {len(patterns)}개 반영 -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
