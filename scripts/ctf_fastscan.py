#!/usr/bin/env python3
"""Fast deterministic pre-pass: collect cheap evidence before using an LLM."""
import concurrent.futures
import hashlib
import json
import os
import subprocess
from pathlib import Path
from paths import WORKSPACE

ROOT = WORKSPACE
FILES = ROOT / "data" / "files"
OUT = ROOT / "data" / "raw" / "fastscan.json"


def run(cmd, cwd):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=20, check=False)
        return {"returncode": p.returncode, "stdout": p.stdout[:6000], "stderr": p.stderr[:2000]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def scan(path):
    raw = path.read_bytes()
    rel = str(path.relative_to(ROOT))
    return {
        "path": rel,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "file": run(["file", "-b", str(path)], ROOT),
        "strings": run(["strings", "-a", "-n", "4", str(path)], ROOT),
        "metadata": run(["exiftool", "-j", str(path)], ROOT) if shutil_which("exiftool") else {"skipped": True},
    }


def shutil_which(name):
    import shutil
    return shutil.which(name)


def main():
    paths = [p for p in FILES.rglob("*") if p.is_file() and not p.name.startswith(".")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(paths)))) as pool:
        results = list(pool.map(scan, paths))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(f"[빠른 분석] 파일 {len(results)}개 분석 완료 -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
