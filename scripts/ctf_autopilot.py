#!/usr/bin/env python3
"""One-command CTF automation pipeline using the logged-in Codex CLI."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(label, command, env):
    print(f"\n=== {label} ===", flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode:
        raise SystemExit(f"{label} failed with exit code {result.returncode}")


def main():
    ap = argparse.ArgumentParser(description="Run the complete CTF discovery and Codex solve loop")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=1, help="How many batches of fresh challenges to investigate")
    ap.add_argument("--ids", nargs="+", type=int, help="Optional challenge IDs; otherwise rank automatically")
    ap.add_argument("--skip-inventory", action="store_true")
    args = ap.parse_args()
    env = os.environ.copy()
    required = ("CTF_URL", "CTF_USER", "CTF_PASSWORD")
    if not args.skip_inventory and not all(env.get(x) for x in required):
        raise SystemExit("Set CTF_URL, CTF_USER and CTF_PASSWORD first")
    if not args.skip_inventory:
        run("inventory and attachment collection", [PYTHON, "scripts/ctf_inventory.py"], env)
    run("deterministic fast scan", [PYTHON, "scripts/ctf_fastscan.py"], env)
    run("name and description ranking", [PYTHON, "scripts/rank_challenges.py"], env)
    for round_no in range(args.rounds):
        cmd = [PYTHON, "scripts/codex_ctf_workers.py", "--workers", str(args.workers)]
        if args.ids:
            cmd += ["--ids", *map(str, args.ids)]
        run(f"Codex investigation batch {round_no + 1}/{args.rounds}", cmd, env)
        run("learn from worker reports", [PYTHON, "scripts/learn_from_runs.py"], env)
    print("\nAutopilot complete. Review data/raw/agent_runs/ and data/raw/fast_priority.json.")


if __name__ == "__main__":
    main()
