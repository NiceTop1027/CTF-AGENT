#!/usr/bin/env python3
"""Continuous title-based CTF queue: keep three Codex investigations full."""
import argparse
import concurrent.futures
import contextlib
import fcntl
import getpass
import json
import os
import re
import subprocess
import sys
import datetime
import threading
import time
from pathlib import Path
from paths import WORKSPACE, CODE_ROOT
from codex_profile import label as model_label
from issue_classifier import classify_issue

ROOT = WORKSPACE
SCRIPTS = CODE_ROOT / "scripts"
PYTHON = sys.executable
DETAILS = ROOT / "data/raw/challenge_details.json"
PRIORITY = ROOT / "data/raw/fast_priority.json"
LEARNED = ROOT / "data/raw/learned_patterns.json"
RUNS = ROOT / "data/raw/agent_runs"
WRITEUPS = ROOT / "writeups"
LOG_DIR = ROOT / "data/logs"
STATE = ROOT / "data/runtime/live_status.json"
RETRY = ROOT / "data/runtime/retry_queue.json"
LOCK_DIR = ROOT / "data/runtime/locks"


class Tee:
    def __init__(self, terminal, log):
        self.terminal = terminal
        self.log = log

    def write(self, value):
        self.terminal.write(value)
        self.log.write(value)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()


def call(cmd, env):
    return subprocess.run(cmd, cwd=ROOT, env=env, check=False, capture_output=True, text=True)


@contextlib.contextmanager
def challenge_lock(challenge_id):
    """Prevent the main queue and a UI retry from attacking one challenge together."""
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    path = LOCK_DIR / f"challenge-{challenge_id}.lock"
    handle = path.open("a+", encoding="utf-8")
    acquired = False
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        if acquired:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def safe_title(title):
    value = re.sub(r"[^A-Za-z0-9ก-힣 _.-]+", "", title).strip().replace(" ", "_")
    return value[:100] or "untitled"


def report_candidate_flags(text):
    sections = re.findall(
        r"candidate flags?\s*:?[ \t]*(.*?)(?=\n\s*(?:confidence|single best next step|observations|commands run)\b|\Z)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return sorted({flag for section in sections for flag in re.findall(r"\b[A-Z0-9_]{2,20}\{[^}\n]{1,200}\}", section) if "..." not in flag})


def prior_attempt_flags(cid):
    values = set()
    snapshots = sorted(RUNS.glob(f"challenge-{cid}-attempt-*.jsonl"))
    for path in snapshots:
        values.update(report_candidate_flags(path.read_text(errors="replace")))
    return values, bool(snapshots)


def save_live(items, overall="실행 중"):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    flags = sum(len(x.get("flags", [])) for x in items.values())
    writeups = len(list(WRITEUPS.glob("*.md"))) if WRITEUPS.exists() else 0
    STATE.write_text(json.dumps({
        "overall": overall, "problems": list(items.values()),
        "flags_found": flags, "writeups": writeups,
    }, ensure_ascii=False, indent=2) + "\n")


def refresh(env):
    for cmd in (
        [PYTHON, str(SCRIPTS / "ctf_inventory.py")],
        [PYTHON, str(SCRIPTS / "ctf_fastscan.py")],
        [PYTHON, str(SCRIPTS / "rank_challenges.py")],
    ):
        result = call(cmd, env)
        print(result.stdout, end="", flush=True)
        if result.returncode:
            raise SystemExit(result.stderr or f"failed: {' '.join(cmd)}")


def start_server_status_monitor(env):
    """Poll CTFd's read-only solved_by_me field; never submits flags."""
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            subprocess.run(
                [PYTHON, str(SCRIPTS / "ctf_inventory.py"), "--status-only"],
                cwd=ROOT, env=env, check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            stop.wait(20)

    thread = threading.Thread(target=loop, name="ctfd-status-monitor", daemon=True)
    thread.start()
    return stop, thread


def run_one(challenge, env):
    cid = str(challenge["id"])
    with challenge_lock(cid) as acquired:
        if not acquired:
            print(f"[중복 방지] {challenge.get('name')}는 다른 워커가 이미 처리 중입니다.", flush=True)
            return subprocess.CompletedProcess(
                [], 0, stdout=json.dumps({"skipped": True, "id": challenge.get("id")}), stderr=""
            )
        if challenge.get("type") == "dynamic_iac":
            instance = call([PYTHON, str(SCRIPTS / "ctf_instances.py"), "--ids", cid], env)
            if instance.stdout:
                print(instance.stdout, end="", flush=True)
            if instance.stderr:
                print(instance.stderr[-800:], flush=True)
        return call([PYTHON, str(SCRIPTS / "codex_ctf_workers.py"), "--ids", cid, "--workers", "1"], env)


def worker_metadata(result):
    """Read the worker's final JSON line without trusting arbitrary stdout."""
    for line in reversed((result.stdout or "").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def learn_and_publish(challenge, env):
    call([PYTHON, str(SCRIPTS / "learn_from_runs.py")], env)
    report = RUNS / f"challenge-{challenge['id']}.jsonl"
    text = report.read_text(errors="replace") if report.exists() else "No report generated."
    all_flags = report_candidate_flags(text)
    previous_flags, is_reanalysis = prior_attempt_flags(challenge["id"])
    repeated_flags = sorted(set(all_flags) & previous_flags)
    flags = sorted(set(all_flags) - previous_flags)
    issue = classify_issue(text)
    if all_flags and issue["kind"] in ("infrastructure", "access_error", "network", "tool_error"):
        issue = {"kind": "none", "label": "", "action": ""}
    WRITEUPS.mkdir(parents=True, exist_ok=True)
    writeup = WRITEUPS / f"{safe_title(challenge.get('name', str(challenge['id'])))}.md"
    writeup.write_text(
        f"# {challenge.get('name')}\n\n"
        f"- Category: {challenge.get('category')}\n"
        f"- Challenge ID: {challenge.get('id')}\n"
        f"- Candidate flags (new): {', '.join(flags) if flags else 'none'}\n"
        f"- Repeated prior candidates (excluded): {', '.join(repeated_flags) if repeated_flags else 'none'}\n\n"
        "## Codex report\n\n" + text + "\n"
    )
    print(f"\n### {challenge.get('name')} ###", flush=True)
    print(f"[라이트업 저장] {writeup}", flush=True)
    if issue["kind"] != "none":
        print(f"[{issue['label']}] {issue['action']}", flush=True)
    if is_reanalysis and repeated_flags:
        print("[재탐색] 기존 후보 반복은 새 플래그로 인정하지 않습니다.", flush=True)
    if flags:
        print("[새 플래그 후보 발견]" if is_reanalysis else "[플래그 후보 발견]", flush=True)
        for flag in flags:
            print(flag, flush=True)
    else:
        print("[보류] 새 플래그 후보가 없어 다른 전략으로 다시 시도할 수 있습니다.", flush=True)
    return flags, repeated_flags, is_reanalysis, issue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--max-problems", type=int, default=0, help="0 = continue until queue is empty")
    ap.add_argument("--skip-inventory", action="store_true")
    ap.add_argument("--status-poll", action="store_true")
    ap.add_argument("--only-id", type=int, help="Run only one selected challenge")
    args = ap.parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log = (LOG_DIR / "ctf_continue.log").open("a", encoding="utf-8")
    log.write(f"\n===== 실행 시작 {datetime.datetime.now().isoformat(timespec='seconds')} =====\n")
    sys.stdout = Tee(sys.__stdout__, log)
    sys.stderr = Tee(sys.__stderr__, log)
    env = os.environ.copy()
    print(f"[AI 프로필] {model_label()} · 최고급 모델/최대 추론 설정", flush=True)
    env.setdefault("CTF_URL", "https://ctf.talldwarfhosting.com")
    env.setdefault("CTF_USER", "s13w00")
    # resume UI의 백그라운드 재탐색에서는 절대 숨은 getpass 프롬프트를 띄우지 않는다.
    if not env.get("CTF_PASSWORD") and not args.skip_inventory:
        env["CTF_PASSWORD"] = getpass.getpass("CTF password: ")
    status_stop = status_thread = None
    if env.get("CTF_PASSWORD"):
        status_stop, status_thread = start_server_status_monitor(env)
    if not args.skip_inventory:
        refresh(env)
    learned = json.loads(LEARNED.read_text()) if LEARNED.exists() else []
    retry_titles = set(json.loads(RETRY.read_text())) if RETRY.exists() else set()
    # 후보 플래그를 찾은 문제만 완료로 간주한다. 미발견 문제는 다음 실행에서 재공략한다.
    done = {x.get("challenge_id") for x in learned if x.get("status") == "candidate" and x.get("challenge_title") not in retry_titles}
    details = {x.get("id"): x for x in json.loads(DETAILS.read_text())}
    queue = [x for x in json.loads(PRIORITY.read_text()) if x.get("id") in details and x.get("id") not in done]
    if args.only_id:
        queue = [x for x in queue if x.get("id") == args.only_id]
    queue = queue[: args.max_problems] if args.max_problems else queue
    learned_by_id = {x.get("challenge_id"): x for x in learned}
    live = {}
    for x in json.loads(PRIORITY.read_text()):
        old = learned_by_id.get(x.get("id"), {})
        detail = details.get(x.get("id"), {})
        live[x.get("name")] = {
            "title": x.get("name"), "id": x.get("id"), "type": detail.get("type", x.get("type", "")), "status": "대기",
            "flags": old.get("candidate_flags", []),
            "category": x.get("category", "-"), "points": x.get("value", 0),
            "solves": x.get("solves", 0), "files": x.get("files", 0),
            "priority": x.get("fast_score", 0),
        }
    for title in live:
        if title not in {x.get("name") for x in queue}:
            old = learned_by_id.get(next((x.get("id") for x in json.loads(PRIORITY.read_text()) if x.get("name") == title), None), {})
            live[title]["status"] = "플래그 후보" if old.get("candidate_flags") else "분석 완료·미발견"
    save_live(live)
    active = {}
    session_retries = {}
    try:
        max_session_retries = max(0, int(os.environ.get("CTF_SESSION_RETRIES", "2")))
    except ValueError:
        max_session_retries = 2
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        while queue or active:
            while queue and len(active) < args.workers:
                item = queue.pop(0)
                print(f"\n[시작] {item.get('name')} 분석을 시작합니다.", flush=True)
                live[item.get("name")]["status"] = "분석 중"
                save_live(live)
                active[pool.submit(run_one, details[item["id"]], env)] = details[item["id"]]
            if not active:
                break
            finished = next(concurrent.futures.as_completed(active))
            challenge = active.pop(finished)
            result = finished.result()
            metadata = worker_metadata(result)
            skipped = bool(metadata.get("skipped"))
            failure_kind = metadata.get("failure_kind", "")
            issue_kind = metadata.get("issue_kind", "none")
            issue_label = metadata.get("issue_label", "")
            next_action = metadata.get("next_action", "")
            if result.returncode:
                print(f"[실패] {challenge.get('name')} 분석 실패", flush=True)
                print(result.stderr[-1200:], flush=True)
            elif skipped:
                print(f"[중복 생략] {challenge.get('name')}는 기존 워커가 계속 처리합니다.", flush=True)
            else:
                print(f"[완료] {challenge.get('name')} 분석 완료", flush=True)
            if skipped:
                # The owner of the lock will publish the report. Do not let a
                # duplicate process rewrite its live state or writeup.
                queue.append(challenge)
                live[challenge.get("name")]["status"] = "중복 실행 감지·대기"
                save_live(live)
                time.sleep(1)
                continue

            found, repeated, is_reanalysis, report_issue = learn_and_publish(challenge, env)
            if issue_kind == "none":
                issue_kind = report_issue.get("kind", "none")
                issue_label = report_issue.get("label", "")
                next_action = report_issue.get("action", "")
            live_item = live[challenge.get("name")]
            old_flags = list(live_item.get("flags", []))
            merged_flags = list(dict.fromkeys(old_flags + found))
            cid = str(challenge.get("id"))
            retries = session_retries.get(cid, 0)
            live_item["issue_kind"] = issue_kind
            live_item["issue_label"] = issue_label
            live_item["next_action"] = next_action
            if issue_kind in ("manual_required", "policy_blocked"):
                live_item["status"] = issue_label or "수동 확인 필요"
                print(f"[수동/정책 보류] {challenge.get('name')} · {next_action}", flush=True)
            elif issue_kind in ("infrastructure", "access_error", "network", "tool_error") and retries < max_session_retries:
                session_retries[cid] = retries + 1
                queue.append(challenge)
                live_item["status"] = f"{issue_label or '오류'} · 재시도 대기 ({retries + 1}/{max_session_retries})"
                print(f"[오류 재시도] {challenge.get('name')} · {next_action}", flush=True)
            elif result.returncode and retries < max_session_retries:
                session_retries[cid] = retries + 1
                queue.append(challenge)
                live_item["status"] = f"오류 재시도 대기 ({retries + 1}/{max_session_retries})"
                print(f"[자동 재시도] {challenge.get('name')} · {retries + 1}/{max_session_retries}", flush=True)
            elif result.returncode:
                live_item["status"] = "오류·이번 세션 한도 초과"
            elif not found and retries < max_session_retries:
                # A clean Codex exit without a candidate is not success. Give
                # the challenge another independent lens in this same run.
                session_retries[cid] = retries + 1
                queue.append(challenge)
                live_item["status"] = f"다음 전략 재시도 대기 ({retries + 1}/{max_session_retries})"
                print(f"[다음 전략] {challenge.get('name')} · 후보 미발견, 다른 관점으로 재시도", flush=True)
            elif is_reanalysis:
                live_item["status"] = "새 플래그 후보" if found else "재탐색 완료·새 후보 없음"
                live_item["flags"] = merged_flags
            else:
                live_item["status"] = "플래그 발견" if found else "보류"
                live_item["flags"] = found
            if result.returncode or not found:
                live_item["flags"] = merged_flags if is_reanalysis else (found or old_flags)
            save_live(live)
            completed += 1
    print(f"\n[종료] 총 {completed}개 문제를 처리했습니다.")
    if status_stop:
        status_stop.set()


if __name__ == "__main__":
    main()
