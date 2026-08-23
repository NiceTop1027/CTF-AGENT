#!/usr/bin/env python3
"""Small cross-process event bus for the live NiceTop dashboard.

Only public progress summaries are persisted.  Raw model reasoning and tool
outputs are intentionally not copied into the UI event stream.
"""
import datetime as dt
import fcntl
import json
import os
import re
from pathlib import Path

from paths import WORKSPACE

ROOT = WORKSPACE
RUNTIME = ROOT / "data/runtime"
EVENTS = RUNTIME / "agent_events.jsonl"
ACTIVITY = RUNTIME / "agent_activity.json"
LOCK = RUNTIME / "agent_events.lock"


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def redact(value, limit=180):
    """Keep the stream useful without copying credentials, tokens, or flags."""
    text = str(value or "").replace("\x1b", "").replace("\n", " ").strip()
    text = re.sub(r"(?i)(password|passwd|token|authorization|cookie)(\s*[=:]\s+)[^\s]+", r"\1\2***", text)
    text = re.sub(r"\b[A-Z0-9_]{2,24}\{[^}\n]{1,220}\}", "FLAG{redacted}", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def _lock():
    RUNTIME.mkdir(parents=True, exist_ok=True)
    handle = LOCK.open("a+", encoding="utf-8")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def _read_activity():
    try:
        value = json.loads(ACTIVITY.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_activity(value):
    tmp = ACTIVITY.with_name(f".{ACTIVITY.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, ACTIVITY)


def set_activity(challenge_id, title, status, phase, message, started_at=None):
    """Set the compact latest state for one worker."""
    cid = str(challenge_id)
    timestamp = now()
    with _lock() as handle:
        activity = _read_activity()
        previous = activity.get(cid, {})
        started_at = started_at or previous.get("started_at") or timestamp
        activity[cid] = {
            "id": challenge_id,
            "title": title,
            "status": status,
            "phase": phase,
            "message": redact(message),
            "started_at": started_at,
            "updated_at": timestamp,
        }
        _write_activity(activity)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def record_event(challenge_id, title, phase, message, status="running", event_type="progress"):
    """Append a dashboard event and update the worker's latest activity."""
    timestamp = now()
    record = {
        "timestamp": timestamp,
        "id": challenge_id,
        "title": title,
        "phase": phase,
        "message": redact(message),
        "status": status,
        "type": event_type,
    }
    cid = str(challenge_id)
    with _lock() as handle:
        with EVENTS.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
        activity = _read_activity()
        previous = activity.get(cid, {})
        activity[cid] = {
            "id": challenge_id,
            "title": title,
            "status": status,
            "phase": phase,
            "message": record["message"],
            "started_at": previous.get("started_at") or timestamp,
            "updated_at": timestamp,
        }
        _write_activity(activity)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def summarize_codex_event(payload):
    """Map a Codex JSONL event to a safe, human-readable dashboard update."""
    if not isinstance(payload, dict):
        return None
    event_type = payload.get("type", "")
    envelope = payload.get("msg") if isinstance(payload.get("msg"), dict) else payload
    event_type = event_type or envelope.get("type", "")
    item = payload.get("item") or envelope.get("item") or {}
    item_type = item.get("type", "") if isinstance(item, dict) else ""
    started = event_type in ("thread.started", "turn.started", "item.started")
    completed = event_type in ("turn.completed", "item.completed")

    if event_type == "thread.started":
        return ("세션", "Codex 작업 세션 연결됨", "running", event_type)
    if event_type == "turn.started":
        return ("계획", "다음 분석 턴 시작", "running", event_type)
    if event_type == "turn.completed":
        return ("검증", "턴 완료 · 결과 정리 중", "running", event_type)
    if event_type == "error":
        return ("오류", f"Codex 오류: {redact(payload.get('message') or envelope.get('message'))}", "failed", event_type)

    verb = "시작" if started else "완료" if completed else "갱신"
    if item_type == "command_execution":
        command = redact(item.get("command", "명령"), 145)
        return ("터미널", f"명령 {verb}: {command}", "running", event_type)
    if item_type == "web_search":
        return ("웹 검색", f"공개 자료 검색 {verb}", "running", event_type)
    if item_type == "mcp_tool_call":
        tool = item.get("tool") or item.get("server") or "MCP 도구"
        return ("도구", f"{redact(tool, 100)} {verb}", "running", event_type)
    if item_type == "file_change":
        return ("파일", f"분석 파일 상태 {verb}", "running", event_type)
    if item_type == "todo_list":
        return ("계획", f"풀이 계획 {verb}", "running", event_type)
    if item_type == "reasoning":
        # Do not expose private chain-of-thought; show only that the public
        # progress summary advanced and that the worker is still reasoning.
        return ("판단", "깊이 추론 중 · 가설과 검증 신호 대조", "running", event_type)
    if item_type == "agent_message":
        text = item.get("text", "")
        headings = {"observations", "commands run", "candidate flags", "confidence", "verification signal", "single best next step"}
        lines = [line.strip(" -*\t") for line in str(text).splitlines() if line.strip()]
        first_line = next((line for line in lines if line.lower().rstrip(":") not in headings), None) or (lines[0] if lines else "에이전트 보고서 갱신")
        return ("에이전트", redact(first_line, 145), "running", event_type)
    if event_type:
        return ("상태", f"{redact(event_type, 80)} {verb}", "running", event_type)
    return None
