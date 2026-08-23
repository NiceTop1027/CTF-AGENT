#!/usr/bin/env python3
"""Terminal dashboard for the continuous CTF queue."""
import argparse
import json
import os
import select
import sys
import subprocess
import termios
import tty
import time
from datetime import datetime
from pathlib import Path
from paths import WORKSPACE, CODE_ROOT
try:
    from rich.console import Group
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    RICH = True
except ImportError:
    RICH = False

ROOT = WORKSPACE
STATE = ROOT / "data/runtime/live_status.json"
LEARNED = ROOT / "data/raw/learned_patterns.json"
SERVER_STATUS = ROOT / "data/raw/server_status.json"

COLORS = {
    "정답 확인": "\033[1;42;30m", "플래그 발견": "\033[1;32m",
    "플래그 후보": "\033[1;33m", "분석 중": "\033[1;36m",
    "분석 완료·미발견": "\033[1;31m", "대기": "\033[1;34m",
}
RESET = "\033[0m"


def paint_status(status):
    color = next((value for key, value in COLORS.items() if status.startswith(key)), "")
    padded = f"{status:<12}"
    return f"{color}{padded}{RESET}" if color else padded


def load_state():
    try:
        state = json.loads(STATE.read_text()) if STATE.exists() else {"problems": []}
    except (OSError, json.JSONDecodeError):
        state = {"problems": []}
    try:
        learned = json.loads(LEARNED.read_text()) if LEARNED.exists() else []
        by_title = {x.get("challenge_title"): x.get("candidate_flags", []) for x in learned}
        for item in state.get("problems", []):
            item["flags"] = [f for f in item.get("flags", []) if "..." not in f]
            if not item.get("flags"):
                item["flags"] = by_title.get(item.get("title"), [])
            item["flags"] = [f for f in item.get("flags", []) if "..." not in f]
            if item.get("status") in {"보류", "완료/보류"}:
                item["status"] = "플래그 후보" if item.get("flags") else "분석 완료·미발견"
    except (OSError, json.JSONDecodeError):
        pass
    try:
        solved = {x.get("title") for x in json.loads(SERVER_STATUS.read_text()) if x.get("solved_by_me")}
        for item in state.get("problems", []):
            if item.get("title") in solved:
                item["status"] = "정답 확인"
    except (OSError, json.JSONDecodeError):
        pass
    state["flags_found"] = sum(len(x.get("flags", [])) for x in state.get("problems", []))
    return state


def rich_dashboard(selected=0):
    state = load_state()
    problems = state.get("problems", [])
    counts = {key: sum(1 for x in problems if str(x.get("status", "")).startswith(key)) for key in ("정답 확인", "플래그 후보", "분석 중", "분석 완료·미발견", "대기")}
    header = Text()
    header.append("N I C E T O P", style="bold bright_green")
    header.append("  //  CTF AUTOPILOT\n", style="bold bright_white")
    header.append("authorized operations console  |  live orchestration", style="dim cyan")
    stats = Table.grid(expand=True, padding=(0, 2))
    for _ in range(4): stats.add_column(justify="center")
    stats.add_row(Text(f"{counts['정답 확인']}", style="bold black on green"), Text(f"{counts['플래그 후보']}", style="bold yellow"), Text(f"{counts['분석 중']}", style="bold cyan"), Text(f"{counts['대기']}", style="bold blue"))
    stats.add_row("VERIFIED", "CANDIDATES", "ACTIVE", "QUEUED")
    table = Table(show_header=True, header_style="bold bright_green", expand=True, box=None, row_styles=["none", "dim"])
    table.add_column("CHALLENGE", min_width=25); table.add_column("CAT", width=10); table.add_column("PTS", width=5, justify="right"); table.add_column("SOLVES", width=6, justify="right"); table.add_column("FILES", width=5, justify="right"); table.add_column("STATE", width=18); table.add_column("FLAG / SIGNAL", overflow="fold"); table.add_column("ACTION", width=22)
    styles = {"정답 확인": "bold black on green", "플래그 발견": "bold green", "플래그 후보": "yellow", "분석 중": "bold cyan", "분석 완료·미발견": "bold red", "대기": "blue"}
    for index, item in enumerate(state.get("problems", [])):
        status = str(item.get("status", "대기"))
        title = str(item.get("title", "알 수 없음")); flags_text = ", ".join(item.get("flags", [])) or Text("—", style="dim")
        title_text = Text(title, style="bold black on bright_green" if index == selected else "bold white")
        action = Text("[R] RETRY", style="bold yellow") if item.get("flags") and status.startswith("플래그 후보") else Text("[I] START", style="bold cyan") if item.get("type") == "dynamic_iac" else Text("—", style="dim")
        table.add_row(title_text, str(item.get("category", "-"))[:10], str(item.get("points", 0)), str(item.get("solves", 0)), str(item.get("files", 0)), Text(status, style=next((v for k, v in styles.items() if status.startswith(k)), "white")), flags_text, action)
    flags = [f"{x.get('title', '알 수 없음')} : {flag}" for x in state.get("problems", []) for flag in x.get("flags", [])]
    active = [x.get("title", "알 수 없음") for x in state.get("problems", []) if x.get("status") == "분석 중"]
    activity = Text(); activity.append("LIVE TASKS\n", style="bold bright_cyan"); activity.append("\n".join(f"▸ {x}" for x in active) if active else "idle — queue is clear", style="white"); activity.append("\n\nSYSTEM\n", style="bold bright_cyan"); activity.append(f"flags      {state.get('flags_found', 0)}\nwriteups   {state.get('writeups', 0)}\nauto-submit OFF\nrefresh    {datetime.now().strftime('%H:%M:%S')}", style="dim white")
    copy = "\n".join(flags) if flags else "no flags discovered yet"
    body = Layout(); body.split_row(Layout(Panel(table, title="[bold bright_green]TARGET QUEUE[/bold bright_green]", border_style="green"), name="queue", ratio=3), Layout(Panel(activity, title="[bold bright_cyan]OPERATIONS[/bold bright_cyan]", border_style="cyan"), name="ops", ratio=1))
    root = Layout(); root.split_column(Layout(Panel(Align.center(header), border_style="bright_green"), size=5), Layout(Panel(stats, border_style="green"), size=4), body, Layout(Panel(copy, title="[bold green]FLAG VAULT // COPY-SAFE[/bold green]", border_style="green"), size=min(max(len(flags) + 2, 4), 12)), Layout(Align.center(Text("[↑↓/j/k] select   [R] retry   [I] start instance   [Q] quit", style="bold bright_green")), size=1))
    return root


def render(clear=True):
    if STATE.exists():
        try:
            state = json.loads(STATE.read_text())
        except json.JSONDecodeError:
            state = {"problems": []}
    else:
        state = {"problems": []}
    if LEARNED.exists():
        try:
            learned = json.loads(LEARNED.read_text())
            by_title = {x.get("challenge_title"): x.get("candidate_flags", []) for x in learned}
            for item in state.get("problems", []):
                if not item.get("flags"):
                    item["flags"] = by_title.get(item.get("title"), [])
                if item.get("status") == "완료/보류":
                    item["status"] = "플래그 후보" if item.get("flags") else "분석 완료·미발견"
            state["flags_found"] = sum(len(x.get("flags", [])) for x in state.get("problems", []))
        except (OSError, json.JSONDecodeError):
            pass
    if SERVER_STATUS.exists():
        try:
            solved = {x.get("title") for x in json.loads(SERVER_STATUS.read_text()) if x.get("solved_by_me")}
            for item in state.get("problems", []):
                if item.get("title") in solved:
                    item["status"] = "정답 확인"
        except (OSError, json.JSONDecodeError):
            pass
    if clear:
        os.system("clear")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                 CTF 실시간 자동 풀이 모니터                         ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    overall = state.get("overall", "대기")
    print(f"갱신: {datetime.now().strftime('%H:%M:%S')}   전체 상태: {paint_status(overall)}")
    print("─" * 76)
    print(f"{'문제 제목':<32} {'상태':<12} {'플래그':<24}")
    print("─" * 76)
    for item in state.get("problems", []):
        title = str(item.get("title", "알 수 없음"))[:30]
        status = str(item.get("status", "대기"))[:10]
        flags = ", ".join(item.get("flags", [])) or "-"
        print(f"{title:<32} {paint_status(status)} {flags}")
    print("─" * 76)
    print(f"발견 플래그: {state.get('flags_found', 0)}   자동 제출: 꺼짐")
    print("\n[복사용 전체 플래그]")
    copied = False
    for item in state.get("problems", []):
        for flag in item.get("flags", []):
            print(f"{item.get('title', '알 수 없음')} : {flag}")
            copied = True
    if not copied:
        print("아직 발견된 플래그가 없습니다.")
    active = [x.get("title", "알 수 없음") for x in state.get("problems", []) if x.get("status") == "분석 중"]
    print("\n[현재 작업 중]")
    print("\n".join(f"- {title}" for title in active) if active else "현재 실행 중인 문제가 없습니다.")
    print(f"라이트업: {state.get('writeups', 0)}개   로그: data/logs/ctf_continue.log")
    print("종료하려면 Ctrl-C를 누르세요.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--no-clear", action="store_true")
    args = ap.parse_args()
    try:
        if RICH and not args.once and not args.no_clear:
            selected = 0
            fd = sys.stdin.fileno(); previous = termios.tcgetattr(fd); tty.setcbreak(fd)
            try:
                with Live(rich_dashboard(selected), refresh_per_second=1, screen=True) as live:
                    while True:
                        ready, _, _ = select.select([sys.stdin], [], [], args.interval)
                        if ready:
                            key = sys.stdin.read(1).lower(); state = load_state(); problems = state.get("problems", [])
                            if key in ("q", "\x03"): break
                            if key in ("j", "\x1b") and problems: selected = min(selected + 1, len(problems) - 1)
                            elif key == "k" and problems: selected = max(selected - 1, 0)
                            elif key == "r" and problems:
                                title = problems[selected].get("title"); p = ROOT / "data/runtime/retry_queue.json"; p.parent.mkdir(parents=True, exist_ok=True); items = json.loads(p.read_text()) if p.exists() else []
                                if title not in items: items.append(title)
                                p.write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n")
                            elif key == "i" and problems and problems[selected].get("type") == "dynamic_iac":
                                subprocess.run([sys.executable, str(CODE_ROOT / "scripts" / "ctf_instances.py"), "--ids", str(problems[selected].get("id"))], cwd=ROOT, env=os.environ.copy(), check=False)
                        live.update(rich_dashboard(selected), refresh=True)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, previous)
            return
        while True:
            render(clear=not args.no_clear)
            if args.once:
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n모니터를 종료했습니다. 백그라운드 작업 상태는 로그에 보존됩니다.")


if __name__ == "__main__":
    main()
