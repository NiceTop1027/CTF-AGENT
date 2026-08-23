#!/usr/bin/env python3
"""NiceTop live CTF operations console with clickable controls and agent telemetry."""
import base64
import json
import os
import signal
import subprocess
import sys

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, Label, Button, RichLog, Select

from paths import WORKSPACE, CODE_ROOT
from agent_events import record_event
from codex_profile import available_models, label as model_label, reasoning_options, resolve_profile, save_profile

ROOT = WORKSPACE
STATE = ROOT / "data/runtime/live_status.json"
LEARNED = ROOT / "data/raw/learned_patterns.json"
SERVER = ROOT / "data/raw/server_status.json"
DETAILS = ROOT / "data/raw/challenge_details.json"
EVENTS = ROOT / "data/runtime/agent_events.jsonl"
ACTIVITY = ROOT / "data/runtime/agent_activity.json"


class NiceTopApp(App):
    TITLE = "N I C E T O P // CTF AUTOPILOT"
    BINDINGS = [
        ("ctrl+c", "quit", "종료"),
        ("q", "quit", "종료"),
        ("c", "copy_flags", "플래그 복사"),
    ]
    CSS = """
    Screen { background: #0b0e14; color: #d8deee; }
    Header { background: #151a28; color: #b9c7ff; }
    Footer { background: #111621; color: #8f9aba; }
    #brand { height: 4; border: round #58699f; content-align: center middle; color: #cbd5ff; text-style: bold; }
    #stats { height: 3; margin: 1 0; border: round #303b61; content-align: center middle; color: #c7d2fe; }
    #profilebar { height: 3; border: round #303b61; padding: 0 1; content-align: center middle; }
    #profile-title { width: 19; color: #b9c7ff; text-style: bold; }
    #model-select { width: 29; margin: 0 1; }
    #reasoning-select { width: 20; margin: 0 1; }
    #apply-profile { width: 11; min-width: 11; background: #344b82; color: white; }
    #profile-note { width: 1fr; color: #8f9aba; padding: 0 1; }
    #main { height: 1fr; }
    #queue { width: 68%; border: round #303b61; padding: 0 1; }
    #inspector { width: 32%; border: round #303b61; margin-left: 1; }
    #queue-title, #inspector-title { height: 2; color: #b9c7ff; text-style: bold; padding: 0 1; }
    #rows { height: 1fr; }
    .row { height: 3; border-bottom: solid #222a3d; content-align: center middle; }
    .title { width: 29; color: #f1f5f9; text-style: bold; }
    .meta { width: 18; color: #9aa5c3; }
    .flag { width: 1fr; color: #f2d479; }
    Button { min-width: 11; width: 11; height: 3; margin: 0 1; }
    Button:hover { text-style: bold; border: round #f2d479; }
    Button:disabled { background: #353b4d; color: #dbe3ff; }
    .retry { background: #8f6713; color: white; }
    .instance { background: #344b82; color: white; }
    .copy { width: 17; min-width: 17; background: #344b82; color: white; }
    #agent-focus { height: 9; border-bottom: solid #303b61; padding: 1; color: #8ee7ff; overflow-y: auto; }
    #activity { height: 1fr; padding: 1; background: #0e121b; }
    #vaultbar { height: 9; border: round #58699f; margin-top: 1; padding: 0 1; }
    #vault-head { height: 2; }
    #vault-title { width: 1fr; color: #b9c7ff; text-style: bold; }
    #vault { height: 1fr; color: #f2d479; overflow-y: auto; }
    #hint { height: 2; content-align: center middle; color: #8d96b3; }
    .verified { color: #a5b4fc; text-style: bold; }
    .candidate { color: #f2d479; }
    .active { color: #5de4ff; text-style: bold; }
    .blocked { color: #ff746e; }
    .queued { color: #93c5fd; }
    """

    def compose(self) -> ComposeResult:
        profile = resolve_profile()
        model_options = [
            (item.get("display_name", item.get("slug")), item.get("slug"))
            for item in available_models()
        ]
        reasoning_choices = [(f"추론 {level}", level) for level in reasoning_options(profile["model"])]
        yield Header(show_clock=True)
        yield Static(
            "N I C E T O P   //   CTF AUTOPILOT\n"
            "허가된 CTF 작업 콘솔 · 실시간 에이전트 오케스트레이션",
            id="brand",
        )
        yield Static("텔레메트리 로딩 중...", id="stats")
        with Horizontal(id="profilebar"):
            yield Static("AI PROFILE", id="profile-title")
            yield Select(model_options, value=profile["model"], allow_blank=False, id="model-select")
            yield Select(reasoning_choices, value=profile["reasoning"], allow_blank=False, id="reasoning-select")
            yield Button("적용", id="apply-profile")
            yield Static("다음 워커부터 적용", id="profile-note")
        with Horizontal(id="main"):
            with Vertical(id="queue"):
                yield Static("TARGET QUEUE  ·  제목 기준 · 마우스 액션", id="queue-title")
                yield ScrollableContainer(id="rows")
            with Vertical(id="inspector"):
                yield Static("LIVE AGENT STREAM  ·  공개 진행 요약", id="inspector-title")
                yield Static("에이전트 이벤트를 기다리는 중...", id="agent-focus", markup=False)
                yield RichLog(id="activity", wrap=True, highlight=False, markup=False, max_lines=160)
        with Vertical(id="vaultbar"):
            with Horizontal(id="vault-head"):
                yield Static("FLAG VAULT // 복사 안전", id="vault-title")
                yield Button("⧉ 플래그 복사", id="copy-flags", classes="copy")
            yield Static("발견된 플래그가 아직 없습니다.", id="vault", markup=False)
        yield Static("마우스: 모델/추론 변경·재탐색·인스턴스  ·  C: 플래그 복사  ·  Ctrl-C 또는 Q: 전체 종료", id="hint")
        yield Footer()

    async def on_mount(self) -> None:
        self.retry_processes = {}
        self.instance_processes = {}
        self.retry_reported = set()
        self.rows_by_id = {}
        self._refreshing = False
        await self.refresh_ui()
        self.set_interval(1.0, self.refresh_ui)

    def action_quit(self) -> None:
        self._stop_all_processes()
        self.exit()

    def action_copy_flags(self) -> None:
        state = self.read_state()
        text = "\n".join(
            f"{x.get('title')} : {flag}"
            for x in state.get("problems", [])
            for flag in x.get("flags", [])
            if "..." not in flag
        )
        if not text:
            self.notify("복사할 플래그가 아직 없습니다.", severity="warning")
            return
        copied = False
        for command in (("wl-copy",), ("xclip", "-selection", "clipboard"), ("xsel", "--clipboard", "--input"), ("pbcopy",)):
            try:
                subprocess.run(command, input=text, text=True, check=True, timeout=2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                copied = True
                break
            except (FileNotFoundError, subprocess.SubprocessError, OSError):
                continue
        if not copied:
            payload = base64.b64encode(text.encode()).decode()
            sys.__stdout__.write(f"\033]52;c;{payload}\a")
            sys.__stdout__.flush()
        self.notify("플래그 전체 목록을 클립보드로 보냈습니다.")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "model-select" or event.value is Select.BLANK:
            return
        model = str(event.value)
        choices = reasoning_options(model)
        reasoning = self.query_one("#reasoning-select", Select)
        current = str(reasoning.value) if reasoning.value is not Select.BLANK else ""
        selected = current if current in choices else choices[0]
        reasoning.set_options([(f"추론 {level}", level) for level in choices])
        reasoning.value = selected

    def action_apply_profile(self) -> None:
        model = self.query_one("#model-select", Select).value
        reasoning = self.query_one("#reasoning-select", Select).value
        if model is Select.BLANK or reasoning is Select.BLANK:
            self.notify("모델과 추론 단계를 먼저 선택하세요.", severity="warning")
            return
        try:
            profile = save_profile(str(model), str(reasoning))
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        record_event(
            "profile",
            "AI 프로필",
            "모델 변경",
            f"{profile['display_name']} / 추론 {profile['reasoning']} · 다음 워커부터 적용",
            "completed",
            "profile.changed",
        )
        self.notify(f"적용 완료 · {profile['display_name']} / {profile['reasoning']} · 다음 워커부터 적용")

    @staticmethod
    def _stop_process(process) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except ProcessLookupError:
                return
        try:
            process.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

    def _stop_all_processes(self) -> None:
        for process in list(self.retry_processes.values()) + list(self.instance_processes.values()):
            self._stop_process(process)
        self.retry_processes.clear()
        self.instance_processes.clear()

    def on_unmount(self) -> None:
        self._stop_all_processes()

    @staticmethod
    def _tail_jsonl(path, limit=100):
        if not path.exists():
            return []
        try:
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - 160_000))
                raw = stream.read().decode("utf-8", "replace")
            rows = []
            for line in raw.splitlines()[-limit:]:
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
                except ValueError:
                    continue
            return rows
        except OSError:
            return []

    def read_activity(self):
        try:
            activity = json.loads(ACTIVITY.read_text(encoding="utf-8")) if ACTIVITY.exists() else {}
            if not isinstance(activity, dict):
                activity = {}
        except (OSError, ValueError):
            activity = {}
        return activity, self._tail_jsonl(EVENTS, 100)

    def read_state(self):
        try:
            state = json.loads(STATE.read_text()) if STATE.exists() else {"problems": []}
        except Exception:
            state = {"problems": []}
        try:
            learned = json.loads(LEARNED.read_text()) if LEARNED.exists() else []
            by_title = {x.get("challenge_title"): x.get("candidate_flags", []) for x in learned}
            for x in state.get("problems", []):
                if not x.get("flags"):
                    x["flags"] = by_title.get(x.get("title"), [])
        except Exception:
            pass
        try:
            solved = {x.get("title") for x in json.loads(SERVER.read_text()) if x.get("solved_by_me")}
            for x in state.get("problems", []):
                if x.get("title") in solved:
                    x["status"] = "정답 확인"
        except Exception:
            pass
        try:
            details = {str(x.get("id")): x for x in json.loads(DETAILS.read_text())}
            for x in state.get("problems", []):
                detail = details.get(str(x.get("id")), {})
                x["type"] = x.get("type") or detail.get("type", "")
                x["category"] = x.get("category") or detail.get("category", "-")
        except Exception:
            pass
        try:
            activity = json.loads(ACTIVITY.read_text()) if ACTIVITY.exists() else {}
            for x in state.get("problems", []):
                current = activity.get(str(x.get("id")), {})
                if current.get("status") == "failed" and not str(x.get("status", "")).startswith("정답"):
                    x["status"] = current.get("phase") or "문제 발생·확인 필요"
                    x["next_action"] = current.get("message", "")
                    x["issue_label"] = current.get("phase", "문제 발생·확인 필요")
        except (OSError, ValueError, TypeError):
            pass
        return state

    @staticmethod
    def _status_class(status):
        if status.startswith("정답"):
            return "verified"
        if status.startswith("플래그"):
            return "candidate"
        if any(term in status for term in ("정책 차단", "수동 필요", "인프라 오류", "접근 오류", "네트워크 오류", "도구/실행 오류", "오류")):
            return "blocked"
        if status.startswith(("분석 중", "재탐색 중")):
            return "active"
        if "재시도" in status or "다음 전략" in status or "중복 실행" in status:
            return "active"
        if "미발견" in status:
            return "blocked"
        return "queued"

    @staticmethod
    def _meta(item, status):
        return f"{item.get('category', '-')}  {item.get('points', 0)}p\n{item.get('solves', 0)} solves · {status}"

    async def refresh_ui(self) -> None:
        if self._refreshing:
            return
        self._refreshing = True
        try:
            await self._refresh_ui()
        finally:
            self._refreshing = False

    async def _refresh_ui(self) -> None:
        state = self.read_state()
        problems = state.get("problems", [])
        counts = {key: sum(str(x.get("status", "")).startswith(key) for x in problems) for key in ("정답 확인", "플래그 후보", "분석 중", "재탐색 중", "대기")}
        activity, events = self.read_activity()
        live_status = {str(x.get("id")): str(x.get("status", "")) for x in problems}
        active_targets = [x for x in problems if str(x.get("status", "")).startswith(("분석 중", "재탐색 중"))]
        active_agents = [x for x in activity.values() if x.get("status") == "running" and live_status.get(str(x.get("id")), "").startswith(("분석 중", "재탐색 중"))]
        attention_agents = [x for x in activity.values() if x.get("status") == "failed" and not live_status.get(str(x.get("id")), "").startswith("정답")]
        self.query_one("#stats", Static).update(
            f"확인 {counts['정답 확인']}   후보 {counts['플래그 후보']}   진행 {counts['분석 중'] + counts['재탐색 중']}   "
            f"에이전트 {len(active_targets)}   대기 {counts['대기']}   |   플래그 {state.get('flags_found', 0)}   "
            f"주의 {len(attention_agents)}   라이트업 {state.get('writeups', 0)}   자동 제출 OFF   |   {model_label()}"
        )
        rows = self.query_one("#rows", ScrollableContainer)
        for item in problems:
            cid = str(item.get("id"))
            status = str(item.get("status", "대기"))
            cls = self._status_class(status)
            meta = self._meta(item, status)
            if cid not in self.rows_by_id:
                children = [
                    Label(str(item.get("title", "알 수 없음")), id=f"title-{cid}", classes="title"),
                    Label(meta, id=f"meta-{cid}", classes="meta"),
                    Label(", ".join(item.get("flags", [])) or "—", id=f"flag-{cid}", classes=f"flag {cls}"),
                    Button("↻ 재탐색", id=f"retry-{cid}", classes="retry"),
                ]
                if item.get("type") == "dynamic_iac":
                    children.append(Button("▶ 인스턴스", id=f"instance-{cid}", classes="instance"))
                row = Horizontal(*children, classes="row")
                await rows.mount(row)
                self.rows_by_id[cid] = row
            else:
                row = self.rows_by_id[cid]
                row.query_one(f"#title-{cid}", Label).update(str(item.get("title", "알 수 없음")))
                row.query_one(f"#meta-{cid}", Label).update(meta)
                flag = row.query_one(f"#flag-{cid}", Label)
                flag.update(", ".join(item.get("flags", [])) or "—")
                flag.set_classes(f"flag {cls}")
            retry = row.query_one(f"#retry-{cid}", Button)
            retry_process = self.retry_processes.get(cid)
            retry_running = retry_process is not None and retry_process.poll() is None
            if retry_process is not None and not retry_running and cid not in self.retry_reported:
                code = retry_process.returncode
                record_event(cid, item.get("title"), "재탐색", f"재탐색 워커 종료 · exit {code}", "completed" if code == 0 else "failed", "retry.finished")
                self.retry_reported.add(cid)
            retry.display = not status.startswith("정답 확인")
            retry.disabled = retry_running
            retry.label = "RUNNING…" if retry_running else "↻ 재탐색"
            if item.get("type") == "dynamic_iac":
                instance = row.query_one(f"#instance-{cid}", Button)
                instance_process = self.instance_processes.get(cid)
                instance_running = instance_process is not None and instance_process.poll() is None
                instance.disabled = instance_running
                instance.label = "STARTING…" if instance_running else "▶ 인스턴스"

        focus = self.query_one("#agent-focus", Static)
        if active_agents:
            focus.update("\n".join(f"● {x.get('title')}\n  {x.get('phase')} · {x.get('message')}" for x in sorted(active_agents, key=lambda value: value.get("updated_at", ""), reverse=True)[:4]))
        elif attention_agents:
            focus.update("\n".join(f"! {x.get('title')}\n  {x.get('phase')} · {x.get('message')}" for x in sorted(attention_agents, key=lambda value: value.get("updated_at", ""), reverse=True)[:4]))
        elif active_targets:
            focus.update("\n".join(f"● {x.get('title')}\n  워커 준비 · Codex 이벤트 대기" for x in active_targets[:4]))
        else:
            focus.update("대기 중인 Codex 작업자가 없습니다.\n재탐색 버튼을 누르면 이곳에 즉시 표시됩니다.")

        log = self.query_one("#activity", RichLog)
        log.clear()
        if events:
            for event in events[-55:]:
                timestamp = str(event.get("timestamp", ""))[-8:]
                title = str(event.get("title", "알 수 없음"))[:20]
                phase = str(event.get("phase", "상태"))[:9]
                message = str(event.get("message", ""))
                color = "#ff746e" if event.get("status") == "failed" else "#f2d479" if event.get("status") == "completed" else "#8ee7ff"
                line = Text()
                line.append(f"{timestamp} ", style="dim #7f8aa8")
                line.append(f"{title:<20} ", style="bold #c7d2fe")
                line.append(f"{phase:<9} ", style=color)
                line.append(message, style="#d8deee")
                log.write(line, scroll_end=True)
        else:
            log.write(Text("아직 Codex 이벤트가 없습니다. 워커가 시작되면 명령·검색·검증 단계가 여기에 표시됩니다.", style="dim #8f9aba"))

        flags = [f"{item.get('title')} : {flag}" for item in problems for flag in item.get("flags", []) if "..." not in flag]
        self.query_one("#vault", Static).update("\n".join(flags) if flags else "발견된 플래그가 아직 없습니다.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply-profile":
            self.action_apply_profile()
            return
        if event.button.id == "copy-flags":
            self.action_copy_flags()
            return
        kind, _, raw = event.button.id.partition("-")
        if kind == "retry":
            if raw in self.retry_processes and self.retry_processes[raw].poll() is None:
                self.notify("이미 재탐색 중입니다.", severity="warning")
                return
            activity, _ = self.read_activity()
            if activity.get(raw, {}).get("status") == "running":
                self.notify("기존 워커가 아직 실행 중입니다. 중복 실행을 막았습니다.", severity="warning")
                return
            title = next((x.get("title") for x in self.read_state().get("problems", []) if str(x.get("id")) == raw), None)
            if not title:
                return
            try:
                queue_file = ROOT / "data/runtime/retry_queue.json"
                queue_file.parent.mkdir(parents=True, exist_ok=True)
                queue = json.loads(queue_file.read_text()) if queue_file.exists() else []
                if title not in queue:
                    queue.append(title)
                queue_file.write_text(json.dumps(queue, ensure_ascii=False, indent=2) + "\n")
                state_file = ROOT / "data/runtime/live_status.json"
                live = json.loads(state_file.read_text()) if state_file.exists() else {"problems": []}
                for item in live.get("problems", []):
                    if str(item.get("id")) == raw:
                        item["status"] = "재탐색 중"
                state_file.write_text(json.dumps(live, ensure_ascii=False, indent=2) + "\n")
                process = subprocess.Popen(
                    [sys.executable, str(CODE_ROOT / "scripts/ctf_continue.py"), "--workers", "1", "--skip-inventory", "--only-id", raw],
                    cwd=ROOT, env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
                self.retry_processes[raw] = process
                self.retry_reported.discard(raw)
                record_event(raw, title, "재탐색", "선택한 문제만 다시 큐에 넣고 Codex 워커를 시작하는 중", "running", "retry.requested")
                event.button.disabled = True
                event.button.label = "RUNNING…"
                self.notify(f"재탐색 시작 · {title}")
            except (OSError, ValueError) as exc:
                event.button.disabled = False
                self.notify(f"재탐색 시작 실패: {exc}", severity="error")
        elif kind == "instance":
            existing = self.instance_processes.get(raw)
            if existing is not None and existing.poll() is None:
                return
            try:
                process = subprocess.Popen(
                    [sys.executable, str(CODE_ROOT / "scripts/ctf_instances.py"), "--ids", raw],
                    cwd=ROOT, env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
                self.instance_processes[raw] = process
                event.button.disabled = True
                event.button.label = "STARTING…"
                self.notify(f"인스턴스 시작 요청 · {raw}")
            except OSError as exc:
                self.notify(f"인스턴스 시작 실패: {exc}", severity="error")


if __name__ == "__main__":
    NiceTopApp().run()
