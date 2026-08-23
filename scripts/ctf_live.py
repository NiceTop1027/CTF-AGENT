#!/usr/bin/env python3
"""Start the continuous solver and show its live title-based dashboard."""
import argparse
import getpass
import json
import os
import signal
import subprocess
import sys
from paths import WORKSPACE, CODE_ROOT

ROOT = WORKSPACE
SCRIPTS = CODE_ROOT / "scripts"
PYTHON = sys.executable
CONFIG = ROOT / "data/runtime/ctf_config.json"


def stop_process_group(process):
    """Stop the solver and descendants even if a worker is waiting on I/O."""
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
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                pass


def load_saved_config(env):
    """Load only non-secret connection settings saved for this workspace."""
    if not CONFIG.exists():
        return
    try:
        saved = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    env.setdefault("CTF_URL", saved.get("url", ""))
    env.setdefault("CTF_USER", saved.get("user", ""))


def save_config(env):
    """Persist URL/user for continue; never write the password to disk."""
    if not env.get("CTF_URL") or not env.get("CTF_USER"):
        return
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps({
        "url": env["CTF_URL"].rstrip("/"),
        "user": env["CTF_USER"],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    CONFIG.chmod(0o600)


def prompt_connection(env, resume):
    """Interactive first-run wizard; resume reuses URL/user and asks only password."""
    load_saved_config(env)
    explicit_url = bool(os.environ.get("CTF_URL"))
    explicit_user = bool(os.environ.get("CTF_USER"))

    if not resume or not env.get("CTF_URL"):
        default = env.get("CTF_URL", "")
        suffix = f" [{default}]" if default else ""
        value = input(f"CTF 웹사이트 URL{suffix}: ").strip()
        env["CTF_URL"] = (value or default).rstrip("/")
    if not env.get("CTF_URL"):
        raise SystemExit("CTF 웹사이트 URL이 필요합니다.")
    if not env["CTF_URL"].startswith(("http://", "https://")):
        raise SystemExit("CTF 웹사이트 URL은 http:// 또는 https://로 시작해야 합니다.")

    if not resume or not env.get("CTF_USER"):
        default = env.get("CTF_USER", "")
        suffix = f" [{default}]" if default else ""
        value = input(f"CTF 아이디{suffix}: ").strip()
        env["CTF_USER"] = value or default
    if not env.get("CTF_USER"):
        raise SystemExit("CTF 아이디가 필요합니다.")

    if not env.get("CTF_PASSWORD"):
        env["CTF_PASSWORD"] = getpass.getpass("CTF 비밀번호 (화면에 표시되지 않음): ")
    if not env["CTF_PASSWORD"]:
        raise SystemExit("CTF 비밀번호가 필요합니다.")

    save_config(env)
    source = "저장된 설정" if resume and not (explicit_url or explicit_user) else "입력한 설정"
    print(f"[연결 설정 완료] {source} · {env['CTF_URL']} · {env['CTF_USER']}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--max-problems", type=int, default=0)
    ap.add_argument("--resume", action="store_true", help="Resume existing workspace without re-login or re-analysis")
    args = ap.parse_args()
    env = os.environ.copy()
    prompt_connection(env, args.resume)
    command = [PYTHON, str(SCRIPTS / "ctf_continue.py"), "--workers", str(args.workers)]
    if args.max_problems:
        command += ["--max-problems", str(args.max_problems)]
    if args.resume:
        command += ["--skip-inventory", "--status-poll"]
    log_dir = ROOT / "data/logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    # Password prompt remains visible on stderr; solver output is preserved in
    # the regular log while the dashboard owns the terminal display.
    # Keep the solver outside the UI's foreground process group.  The UI
    # receives Ctrl-C, then this parent explicitly tears down the whole tree.
    child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    monitor_failed = False
    try:
        textual = SCRIPTS / "ctf_textual.py"
        monitor = textual if textual.exists() else SCRIPTS / "ctf_monitor.py"
        monitor_python = str(CODE_ROOT / ".venv/bin/python") if (CODE_ROOT / ".venv/bin/python").exists() else PYTHON
        monitor_result = subprocess.run([monitor_python, str(monitor)], cwd=ROOT, env=env, check=False)
        monitor_failed = monitor_result.returncode != 0
        if monitor_failed and child.poll() is None:
            print(
                f"[UI 오류] 모니터가 비정상 종료되었습니다 (exit {monitor_result.returncode}). "
                "풀이 워커는 유지합니다. 로그를 확인한 뒤 UI만 다시 시작하세요.",
                flush=True,
            )
    except KeyboardInterrupt:
        stop_process_group(child)
    finally:
        if not monitor_failed:
            stop_process_group(child)
    if monitor_failed:
        print(f"풀이 프로세스 유지 중: {child.pid}", flush=True)
    else:
        print(f"풀이 프로세스 종료: {child.returncode}", flush=True)


if __name__ == "__main__":
    main()
