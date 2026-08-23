#!/usr/bin/env python3
"""Collect a CTFd challenge inventory without storing credentials or cookies."""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import argparse
from http.cookiejar import CookieJar
from pathlib import Path
from paths import WORKSPACE


BASE = os.environ.get("CTF_URL", "").rstrip("/")
USER = os.environ.get("CTF_USER")
PASSWORD = os.environ.get("CTF_PASSWORD")
OUT = WORKSPACE / "data/raw"
FILES = WORKSPACE / "data/files"


def request(opener, url, data=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "ctf-rapid-workbench/1.0"})
    with opener.open(req, timeout=25) as response:
        return response.status, response.geturl(), response.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--status-only", action="store_true", help="Only refresh solved_by_me status")
    args = ap.parse_args()
    if not all((BASE, USER, PASSWORD)):
        print("Set CTF_URL, CTF_USER and CTF_PASSWORD first.", file=sys.stderr)
        return 2

    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    status, login_url, html = request(opener, BASE + "/login")
    match = re.search(r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)', html.decode("utf-8", "replace"))
    fields = {"name": USER, "password": PASSWORD, "_submit": "Submit"}
    if match:
        fields["nonce"] = match.group(1)
    encoded = urllib.parse.urlencode(fields).encode()
    status, final_url, body = request(opener, BASE + "/login", encoded)
    if b"Your username or password is incorrect" in body or "/login" in final_url:
        print("Login failed; verify account, password, and event availability.", file=sys.stderr)
        return 1
    print(f"[로그인 확인] {BASE} 계정 인증 성공", flush=True)

    if args.status_only:
        try:
            code, _, raw = request(opener, BASE + "/api/v1/challenges")
            payload = json.loads(raw)
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
            print(f"Could not refresh solve status: {exc}", file=sys.stderr)
            return 1
        OUT.mkdir(parents=True, exist_ok=True)
        rows = [{"id": c.get("id"), "title": c.get("name"),
                 "solved_by_me": bool(c.get("solved_by_me"))}
                for c in payload.get("data", [])]
        (OUT / "server_status.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
        return 0

    print("[CTF 분석] 문제 목록·상세 페이지·첨부파일을 수집합니다.", flush=True)
    endpoints = {"challenges": BASE + "/api/v1/challenges"}
    OUT.mkdir(parents=True, exist_ok=True)
    for name, url in endpoints.items():
        try:
            code, final, raw = request(opener, url)
            payload = json.loads(raw)
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
            print(f"Could not collect {name}: {exc}", file=sys.stderr)
            return 1
        (OUT / f"{name}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        print(f"[수집 완료] {name} HTTP {code} -> {OUT / (name + '.json')}", flush=True)

    challenges = payload.get("data", []) if isinstance(payload, dict) else []
    details = []
    for challenge in challenges:
        cid = challenge.get("id")
        try:
            code, _, raw = request(opener, f"{BASE}/api/v1/challenges/{cid}")
            detail = json.loads(raw)
            details.append(detail.get("data", detail))
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError):
            details.append({"id": cid, "name": challenge.get("name"), "detail_error": True})
    (OUT / "challenge_details.json").write_text(json.dumps(details, indent=2, ensure_ascii=False) + "\n")
    downloaded = 0
    for detail in details:
        challenge_id = detail.get("id")
        challenge_files = detail.get("files") or []
        destination = FILES / str(challenge_id)
        destination.mkdir(parents=True, exist_ok=True)
        for file_url in challenge_files:
            relative = urllib.parse.urlsplit(file_url).path
            filename = Path(urllib.parse.unquote(relative)).name or f"file-{downloaded}"
            filename = "".join(ch for ch in filename if ch.isalnum() or ch in ".-_")
            target = destination / filename
            try:
                _, _, content = request(opener, urllib.parse.urljoin(BASE + "/", file_url))
                if not target.exists():
                    target.write_bytes(content)
                    downloaded += 1
            except (urllib.error.HTTPError, urllib.error.URLError):
                print(f"could not download challenge {challenge_id}: {filename}", file=sys.stderr)
    print(f"[첨부파일] 새로 받은 파일 {downloaded}개", flush=True)
    rows = []
    for c in challenges:
        rows.append({
            "title": c.get("name"), "id": c.get("id"), "category": c.get("category"), "name": c.get("name"),
            "value": c.get("value"), "solves": c.get("solves"),
            "ratio": round((c.get("solves", 0) or 0) / max(c.get("value", 1) or 1, 1), 3),
            "files": len(c.get("files", []) or []),
        })
    (OUT / "challenge_index.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(f"[문제 정리] 총 {len(rows)}개 문제", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
