#!/usr/bin/env python3
"""Manage authorized CTFd-Chall-Manager player instances."""
import argparse, getpass, json, os, re, urllib.error, urllib.parse, urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from paths import WORKSPACE

BASE = os.environ.get("CTF_URL", "").rstrip("/")
USER = os.environ.get("CTF_USER")
PASSWORD = os.environ.get("CTF_PASSWORD")
ROOT = WORKSPACE
OUT = ROOT / "data/raw/instances.json"
API = BASE + "/api/v1/plugins/ctfd-chall-manager/instance"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", nargs="*", type=int)
    ap.add_argument("--destroy", action="store_true")
    args = ap.parse_args()
    password = PASSWORD or getpass.getpass("CTF password (instance manager): ")
    if not all((BASE, USER, password)):
        raise SystemExit("CTF_URL, CTF_USER and CTF_PASSWORD are required")
    details = json.loads((ROOT / "data/raw/challenge_details.json").read_text())
    targets = [x for x in details if x.get("type") == "dynamic_iac" and (not args.ids or x.get("id") in args.ids)]
    jar = CookieJar(); opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def request(method, url, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"User-Agent": "NiceTop-CTF-Autopilot/1.0", "Accept": "application/json"}
        if data: headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with opener.open(req, timeout=30) as r: return r.status, json.loads(r.read() or b"{}")
    html = opener.open(BASE + "/login", timeout=30).read().decode("utf8", "replace")
    nonce = re.search(r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)', html)
    fields = {"name": USER, "password": password, "_submit": "Submit"}
    if nonce: fields["nonce"] = nonce.group(1)
    login = urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode(fields).encode(), headers={"User-Agent":"NiceTop-CTF-Autopilot/1.0"})
    with opener.open(login, timeout=30) as r: final = r.geturl()
    if final.endswith("/login"): raise SystemExit("CTF login failed")
    result = json.loads(OUT.read_text()) if OUT.exists() else {}
    for challenge in targets:
        cid = challenge["id"]
        try:
            if args.destroy:
                code, data = request("DELETE", API, {"challengeId": cid}); result.pop(str(cid), None)
            else:
                try: code, data = request("GET", API + "?challengeId=" + str(cid))
                except urllib.error.HTTPError as e:
                    if e.code != 404: raise
                    code, data = request("POST", API, {"challengeId": cid})
                result[str(cid)] = {"title": challenge.get("name"), **data.get("data", {})}
            print(f"[인스턴스] {challenge.get('name')}: HTTP {code}", flush=True)
        except Exception as exc:
            print(f"[인스턴스 실패] {challenge.get('name')}: {exc}", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True); OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")

if __name__ == "__main__": main()
