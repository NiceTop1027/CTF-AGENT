#!/usr/bin/env python3
"""Token-aware HTTP helper restricted to hosts declared by a challenge."""
import argparse
import json
import os
import re
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from paths import WORKSPACE

ROOT = WORKSPACE
DETAILS = ROOT / "data" / "raw" / "challenge_details.json"


def challenge_hosts(challenge_id):
    details = json.loads(DETAILS.read_text())
    for c in details:
        if c.get("id") == challenge_id:
            text = (c.get("connection_info") or "") + " " + (c.get("description") or "")
            return {urllib.parse.urlsplit(x).netloc for x in re.findall(r"https?://[^\s<>\"']+", text) if urllib.parse.urlsplit(x).netloc}
    return set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("challenge_id", type=int)
    ap.add_argument("url", help="Full URL; its host must be listed by the challenge")
    ap.add_argument("--method", choices=("GET", "POST"), default="GET")
    ap.add_argument("--token-env", help="Environment variable containing the CTF token")
    ap.add_argument("--token-header", default="Authorization")
    ap.add_argument("--token-field", help="Put the token in a form field instead of a header")
    ap.add_argument("--data", action="append", default=[], help="POST form key=value; repeatable")
    args = ap.parse_args()
    parsed = urllib.parse.urlsplit(args.url)
    allowed = challenge_hosts(args.challenge_id)
    if parsed.scheme != "https" or parsed.netloc not in allowed:
        raise SystemExit(f"Blocked host. Allowed HTTPS hosts for challenge: {sorted(allowed)}")
    token = os.environ.get(args.token_env) if args.token_env else None
    form = dict(item.split("=", 1) for item in args.data if "=" in item)
    headers = {"User-Agent": "ctf-rapid-workbench/1.0"}
    if token and args.token_field:
        form[args.token_field] = token
    elif token:
        headers[args.token_header] = token
    body = urllib.parse.urlencode(form).encode() if args.method == "POST" else None
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    req = urllib.request.Request(args.url, data=body, headers=headers, method=args.method)
    with opener.open(req, timeout=20) as response:
        content = response.read(20000).decode("utf-8", "replace")
        print(json.dumps({"status": response.status, "url": response.geturl(), "content_type": response.headers.get("content-type"), "body": content}, ensure_ascii=False))


if __name__ == "__main__":
    main()
