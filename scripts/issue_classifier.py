#!/usr/bin/env python3
"""Classify blockers that need a person or a different recovery path."""
import re


def classify_issue(*parts):
    text = " ".join(str(part or "") for part in parts).lower()

    if any(term in text for term in (
        "possible cybersecurity risk",
        "trusted access",
        "content was flagged",
    )):
        return {
            "kind": "policy_blocked",
            "label": "모델 정책 차단",
            "action": "프롬프트를 더 좁히거나 Trusted Access가 있는 세션에서 수동 판단",
        }

    # Discord, CAPTCHA, MFA and browser-only gates cannot be completed by a
    # headless worker without the user's account/session or a human gesture.
    discord_gate = "discord" in text and any(term in text for term in (
        "unauthenticated", "unauthorized", "channel/message", "channel and message",
        "must join", "join the server", "server content unavailable",
        "cannot access", "could not access", "requires an authenticated",
    ))
    browser_gate = any(term in text for term in (
        "captcha", "recaptcha", "two-factor", "2fa", "mfa", "qr code",
        "browser login", "human verification", "manual login", "requires a human",
    ))
    if discord_gate:
        return {
            "kind": "manual_required",
            "label": "수동 필요 · Discord/브라우저",
            "action": "브라우저에서 Discord 로그인·서버 참여 후 ctf continue",
        }
    if browser_gate:
        return {
            "kind": "manual_required",
            "label": "수동 필요 · CAPTCHA/MFA",
            "action": "브라우저에서 인증을 완료한 뒤 ctf continue",
        }

    if any(term in text for term in (
        "mana used", "quota", "no instance is running", "instance state",
        "launch request", "target host", "connection info",
    )) and any(term in text for term in ("403", "empty", "unavailable", "none", "no ")):
        return {
            "kind": "infrastructure",
            "label": "인프라 오류 · 인스턴스/쿼터",
            "action": "인스턴스·쿼터 상태를 확인하고 잠시 후 재시도",
        }

    if re.search(r"\b(?:http|status|error)\s*4(?:0[13]|29)\b|\b403\b|forbidden|unauthorized", text):
        return {
            "kind": "access_error",
            "label": "접근 오류 · HTTP/권한",
            "action": "허가된 세션·토큰·호스트를 확인한 뒤 재시도",
        }
    if any(term in text for term in (
        "timed out", "timeout", "connection reset", "connection refused",
        "temporary failure", "name resolution", "network is unreachable",
        "failed to refresh available models",
    )):
        return {
            "kind": "network",
            "label": "네트워크 오류",
            "action": "잠시 후 동일 문제를 자동 재시도",
        }
    if any(term in text for term in ("traceback", "exec_command failed", "no such file", "broken pipe")):
        return {
            "kind": "tool_error",
            "label": "도구/실행 오류",
            "action": "실행 환경을 정리하고 다른 전략으로 재시도",
        }
    return {"kind": "none", "label": "", "action": ""}


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(classify_issue(*sys.argv[1:]), ensure_ascii=False))
