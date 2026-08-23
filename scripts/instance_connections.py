#!/usr/bin/env python3
"""Parse declared CTF instance endpoints without widening the attack scope.

The portal has returned connection data in several shapes over time: a URL,
an ``ssh user@host -p port`` command, a host:port string, or a nested JSON
object.  This module normalises those shapes for the worker and keeps secrets
out of the context shown in the dashboard.
"""
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from paths import WORKSPACE


DETAILS = WORKSPACE / "data/raw/challenge_details.json"
INSTANCES = WORKSPACE / "data/raw/instances.json"

_HOST = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_IP = r"(?:\d{1,3}\.){3}\d{1,3}"
_SAFE_HOST = re.compile(rf"^(?:{_HOST}|{_IP})$")
_SSH_COMMAND = re.compile(
    r"\bssh\s+(?P<target>(?:[A-Za-z0-9_.-]+@)?(?:[A-Za-z0-9_.-]+|(?:\d{1,3}\.){3}\d{1,3}))"
    r"(?:\s+(?:-p|--port)\s+(?P<port>\d{1,5}))?",
    re.IGNORECASE,
)
_SSH_COMMAND_WITH_OPTIONS = re.compile(
    r"\bssh\s+(?:(?:-[A-Za-z][A-Za-z-]*)(?:\s+[^\s]+)?\s+)*"
    r"(?P<target>(?:[A-Za-z0-9_.-]+@)?(?:[A-Za-z0-9_.-]+|(?:\d{1,3}\.){3}\d{1,3}))"
    r"(?:\s+(?:-p|--port)\s+(?P<port>\d{1,5}))?",
    re.IGNORECASE,
)
_HOST_PORT = re.compile(
    rf"(?<![A-Za-z0-9_.-])(?P<host>{_HOST}|{_IP}):(?P<port>\d{{1,5}})(?!\d)"
)


def _valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _endpoint(protocol, host, port=None, user=None, source="declared"):
    host = str(host or "").strip().strip("[]")
    if not _SAFE_HOST.fullmatch(host):
        return None
    port = _valid_port(port)
    if protocol == "ssh":
        port = port or 22
    return {
        "protocol": protocol,
        "host": host,
        "port": port,
        "user": str(user).strip() if user else None,
        "source": source,
    }


def parse_endpoint(value, source="declared"):
    """Return one endpoint from a portal value, or ``None``.

    This deliberately accepts only explicit endpoint syntax.  It does not
    perform DNS, scan nearby ports, or infer alternate hosts.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None

    for command_pattern in (_SSH_COMMAND, _SSH_COMMAND_WITH_OPTIONS):
        match = command_pattern.search(text)
        if match:
            target = match.group("target")
            user, _, host = target.partition("@")
            port = match.group("port")
            if not port:
                port_match = re.search(r"(?:-p|--port)\s+(\d{1,5})", match.group(0))
                port = port_match.group(1) if port_match else None
            endpoint = _endpoint("ssh", host, port, user or None, source)
            if endpoint:
                return endpoint

    if text.lower().startswith(("ssh://", "http://", "https://")):
        parsed = urlsplit(text)
        protocol = parsed.scheme.lower()
        try:
            port = parsed.port
        except ValueError:
            return None
        if protocol == "ssh":
            return _endpoint("ssh", parsed.hostname, port, parsed.username, source)
        return _endpoint(protocol, parsed.hostname, port, parsed.username, source)

    match = _HOST_PORT.search(text)
    if match:
        return _endpoint("tcp", match.group("host"), match.group("port"), source=source)

    # A bare declared host is useful when the portal separately provides a
    # port or protocol.  Never treat arbitrary prose as a host.
    if _SAFE_HOST.fullmatch(text):
        return _endpoint("tcp", text, source=source)
    return None


def _walk_strings(value, key=""):
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for name, child in value.items():
            yield from _walk_strings(child, str(name).lower())
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child, key)


def _load_json(path):
    try:
        return json.loads(path.read_text(errors="replace")) if path.exists() else None
    except (OSError, ValueError):
        return None


def _challenge(challenge_id):
    data = _load_json(DETAILS) or []
    for item in data if isinstance(data, list) else []:
        if str(item.get("id")) == str(challenge_id):
            return item
    return {}


def _instance_record(challenge_id):
    data = _load_json(INSTANCES) or {}
    if isinstance(data, dict):
        item = data.get(str(challenge_id), data.get(challenge_id, {}))
        return item if isinstance(item, dict) else {"value": item}
    if isinstance(data, list):
        return next((x for x in data if str(x.get("id", x.get("challengeId"))) == str(challenge_id)), {})
    return {}


def declared_endpoints(challenge_id):
    """Collect unique endpoints declared by challenge details/instance data."""
    challenge = _challenge(challenge_id)
    record = _instance_record(challenge_id)
    candidates = []
    for key, value in _walk_strings(challenge):
        if key in {"connection_info", "connectioninfo", "connection", "ssh", "sshcommand", "command", "host", "endpoint", "url"}:
            candidates.append((value, f"challenge.{key}"))
    for key, value in _walk_strings(record):
        if key in {"connection_info", "connectioninfo", "connection", "ssh", "sshcommand", "command", "host", "endpoint", "url", "ip"}:
            candidates.append((value, f"instance.{key}"))
    # A full response can also contain a command nested under an unlabelled
    # string.  Parse only strings that actually contain explicit syntax.
    for key, value in _walk_strings(record):
        if "ssh " in value.lower() or re.search(r"https?://|:\d{2,5}\b", value):
            candidates.append((value, f"instance.{key or 'value'}"))

    found = []
    seen = set()
    for value, source in candidates:
        endpoint = parse_endpoint(value, source)
        if not endpoint:
            continue
        identity = tuple(endpoint.get(k) for k in ("protocol", "host", "port", "user"))
        if identity not in seen:
            seen.add(identity)
            found.append(endpoint)
    return found


def _redact_value(text):
    text = re.sub(r"(?i)(password|passwd|pass|token|secret|authorization)(\s*[=:]\s+)[^\s,;]+", r"\1\2***", str(text))
    text = re.sub(r"(?i)(-p\s+)([^\s]+)", r"\1***", text)
    return text


def safe_connection_context(challenge_id):
    """Build worker context with exact endpoints and no secret fields."""
    endpoints = declared_endpoints(challenge_id)
    if not endpoints:
        return "No declared instance endpoint is currently available. Do not guess or scan; report an infrastructure blocker and let the queue retry."
    lines = ["Declared connection endpoints (use only these exact endpoints):"]
    for item in endpoints:
        target = f"{item['user']}@" if item.get("user") else ""
        target += item["host"]
        if item.get("port"):
            target += f":{item['port']}"
        lines.append(f"- protocol={item['protocol']} target={target} source={item['source']}")
    lines.append("For SSH, use only the declared user/host/port. Never scan alternate hosts or ports.")
    return "\n".join(_redact_value(line) for line in lines)


def endpoint_for_ssh(challenge_id):
    return next((x for x in declared_endpoints(challenge_id) if x["protocol"] == "ssh"), None)


def connection_secret(challenge_id):
    """Return an explicitly supplied instance password, if one exists.

    The value is used only in memory by the SSH helper and is never included
    in the worker context, event stream, or generated writeups.
    """
    challenge = _challenge(challenge_id)
    record = _instance_record(challenge_id)
    for key, value in _walk_strings(record):
        if key in {"password", "passwd", "ssh_password", "secret"} and value.strip():
            return value.strip()
    description = str(challenge.get("description") or "")
    patterns = (
        r"password\s*(?:(?:is|:)\s*)?[`'\"]([^`'\"\s]+)[`'\"]",
        r"password\s+(?:is\s+)?([A-Za-z0-9_.:@%+/-]{3,})",
    )
    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            return match.group(1).strip().rstrip(".,")
    return None


def endpoint_hosts(challenge_id, schemes=("http", "https")):
    return {
        f"{item['host']}:{item['port']}" if item.get("port") else item["host"]
        for item in declared_endpoints(challenge_id)
        if item["protocol"] in schemes
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("challenge_id", type=int)
    args = parser.parse_args()
    print(safe_connection_context(args.challenge_id))
