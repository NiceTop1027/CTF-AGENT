#!/usr/bin/env python3
"""Execute a command on one declared CTF SSH instance.

This helper exists so a headless Codex worker can use a challenge-provided
password without putting that password in argv, shell history, or dashboard
events.  It is intentionally scoped to the exact endpoint in the workspace's
challenge/instance data.
"""
import argparse
import sys

from instance_connections import connection_secret, endpoint_for_ssh


def main():
    parser = argparse.ArgumentParser(description="Run a command on the declared CTF SSH instance")
    parser.add_argument("challenge_id", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="remote command after --")
    args = parser.parse_args()
    endpoint = endpoint_for_ssh(args.challenge_id)
    if not endpoint:
        print("instance endpoint missing", file=sys.stderr)
        return 75
    command = " ".join(args.command).strip()
    if not command:
        command = "true"
    target = f"{endpoint['user']}@{endpoint['host']}" if endpoint.get("user") else endpoint["host"]
    password = connection_secret(args.challenge_id)

    try:
        import pexpect
    except ImportError:
        print("pexpect is required for password-authenticated CTF SSH instances", file=sys.stderr)
        return 69

    ssh_args = [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
        "-p", str(endpoint["port"] or 22),
        target,
        command,
    ]
    child = pexpect.spawn("ssh", ssh_args, encoding="utf-8", timeout=30)
    # logfile_read mirrors remote output but never echoes the password sent
    # to the child process.
    child.logfile_read = sys.stdout
    sent_password = False
    try:
        while True:
            index = child.expect([
                r"(?i)are you sure you want to continue connecting \(yes/no(?:/\[fingerprint\])?\)\?",
                r"(?i)(?:password|passphrase):\s*",
                pexpect.EOF,
                pexpect.TIMEOUT,
            ])
            if index == 0:
                child.sendline("yes")
            elif index == 1:
                if sent_password or not password:
                    print("SSH password unavailable or requested more than once", file=sys.stderr)
                    child.close(force=True)
                    return 77
                child.sendline(password)
                sent_password = True
            elif index == 2:
                break
            else:
                print("SSH connection timed out", file=sys.stderr)
                child.close(force=True)
                return 124
        child.close()
        return child.exitstatus if child.exitstatus is not None else (128 + (child.signalstatus or 0))
    finally:
        if child.isalive():
            child.close(force=True)


if __name__ == "__main__":
    raise SystemExit(main())
