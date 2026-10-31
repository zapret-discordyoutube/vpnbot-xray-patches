#!/usr/bin/env python3
"""Fail when a built Xray listens with MPTCP (CVE-2026-98432 regression guard).

CVE-2026-98432 (Linux IPv4 TCP request-socket use-after-free) was exploited
remotely through an MPTCP listener, and Go 1.24+ listens with MPTCP by
default.  Xray-core v26.10.31 turned MPTCP off by default (XTLS/Xray-core#7291);
a later upstream release or patch that turns it back on must not reach the
fleet.  This check starts the built binary with one loopback inbound and asks
the kernel (``ss -M``) whether that port is an MPTCP listener.

The check runs in a network namespace of its own (``unshare -rn``): there
``net.mptcp.enabled`` starts at its kernel default (1) whatever the host or
the CI container set, so the verdict is about the binary, not the machine.
A positive control comes first: a Python MPTCP listener must be visible to
``ss -M``.  Without kernel MPTCP support the check cannot tell anything and
fails closed, instead of passing vacuously.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IPPROTO_MPTCP = 262


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def listeners(mptcp: bool) -> set[int]:
    argv = ["ss", "-H", "-l", "-n"] + (["-M"] if mptcp else ["-t"])
    output = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=True).stdout
    ports = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1].isdigit():
            ports.add(int(fields[3].rsplit(":", 1)[-1]))
    return ports


def positive_control() -> None:
    try:
        control = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
    except OSError as exc:
        raise SystemExit(f"check_no_mptcp_listener: the kernel offers no MPTCP socket ({exc}); cannot judge")
    with control:
        control.bind(("127.0.0.1", 0))
        control.listen(1)
        port = control.getsockname()[1]
        if port not in listeners(mptcp=True):
            raise SystemExit("check_no_mptcp_listener: ss -M does not show a known MPTCP listener; cannot judge")


def enter_own_network_namespace(argv: list[str]) -> None:
    """Re-run this script inside a fresh user+network namespace with loopback up."""

    if os.environ.get("VPNBOT_MPTCP_CHECK_NETNS") == "1":
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=15)
        return
    environment = {**os.environ, "VPNBOT_MPTCP_CHECK_NETNS": "1"}
    completed = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable, "-I", *argv],
                               env=environment, check=False)
    raise SystemExit(completed.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xray", type=Path)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    enter_own_network_namespace([str(Path(__file__).resolve()), str(args.xray.resolve()), "--timeout", str(args.timeout)])
    positive_control()
    port = free_port()
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 9, "network": "tcp"}}],
        "outbounds": [{"protocol": "freedom"}],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen([str(args.xray), "run", "-c", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + args.timeout
            while port not in listeners(mptcp=False) and port not in listeners(mptcp=True):
                if process.poll() is not None or time.monotonic() > deadline:
                    stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
                    raise SystemExit(f"check_no_mptcp_listener: Xray did not listen on {port}: {stderr[-500:]}")
                time.sleep(0.2)
            if port in listeners(mptcp=True):
                print(f"check_no_mptcp_listener: FAILED — Xray listens with MPTCP on 127.0.0.1:{port}", file=sys.stderr)
                return 1
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    print(f"check_no_mptcp_listener: passed — Xray listens with plain TCP on 127.0.0.1:{port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
