#!/usr/bin/env python3
"""Run a production-host canary without touching the live Xray configuration."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any


def command(args: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def live_user_audit(
    xray: Path,
    api_port: int,
    inbound_tag: str,
    expected_emails: set[str],
) -> dict[str, Any]:
    """Prove the one-process/two-pass command without retaining identities."""

    result = command(
        [
            str(xray),
            "api",
            "vpnbot-audit-users",
            f"--server=127.0.0.1:{api_port}",
            "-timeout=10",
        ],
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError("Xray single-connection live user audit failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Xray single-connection live user audit returned invalid JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("contract") != "vpnbot-live-user-audit-v1"
        or payload.get("snapshot_passes") != 2
        or not isinstance(payload.get("passes"), list)
        or len(payload["passes"]) != 2
    ):
        raise RuntimeError("Xray single-connection live user audit contract is invalid")
    normalized_passes: list[list[tuple[str, bool, int, tuple[str, ...]]]] = []
    for snapshot in payload["passes"]:
        inbounds = snapshot.get("inbounds") if isinstance(snapshot, dict) else None
        if not isinstance(inbounds, list):
            raise RuntimeError("Xray live user audit omitted inbounds")
        normalized: list[tuple[str, bool, int, tuple[str, ...]]] = []
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                raise RuntimeError("Xray live user audit returned a malformed inbound")
            users = inbound.get("users")
            count = inbound.get("count")
            user_manager = inbound.get("user_manager")
            if (
                not isinstance(users, list)
                or not all(isinstance(user, dict) for user in users)
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count != len(users)
                or not isinstance(user_manager, bool)
            ):
                raise RuntimeError("Xray live user audit returned invalid user evidence")
            emails = tuple(sorted(str(user.get("email") or "").lower() for user in users))
            normalized.append(
                (str(inbound.get("tag") or ""), user_manager, count, emails)
            )
        normalized_passes.append(sorted(normalized))
    if normalized_passes[0] != normalized_passes[1]:
        raise RuntimeError("Xray live user registry changed between audit passes")
    matching = [row for row in normalized_passes[0] if row[0] == inbound_tag]
    if len(matching) != 1 or not matching[0][1]:
        raise RuntimeError("Xray canary inbound is not auditable")
    observed_emails = set(matching[0][3])
    if observed_emails != {email.lower() for email in expected_emails}:
        raise RuntimeError("Xray canary live user set does not match expectation")
    return {
        "snapshot_passes": 2,
        "audited_inbound_count": len(normalized_passes[0]),
        "expected_user_count": len(expected_emails),
        "process_count": 1,
        "grpc_connection_count": 1,
    }


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[str], *, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise RuntimeError(
                f"Xray process exited early ({process.returncode}): "
                f"{(stderr or '').strip() or (stdout or '').strip() or '<see process log>'}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Xray did not listen on loopback port {port}")


class EchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.5)
        self.port = int(self.listener.getsockname()[1])
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)

    def start(self) -> None:
        self.accept_thread.start()

    def _accept(self) -> None:
        while not self.stop_event.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._echo, args=(connection,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def _echo(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(0.5)
            while not self.stop_event.is_set():
                try:
                    data = connection.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not data:
                    return
                try:
                    connection.sendall(data)
                except OSError:
                    return

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.accept_thread.join(timeout=2)
        for thread in self.threads:
            thread.join(timeout=2)


class StreamWorker:
    def __init__(self, port: int) -> None:
        self.port = port
        self.stop_event = threading.Event()
        self.closed_event = threading.Event()
        self.bytes_echoed = 0
        self.error = ""
        self.socket: socket.socket | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        payload = os.urandom(16 * 1024)
        try:
            connection = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            self.socket = connection
            connection.settimeout(2)
            while not self.stop_event.is_set():
                connection.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = connection.recv(len(payload) - len(received))
                    if not chunk:
                        raise ConnectionError("stream closed")
                    received.extend(chunk)
                if bytes(received) != payload:
                    raise RuntimeError("echo payload mismatch")
                self.bytes_echoed += len(payload)
        except Exception as exc:  # the revoked stream is expected to arrive here
            self.error = f"{type(exc).__name__}: {exc}"
            self.closed_event.set()
        finally:
            if self.socket is not None:
                try:
                    self.socket.close()
                except OSError:
                    pass

    def close(self) -> None:
        self.stop_event.set()
        if self.socket is not None:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(timeout=3)


def wait_for_bytes(worker: StreamWorker, minimum: int, *, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if worker.bytes_echoed >= minimum:
            return
        if worker.closed_event.is_set():
            raise RuntimeError(f"test stream closed before reaching {minimum} bytes: {worker.error}")
        time.sleep(0.05)
    raise RuntimeError(f"test stream did not reach {minimum} bytes; got {worker.bytes_echoed}")


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def isolated_active_revoke(xray: Path, cutoff_seconds: float) -> dict[str, Any]:
    echo = EchoServer()
    echo.start()
    server_port = unused_port()
    api_port = unused_port()
    client_a_port = unused_port()
    client_b_port = unused_port()
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    email_a = f"vpnbot-canary-a-{uuid.uuid4().hex}@invalid"
    email_b = f"vpnbot-canary-b-{uuid.uuid4().hex}@invalid"
    inbound_tag = "vpnbot-canary-vless"
    server_process: subprocess.Popen[str] | None = None
    client_process: subprocess.Popen[str] | None = None
    stream_a: StreamWorker | None = None
    stream_b: StreamWorker | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="vpnbot-xray-canary-") as raw_tmp:
            temporary = Path(raw_tmp)
            server_config = {
                "log": {"loglevel": "warning"},
                "api": {"tag": "api", "services": ["HandlerService"]},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": server_port,
                        "protocol": "vless",
                        "tag": inbound_tag,
                        "settings": {
                            "decryption": "none",
                            "clients": [
                                {"id": user_a, "email": email_a},
                                {"id": user_b, "email": email_b},
                            ],
                        },
                        "streamSettings": {"network": "tcp", "security": "none"},
                    },
                    {
                        "listen": "127.0.0.1",
                        "port": api_port,
                        "protocol": "dokodemo-door",
                        "tag": "api",
                        "settings": {"address": "127.0.0.1"},
                    },
                ],
                "outbounds": [
                    {
                        "protocol": "freedom",
                        "tag": "direct",
                        "settings": {
                            "finalRules": [{"action": "allow", "network": "tcp,udp"}]
                        },
                    }
                ],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
                    ]
                },
            }
            client_config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": client_a_port,
                        "protocol": "dokodemo-door",
                        "tag": "client-a",
                        "settings": {
                            "address": "127.0.0.1",
                            "port": echo.port,
                            "network": "tcp",
                        },
                    },
                    {
                        "listen": "127.0.0.1",
                        "port": client_b_port,
                        "protocol": "dokodemo-door",
                        "tag": "client-b",
                        "settings": {
                            "address": "127.0.0.1",
                            "port": echo.port,
                            "network": "tcp",
                        },
                    },
                ],
                "outbounds": [
                    {
                        "protocol": "vless",
                        "tag": "out-a",
                        "settings": {
                            "vnext": [
                                {
                                    "address": "127.0.0.1",
                                    "port": server_port,
                                    "users": [{"id": user_a, "encryption": "none"}],
                                }
                            ]
                        },
                        "streamSettings": {"network": "tcp", "security": "none"},
                    },
                    {
                        "protocol": "vless",
                        "tag": "out-b",
                        "settings": {
                            "vnext": [
                                {
                                    "address": "127.0.0.1",
                                    "port": server_port,
                                    "users": [{"id": user_b, "encryption": "none"}],
                                }
                            ]
                        },
                        "streamSettings": {"network": "tcp", "security": "none"},
                    },
                ],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["client-a"], "outboundTag": "out-a"},
                        {"type": "field", "inboundTag": ["client-b"], "outboundTag": "out-b"},
                    ]
                },
            }
            server_path = temporary / "server.json"
            client_path = temporary / "client.json"
            server_log_path = temporary / "server.log"
            client_log_path = temporary / "client.log"
            write_json(server_path, server_config)
            write_json(client_path, client_config)
            with server_log_path.open("w", encoding="utf-8") as server_log, client_log_path.open(
                "w", encoding="utf-8"
            ) as client_log:
                try:
                    server_process = subprocess.Popen(
                        [str(xray), "run", "-config", str(server_path)],
                        text=True,
                        stdout=server_log,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    wait_for_port(server_port, server_process)
                    wait_for_port(api_port, server_process)
                    client_process = subprocess.Popen(
                        [str(xray), "run", "-config", str(client_path)],
                        text=True,
                        stdout=client_log,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    wait_for_port(client_a_port, client_process)
                    wait_for_port(client_b_port, client_process)

                    stream_a = StreamWorker(client_a_port)
                    stream_b = StreamWorker(client_b_port)
                    stream_a.start()
                    stream_b.start()
                    wait_for_bytes(stream_a, 512 * 1024, timeout=4)
                    wait_for_bytes(stream_b, 512 * 1024, timeout=4)
                    audit_before = live_user_audit(
                        xray,
                        api_port,
                        inbound_tag,
                        {email_a, email_b},
                    )
                    b_before = stream_b.bytes_echoed
                    revoke_started = time.monotonic()
                    removed = command(
                        [
                            str(xray),
                            "api",
                            "rmu",
                            f"--server=127.0.0.1:{api_port}",
                            f"-tag={inbound_tag}",
                            email_a,
                        ],
                        timeout=10,
                    )
                    if removed.returncode != 0:
                        raise RuntimeError(
                            "Xray RemoveUser API failed: "
                            + (removed.stderr.strip() or removed.stdout.strip() or str(removed.returncode))
                        )
                    audit_after = live_user_audit(
                        xray,
                        api_port,
                        inbound_tag,
                        {email_b},
                    )
                    if not stream_a.closed_event.wait(timeout=cutoff_seconds):
                        raise RuntimeError(
                            f"revoked stream A stayed alive longer than {cutoff_seconds:.1f} seconds"
                        )
                    cutoff = time.monotonic() - revoke_started
                    wait_for_bytes(stream_b, b_before + 512 * 1024, timeout=4)
                    if stream_b.closed_event.is_set():
                        raise RuntimeError(f"unrelated stream B was closed: {stream_b.error}")
                    if server_process.poll() is not None:
                        raise RuntimeError("isolated Xray server exited during the test")
                    if client_process.poll() is not None:
                        raise RuntimeError("isolated Xray client exited during the test")
                    return {
                        "cutoff_seconds": round(cutoff, 3),
                        "stream_a_bytes": stream_a.bytes_echoed,
                        "stream_b_bytes": stream_b.bytes_echoed,
                        "live_configuration_untouched": True,
                        "live_user_audit_before": audit_before,
                        "live_user_audit_after": audit_after,
                    }
                except Exception as exc:
                    stop_process(client_process)
                    stop_process(server_process)
                    server_log.flush()
                    client_log.flush()
                    server_tail = server_log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                    client_tail = client_log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                    raise RuntimeError(
                        f"{exc}; server_log={server_tail!r}; client_log={client_tail!r}"
                    ) from exc
    finally:
        if stream_a is not None:
            stream_a.close()
        if stream_b is not None:
            stream_b.close()
        stop_process(client_process)
        stop_process(server_process)
        echo.close()


def run(args: argparse.Namespace) -> dict[str, Any]:
    xray = args.xray.resolve()
    if not xray.is_file() or not os.access(xray, os.X_OK):
        raise RuntimeError(f"Xray binary is unavailable: {xray}")
    active = command(["systemctl", "is-active", args.service], timeout=15)
    if active.returncode != 0 or active.stdout.strip() != "active":
        raise RuntimeError(f"{args.service} is not active")
    version = command([str(xray), "version"], timeout=15)
    statement = (version.stdout or "").strip()
    if version.returncode != 0:
        raise RuntimeError(version.stderr.strip() or "xray version failed")
    if args.expected_tag not in statement:
        raise RuntimeError(f"installed Xray does not report expected tag {args.expected_tag}")
    if args.capability not in statement:
        raise RuntimeError(f"installed Xray lacks capability {args.capability}")
    if args.live_audit_capability not in statement:
        raise RuntimeError(
            f"installed Xray lacks capability {args.live_audit_capability}"
        )
    config = command(
        [str(xray), "run", "-confdir", str(args.config_dir), "-dump"],
        timeout=45,
    )
    if config.returncode != 0:
        raise RuntimeError(
            "installed Xray rejected the live config: "
            + (config.stderr.strip() or config.stdout.strip() or str(config.returncode))
        )
    revoke = isolated_active_revoke(xray, args.cutoff_seconds)
    active_after = command(["systemctl", "is-active", args.service], timeout=15)
    if active_after.returncode != 0 or active_after.stdout.strip() != "active":
        raise RuntimeError(f"{args.service} stopped during the isolated canary")
    return {
        "schema_version": 1,
        "result": "passed",
        "installed_version_statement": statement,
        "checks": {
            "service_active": True,
            "expected_version": True,
            "required_capability": True,
            "single_connection_live_user_audit": True,
            "live_config_valid": True,
            "isolated_active_revoke": True,
            "unrelated_stream_survived": True,
            "service_still_active": True,
        },
        "active_revoke": revoke,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", type=Path, default=Path("/opt/vpnbot/xray-core/bin/xray"))
    parser.add_argument("--config-dir", type=Path, default=Path("/opt/vpnbot/xray-core/config"))
    parser.add_argument("--service", default="vpnbot-xray.service")
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--capability", default="vpnbot-active-revoke-v3")
    parser.add_argument(
        "--live-audit-capability",
        default="vpnbot-live-user-audit-v1",
    )
    parser.add_argument("--cutoff-seconds", type=float, default=10.0)
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "result": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
