#!/usr/bin/env python3
"""Notify the VPnBot operator when the Xray release train stops safely."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import fcntl
import html
import http.client
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True
import release_pipeline


STATE_SCHEMA_VERSION = 1
FAILED_WORKFLOW_STATES = {"cancelled", "error", "failed", "failure", "timed_out"}
PENDING_WORKFLOW_STATES = {
    "blocked",
    "created",
    "pending",
    "queued",
    "running",
    "waiting",
}
PROMOTER_PENDING_PHASES = {"installing", "installed", "pilot_passed", "promoted"}
PROMOTER_FAILED_PHASES = {"failed_rolled_back", "failed_rollback_failed"}
CONDITION_NAMES = ("patch_pipeline", "candidate_stalled", "canary_failed")
ALERT_ENV_NAMES = {
    "VPNBOT_XRAY_ALERT_ACTIONS_URL",
    "VPNBOT_XRAY_ALERT_RELEASES_URL",
    "VPNBOT_XRAY_ALERT_WORKFLOW_ID",
    "VPNBOT_XRAY_ALERT_BOT_ENV_FILE",
    "VPNBOT_XRAY_ALERT_CHAT_ID",
    "VPNBOT_XRAY_ALERT_PROMOTER_STATE_DIR",
    "VPNBOT_XRAY_ALERT_STATE_DIR",
    "VPNBOT_XRAY_ALERT_STALL_SECONDS",
    "VPNBOT_XRAY_ALERT_REMINDER_SECONDS",
    "VPNBOT_XRAY_ALERT_RETRY_SECONDS",
    "VPNBOT_XRAY_ALERT_REQUEST_TIMEOUT_SECONDS",
}

# Telegram egress contract of the VPnBot host.  Every process that owns the bot
# must reach Telegram through the same endpoint policy (VPnBot
# ``deployment/service_env_profiles.py`` ``_BOT_IDENTITY``,
# ``telegram_client.py``, ``telegram_egress.py``): the production uplink has no
# IPv6 route and black-holes some Telegram IPv4 addresses, so a plain
# ``urlopen`` spends its whole timeout on a dead address and then fails with
# ENETUNREACH on IPv6.  The contract is read from the bot's own runtime env and
# the node manager's relay projection, never copied into this repository.
TELEGRAM_API_HOST = "api.telegram.org"
TELEGRAM_API_PORT = 443
TELEGRAM_IP_FAMILY_KEY = "VPNBOT_TELEGRAM_IP_FAMILY"
TELEGRAM_FALLBACK_IPV4S_KEY = "VPNBOT_TELEGRAM_API_FALLBACK_IPV4S"
TELEGRAM_EGRESS_HEALTH_PATH_KEY = "VPNBOT_TELEGRAM_EGRESS_HEALTH_PATH"
BOT_TOKEN_KEY = "VPNBOT_BOT_TOKEN"
BOT_RUNTIME_KEYS = (
    BOT_TOKEN_KEY,
    TELEGRAM_IP_FAMILY_KEY,
    TELEGRAM_FALLBACK_IPV4S_KEY,
    TELEGRAM_EGRESS_HEALTH_PATH_KEY,
)
DEFAULT_TELEGRAM_EGRESS_HEALTH_PATH = Path(
    "/run/vpnbot-node-manager/telegram-egress.json"
)
# Same freshness bound as the bot (``TELEGRAM_RELAY_HEALTH_STALE_SECONDS``):
# a projection whose writer stopped ticking is not evidence of a healthy relay.
TELEGRAM_RELAY_HEALTH_STALE_SECONDS = 45.0
TELEGRAM_RESPONSE_LIMIT_BYTES = 1024 * 1024

# Typed delivery failure codes.  ``telegram_connect_failed`` and
# ``telegram_no_route`` guarantee that no request byte reached Telegram;
# ``telegram_delivery_ambiguous`` means the request was sent and Telegram may
# have accepted it, so it is never retried on another address in the same run.
TELEGRAM_EGRESS_CONFIG_INVALID = "telegram_egress_config_invalid"
TELEGRAM_NO_ROUTE = "telegram_no_route"
TELEGRAM_CONNECT_FAILED = "telegram_connect_failed"
TELEGRAM_DELIVERY_AMBIGUOUS = "telegram_delivery_ambiguous"
TELEGRAM_HTTP_STATUS = "telegram_http_status"
TELEGRAM_RESPONSE_INVALID = "telegram_response_invalid"
TELEGRAM_REJECTED = "telegram_rejected"


class TelegramDeliveryError(release_pipeline.PipelineError):
    """Telegram delivery failed with one typed, secret-free code."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


@dataclasses.dataclass(frozen=True)
class BotRuntime:
    """The bot identity and Telegram endpoint policy from the bot runtime env."""

    token: str
    ip_family: socket.AddressFamily
    fallback_ipv4s: tuple[str, ...]
    egress_health_path: Path


@dataclasses.dataclass(frozen=True)
class TelegramRoute:
    """One TCP destination for ``api.telegram.org``; TLS still verifies the host."""

    kind: str
    address: str
    port: int
    family: socket.AddressFamily

    def label(self) -> str:
        return f"{self.kind} {self.address}:{self.port}"


@dataclasses.dataclass(frozen=True)
class Settings:
    actions_url: str
    releases_url: str
    workflow_id: str
    bot_env_file: Path
    chat_id: str
    promoter_state_dir: Path
    state_dir: Path
    stall_seconds: int
    reminder_seconds: int
    retry_seconds: int
    request_timeout_seconds: int


@dataclasses.dataclass(frozen=True)
class Candidate:
    tag: str
    proven_tag: str
    published_epoch: int
    release_url: str


@dataclasses.dataclass(frozen=True)
class Condition:
    name: str
    status: str
    signature: str = ""
    headline: str = ""
    detail: str = ""
    action: str = ""
    url: str = ""
    severity: str = "warning"


def env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default)).strip()


def positive_seconds(name: str, default: int, minimum: int) -> int:
    raw = env(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise release_pipeline.PipelineError(f"{name} must be an integer") from exc
    if value < minimum:
        raise release_pipeline.PipelineError(f"{name} must be at least {minimum}")
    return value


def load_settings() -> Settings:
    settings = Settings(
        actions_url=env(
            "VPNBOT_XRAY_ALERT_ACTIONS_URL",
            "https://git.zapret.moe/api/v1/repos/"
            "zapretkvn/vpnbot-xray-patches/actions/runs",
        ),
        releases_url=env(
            "VPNBOT_XRAY_ALERT_RELEASES_URL",
            "https://git.zapret.moe/api/v1/repos/"
            "zapretkvn/vpnbot-xray-patches/releases",
        ),
        workflow_id=env("VPNBOT_XRAY_ALERT_WORKFLOW_ID", "candidate.yml"),
        bot_env_file=Path(
            env(
                "VPNBOT_XRAY_ALERT_BOT_ENV_FILE",
                "/home/codex-pve/vpnbot/vpnbotdata/env/vpnbot.env",
            )
        ),
        chat_id=env("VPNBOT_XRAY_ALERT_CHAT_ID"),
        promoter_state_dir=Path(
            env(
                "VPNBOT_XRAY_ALERT_PROMOTER_STATE_DIR",
                "/var/lib/vpnbot-xray-release-promoter",
            )
        ),
        state_dir=Path(
            env(
                "VPNBOT_XRAY_ALERT_STATE_DIR",
                "/var/lib/vpnbot-xray-release-alert",
            )
        ),
        stall_seconds=positive_seconds("VPNBOT_XRAY_ALERT_STALL_SECONDS", 7200, 900),
        reminder_seconds=positive_seconds(
            "VPNBOT_XRAY_ALERT_REMINDER_SECONDS", 21600, 3600
        ),
        retry_seconds=positive_seconds("VPNBOT_XRAY_ALERT_RETRY_SECONDS", 900, 60),
        request_timeout_seconds=positive_seconds(
            "VPNBOT_XRAY_ALERT_REQUEST_TIMEOUT_SECONDS", 20, 5
        ),
    )
    for label, url in {
        "Actions URL": settings.actions_url,
        "releases URL": settings.releases_url,
    }.items():
        if not url.startswith("https://"):
            raise release_pipeline.PipelineError(f"{label} must use HTTPS")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", settings.workflow_id):
        raise release_pipeline.PipelineError("invalid monitored workflow id")
    if not re.fullmatch(r"-?[1-9][0-9]*", settings.chat_id):
        raise release_pipeline.PipelineError("invalid Telegram chat id")
    for label, path in {
        "VPnBot runtime env": settings.bot_env_file,
        "promoter state directory": settings.promoter_state_dir,
        "release alert state directory": settings.state_dir,
    }.items():
        if not path.is_absolute():
            raise release_pipeline.PipelineError(f"{label} path must be absolute")
    require_safe_regular_file(settings.bot_env_file, "VPnBot runtime env")
    if not settings.promoter_state_dir.is_dir() or settings.promoter_state_dir.is_symlink():
        raise release_pipeline.PipelineError(
            f"promoter state directory is missing or unsafe: {settings.promoter_state_dir}"
        )
    return settings


def require_safe_regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise release_pipeline.PipelineError(f"{label} is missing or unsafe: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise release_pipeline.PipelineError(f"{label} must not be group/world-readable")


def utc_now(epoch: int | None = None) -> str:
    value = int(time.time()) if epoch is None else epoch
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def parse_timestamp(value: Any, label: str) -> int:
    raw = str(value or "").strip()
    if not raw:
        raise release_pipeline.PipelineError(f"{label} is missing")
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise release_pipeline.PipelineError(f"{label} is invalid: {raw}") from exc
    if parsed.tzinfo is None:
        raise release_pipeline.PipelineError(f"{label} has no timezone: {raw}")
    return int(parsed.timestamp())


def parse_env_value(raw: str, label: str) -> str:
    try:
        parts = shlex.split(raw, comments=False, posix=True)
    except ValueError as exc:
        raise release_pipeline.PipelineError(f"invalid {label} value") from exc
    if len(parts) != 1:
        raise release_pipeline.PipelineError(f"invalid {label} value")
    return parts[0]


def load_alert_environment(path: Path | None = None) -> None:
    configured = path or Path(
        env("VPNBOT_XRAY_ALERT_ENV_FILE", "/etc/vpnbot-xray-release-alert.env")
    )
    if not configured.is_absolute():
        raise release_pipeline.PipelineError("release alert env path must be absolute")
    require_safe_regular_file(configured, "release alert env")
    seen: set[str] = set()
    for number, raw_line in enumerate(
        configured.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise release_pipeline.PipelineError(
                f"invalid release alert env row {number}"
            )
        name, raw_value = line.split("=", 1)
        name = name.strip()
        if name not in ALERT_ENV_NAMES or name in seen:
            raise release_pipeline.PipelineError(
                f"unknown or duplicate release alert env name at row {number}: {name}"
            )
        seen.add(name)
        os.environ.setdefault(
            name,
            parse_env_value(raw_value.strip(), f"{name} at line {number}"),
        )


def parse_telegram_ip_family(raw: str) -> socket.AddressFamily:
    """The bot's ``VPNBOT_TELEGRAM_IP_FAMILY``; empty keeps its IPv4 default."""

    configured = raw.strip().lower()
    if configured in {"", "ipv4", "inet", "inet4", "4"}:
        return socket.AF_INET
    if configured in {"auto", "dual", "dual-stack", "unspec"}:
        return socket.AF_UNSPEC
    if configured in {"ipv6", "inet6", "6"}:
        return socket.AF_INET6
    raise TelegramDeliveryError(
        TELEGRAM_EGRESS_CONFIG_INVALID,
        f"{TELEGRAM_IP_FAMILY_KEY} has an unknown value",
    )


def parse_telegram_fallback_ipv4s(raw: str) -> tuple[str, ...]:
    """The bot's ``VPNBOT_TELEGRAM_API_FALLBACK_IPV4S``: IPv4 only, deduplicated."""

    result: list[str] = []
    for candidate in raw.replace(";", ",").split(","):
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise TelegramDeliveryError(
                TELEGRAM_EGRESS_CONFIG_INVALID,
                f"{TELEGRAM_FALLBACK_IPV4S_KEY} contains an invalid IP",
            ) from exc
        if parsed.version != 4:
            raise TelegramDeliveryError(
                TELEGRAM_EGRESS_CONFIG_INVALID,
                f"{TELEGRAM_FALLBACK_IPV4S_KEY} accepts IPv4 addresses only",
            )
        if str(parsed) not in result:
            result.append(str(parsed))
    return tuple(result)


def load_bot_runtime(path: Path) -> BotRuntime:
    require_safe_regular_file(path, "VPnBot runtime env")
    values: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        name, raw_value = line.split("=", 1)
        name = name.strip()
        if name not in BOT_RUNTIME_KEYS:
            continue
        if name in values:
            raise release_pipeline.PipelineError(f"duplicate {name} in runtime env")
        raw_value = raw_value.strip()
        values[name] = (
            parse_env_value(raw_value, f"{name} at line {number}") if raw_value else ""
        )
    token = values.get(BOT_TOKEN_KEY, "")
    if not re.fullmatch(r"[1-9][0-9]{5,}:[A-Za-z0-9_-]{20,}", token):
        raise release_pipeline.PipelineError("VPNBOT_BOT_TOKEN is missing or malformed")
    health_path = Path(
        values.get(TELEGRAM_EGRESS_HEALTH_PATH_KEY)
        or DEFAULT_TELEGRAM_EGRESS_HEALTH_PATH
    )
    if not health_path.is_absolute():
        raise TelegramDeliveryError(
            TELEGRAM_EGRESS_CONFIG_INVALID,
            f"{TELEGRAM_EGRESS_HEALTH_PATH_KEY} must be absolute",
        )
    return BotRuntime(
        token=token,
        ip_family=parse_telegram_ip_family(values.get(TELEGRAM_IP_FAMILY_KEY, "")),
        fallback_ipv4s=parse_telegram_fallback_ipv4s(
            values.get(TELEGRAM_FALLBACK_IPV4S_KEY, "")
        ),
        egress_health_path=health_path,
    )


def healthy_relay_ports(
    path: Path, *, monotonic: Callable[[], float] = time.monotonic
) -> tuple[int, ...]:
    """Healthy loopback relay ports for the Bot API from the manager projection.

    Only a fresh, well-formed projection routes.  An absent, unreadable,
    foreign-schema or stale file yields no relay and the sender takes the
    direct path, exactly as the bot's ``read_healthy_relay_ports`` does.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ()
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(raw, dict) or raw.get("schema") != 1:
        return ()
    observed = raw.get("updated_at_monotonic")
    if isinstance(observed, bool) or not isinstance(observed, (int, float)):
        return ()
    age = monotonic() - float(observed)
    if age < -5.0 or age > TELEGRAM_RELAY_HEALTH_STALE_SECONDS:
        return ()
    by_host = raw.get("healthy_ports_by_host")
    if not isinstance(by_host, dict):
        return ()
    ports = by_host.get(TELEGRAM_API_HOST)
    if not isinstance(ports, list):
        return ()
    result: list[int] = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            return ()
        if port not in result:
            result.append(port)
    return tuple(sorted(result))


def telegram_routes(
    runtime: BotRuntime,
    *,
    resolve: Callable[..., list[Any]] = socket.getaddrinfo,
    relay_ports: Callable[[Path], tuple[int, ...]] = healthy_relay_ports,
) -> list[TelegramRoute]:
    """Ordered TCP destinations for the Bot API under the host egress contract.

    A healthy manager relay is used exclusively: the direct uplink is the path
    whose Telegram traffic is black-holed.  Without one, the operator's
    fallback IPv4 addresses come first, then DNS restricted to the configured
    address family — never IPv6 when the bot is IPv4-only.
    """

    ports = relay_ports(runtime.egress_health_path)
    if ports:
        return [
            TelegramRoute("relay", "127.0.0.1", port, socket.AF_INET) for port in ports
        ]
    routes: list[TelegramRoute] = []
    seen: set[tuple[int, str]] = set()

    def add(address: str, family: socket.AddressFamily) -> None:
        if (int(family), address) in seen:
            return
        seen.add((int(family), address))
        routes.append(TelegramRoute("direct", address, TELEGRAM_API_PORT, family))

    if runtime.ip_family in {socket.AF_INET, socket.AF_UNSPEC}:
        for address in runtime.fallback_ipv4s:
            add(address, socket.AF_INET)
    try:
        resolved = resolve(
            TELEGRAM_API_HOST,
            TELEGRAM_API_PORT,
            runtime.ip_family,
            socket.SOCK_STREAM,
        )
    except OSError as exc:
        # DNS is an external boundary: the operator's fallback addresses are
        # exactly the route for a broken resolver, as in the bot's resolver.
        if routes:
            return routes
        raise TelegramDeliveryError(
            TELEGRAM_NO_ROUTE, f"cannot resolve {TELEGRAM_API_HOST}: {exc}"
        ) from exc
    for family, _socktype, _proto, _canonname, sockaddr in resolved:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        if runtime.ip_family != socket.AF_UNSPEC and family != runtime.ip_family:
            continue
        add(str(sockaddr[0]), socket.AddressFamily(family))
    if not routes:
        raise TelegramDeliveryError(
            TELEGRAM_NO_ROUTE, f"no usable address for {TELEGRAM_API_HOST}"
        )
    return routes


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to ``api.telegram.org`` over one chosen TCP destination.

    Only the TCP destination changes; the TLS handshake still sends the
    Telegram SNI and verifies Telegram's certificate for that hostname.
    """

    def __init__(
        self,
        route: TelegramRoute,
        *,
        timeout: float,
        tls_context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            TELEGRAM_API_HOST, TELEGRAM_API_PORT, timeout=timeout, context=tls_context
        )
        self._route = route
        self._tls_context = tls_context

    def connect(self) -> None:
        sock = socket.socket(self._route.family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self._route.address, self._route.port))
            self.sock = self._tls_context.wrap_socket(
                sock, server_hostname=TELEGRAM_API_HOST
            )
        except BaseException:
            sock.close()
            raise


def post_telegram(
    route: TelegramRoute,
    path: str,
    payload: bytes,
    *,
    timeout: float,
    tls_context: ssl.SSLContext,
    connection_factory: Callable[..., http.client.HTTPSConnection] = PinnedHTTPSConnection,
) -> tuple[int, bytes] | None:
    """POST once; ``None`` means the connection failed before any byte was sent."""

    connection = connection_factory(route, timeout=timeout, tls_context=tls_context)
    try:
        try:
            connection.connect()
        except OSError:
            return None
        try:
            connection.request(
                "POST",
                path,
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "vpnbot-xray-release-alert/1",
                },
            )
            response = connection.getresponse()
            raw = response.read(TELEGRAM_RESPONSE_LIMIT_BYTES + 1)
            return response.status, raw
        except (OSError, http.client.HTTPException) as exc:
            raise TelegramDeliveryError(
                TELEGRAM_DELIVERY_AMBIGUOUS,
                f"request sent over {route.label()} but no complete response: "
                f"{type(exc).__name__}",
            ) from exc
    finally:
        connection.close()


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(
        url,
        headers={"Accept": "text/html", "User-Agent": "vpnbot-xray-release-alert/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        raise release_pipeline.PipelineError(
            f"Forgejo Actions page returned HTTP {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise release_pipeline.PipelineError(
            f"Forgejo Actions page request failed: {exc.reason}"
        ) from exc
    if len(raw) > 2 * 1024 * 1024:
        raise release_pipeline.PipelineError("Forgejo Actions page is too large")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise release_pipeline.PipelineError(
            "Forgejo Actions page is not UTF-8"
        ) from exc


def actions_web_url(actions_api_url: str, workflow_id: str) -> str:
    match = re.fullmatch(
        r"(https://[^/]+)/api/v1/repos/([^/]+)/([^/]+)/actions/runs(?:\?.*)?",
        actions_api_url,
    )
    if not match:
        raise release_pipeline.PipelineError(
            "Forgejo Actions API URL cannot be mapped to its public workflow page"
        )
    origin, owner, repository = match.groups()
    query = urllib.parse.urlencode({"workflow": workflow_id})
    return f"{origin}/{owner}/{repository}/actions?{query}"


def fetch_actions_html(
    actions_api_url: str,
    workflow_id: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """Read the newest public run when Forgejo's Actions API returns zero rows.

    Forgejo 16 currently renders public runs while its unauthenticated
    ``actions/runs`` API can return an empty list.  The run detail page embeds
    one escaped, structured JSON state object; parsing that object is safer
    than inferring outcome from localized icons or text.
    """

    web_url = actions_web_url(actions_api_url, workflow_id)
    listing = fetch_text(web_url, timeout)
    items = re.findall(
        r'<div class="flex-item tw-items-center">(.*?)(?=<div class="flex-item tw-items-center">|\Z)',
        listing,
        flags=re.DOTALL,
    )
    candidates: list[tuple[int, str, str]] = []
    for item in items:
        link_match = re.search(r'href="([^"]+/actions/runs/([1-9][0-9]*))"', item)
        run_number_match = re.search(r"<b>\s*#([1-9][0-9]*)\s*</b>", item)
        branch_match = re.search(
            r'class="ui label run-list-ref[^>]*data-tooltip-content="([^"]+)"',
            item,
        )
        timestamp_match = re.search(
            r'<relative-time[^>]+datetime="([^"]+)"',
            item,
        )
        if (
            link_match is None
            or run_number_match is None
            or branch_match is None
            or timestamp_match is None
            or run_number_match.group(1) != link_match.group(2)
            or branch_match.group(1) != "main"
        ):
            continue
        candidates.append(
            (int(run_number_match.group(1)), link_match.group(1), timestamp_match.group(1))
        )
    if not candidates:
        return []
    run_id, relative_link, created_at = max(candidates)
    detail_url = urllib.parse.urljoin(web_url, relative_link)
    detail = fetch_text(detail_url, timeout)
    state_match = re.search(
        r'data-initial-post-response="([^"]+)"',
        detail,
    )
    if state_match is None:
        raise release_pipeline.PipelineError(
            f"Forgejo Actions run {run_id} has no structured state"
        )
    try:
        payload = json.loads(html.unescape(state_match.group(1)))
        run = payload["state"]["run"]
        status = str(run["status"]).strip().lower()
        branch = str(run["commit"]["branch"]["name"]).strip()
        title = str(run["title"]).strip()
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise release_pipeline.PipelineError(
            f"Forgejo Actions run {run_id} has invalid structured state"
        ) from exc
    if branch != "main" or not status:
        raise release_pipeline.PipelineError(
            f"Forgejo Actions run {run_id} has an invalid branch or status"
        )
    return [
        {
            "id": run_id,
            "workflow_id": workflow_id,
            "prettyref": branch,
            "status": status,
            "title": title,
            "html_url": detail_url,
            "created_at": created_at,
        }
    ]


def fetch_actions(
    url: str,
    timeout: int,
    workflow_id: str = "",
) -> list[dict[str, Any]]:
    separator = "&" if "?" in url else "?"
    payload = release_pipeline.request_json(f"{url}{separator}limit=50", timeout=timeout)
    if not isinstance(payload, dict):
        raise release_pipeline.PipelineError("Forgejo Actions API returned a non-object")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or not all(isinstance(item, dict) for item in runs):
        raise release_pipeline.PipelineError("Forgejo Actions API returned an invalid run list")
    if runs or not workflow_id:
        return runs
    return fetch_actions_html(url, workflow_id, timeout)


def evaluate_patch_pipeline(
    runs: list[dict[str, Any]],
    workflow_id: str,
    *,
    now_epoch: int | None = None,
    stall_seconds: int = 7200,
) -> Condition:
    relevant = [
        run
        for run in runs
        if str(run.get("workflow_id") or "") == workflow_id
        and str(run.get("prettyref") or "") == "main"
        and isinstance(run.get("id"), int)
    ]
    if not relevant:
        raise release_pipeline.PipelineError(
            f"Forgejo Actions has no {workflow_id} run for main"
        )
    latest = max(relevant, key=lambda item: int(item["id"]))
    status = str(latest.get("status") or "").strip().lower()
    run_id = int(latest["id"])
    title = str(latest.get("title") or "").strip() or "без названия"
    link = str(latest.get("html_url") or "").strip()
    if status == "success":
        return Condition(name="patch_pipeline", status="healthy")
    if status in PENDING_WORKFLOW_STATES:
        created_at = latest.get("created_at")
        if created_at and now_epoch is not None:
            created_epoch = parse_timestamp(
                created_at,
                f"Forgejo Actions run {run_id} creation time",
            )
            if now_epoch - created_epoch >= stall_seconds:
                age_minutes = max(0, (now_epoch - created_epoch) // 60)
                return Condition(
                    name="patch_pipeline",
                    status="problem",
                    signature=f"run:{run_id}:stalled:{status}",
                    headline="Forgejo Actions не начал или не завершил выпуск Xray",
                    detail=(
                        f"Workflow {workflow_id}, запуск {run_id}, состояние: {status}, "
                        f"возраст: {age_minutes} мин. Candidate безопасно не выпускается."
                    ),
                    action=(
                        "Проверь регистрацию и online-состояние Forgejo runner, его "
                        "метку linux и журнал конкретного запуска. Не публикуй proven вручную."
                    ),
                    url=link,
                )
        return Condition(name="patch_pipeline", status="pending")
    if status not in FAILED_WORKFLOW_STATES:
        raise release_pipeline.PipelineError(
            f"unknown Forgejo Actions status for run {run_id}: {status or '<empty>'}"
        )
    return Condition(
        name="patch_pipeline",
        status="problem",
        signature=f"run:{run_id}:{status}",
        headline="Автоматический выпуск Xray остановился в Forgejo",
        detail=(
            f"Workflow {workflow_id}, запуск {run_id}, результат: {status}. "
            f"Commit/запуск: {title}. Новый candidate и proven безопасно не выпускаются."
        ),
        action=(
            "Открой запуск и проверь первый упавший шаг. Если конфликтуют патчи, "
            "адаптируй их к новому официальному Xray и повторно запусти workflow."
        ),
        url=link,
    )


def unproven_candidates(releases: list[dict[str, Any]]) -> list[Candidate]:
    published_tags = {
        str(item.get("tag_name") or "")
        for item in releases
        if not item.get("draft") and not item.get("prerelease")
    }
    candidates: list[Candidate] = []
    for release in releases:
        tag = str(release.get("tag_name") or "").strip()
        if (
            release.get("draft")
            or not release.get("prerelease")
            or not release_pipeline.CANDIDATE_RE.fullmatch(tag)
        ):
            continue
        manifest = release_pipeline.read_release_manifest(release)
        if manifest is None:
            raise release_pipeline.PipelineError(f"candidate {tag} has no manifest")
        if str(manifest["release"]["candidate_tag"]) != tag:
            raise release_pipeline.PipelineError(f"candidate {tag} manifest tag mismatch")
        proven_tag = str(manifest["release"]["proven_tag"])
        if proven_tag in published_tags:
            continue
        candidates.append(
            Candidate(
                tag=tag,
                proven_tag=proven_tag,
                published_epoch=parse_timestamp(
                    release.get("published_at") or release.get("created_at"),
                    f"candidate {tag} publication time",
                ),
                release_url=str(release.get("html_url") or "").strip(),
            )
        )
    return sorted(candidates, key=lambda item: (item.published_epoch, item.tag))


def evaluate_candidate_stall(
    candidates: list[Candidate], now_epoch: int, stall_seconds: int
) -> Condition:
    stalled = [
        candidate
        for candidate in candidates
        if now_epoch - candidate.published_epoch >= stall_seconds
    ]
    if not stalled:
        return Condition(name="candidate_stalled", status="healthy")
    signature = "|".join(candidate.tag for candidate in stalled)
    rows = []
    for candidate in stalled:
        age_minutes = max(0, (now_epoch - candidate.published_epoch) // 60)
        rows.append(
            f"{candidate.tag} -> {candidate.proven_tag}, ждёт {age_minutes} мин."
        )
    return Condition(
        name="candidate_stalled",
        status="problem",
        signature=signature,
        headline="Xray candidate слишком долго не стал proven",
        detail=(
            "Опубликованный candidate уже превысил допустимое окно пилота:\n"
            + "\n".join(rows)
            + "\nСтабильный парк продолжает использовать предыдущий proven."
        ),
        action=(
            "Проверь vpnbot-xray-release-promoter.service, его журнал и root-only "
            "состояние кандидата. Не публикуй proven вручную без успешного proof."
        ),
        url=stalled[0].release_url,
    )


def load_promoter_states(directory: Path) -> dict[str, dict[str, Any]]:
    if not directory.is_dir() or directory.is_symlink():
        raise release_pipeline.PipelineError(
            f"promoter state directory is missing or unsafe: {directory}"
        )
    states: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("*-candidate.*.json")):
        if path.name.endswith(".proof.json"):
            continue
        require_safe_regular_file(path, "promoter candidate state")
        payload = release_pipeline.load_json(path)
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise release_pipeline.PipelineError(f"invalid promoter state: {path}")
        tag = str(payload.get("candidate_tag") or "")
        if not release_pipeline.CANDIDATE_RE.fullmatch(tag):
            raise release_pipeline.PipelineError(f"invalid candidate tag in {path}")
        if path.name != f"{tag}.json" or tag in states:
            raise release_pipeline.PipelineError(f"ambiguous promoter state: {path}")
        states[tag] = payload
    return states


def bounded_error(value: Any, limit: int = 700) -> str:
    text = " ".join(str(value or "неизвестная ошибка").split())
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def evaluate_canary(
    candidates: list[Candidate], states: dict[str, dict[str, Any]]
) -> Condition:
    if not candidates:
        return Condition(name="canary_failed", status="healthy")
    failed: list[tuple[Candidate, dict[str, Any]]] = []
    pending = False
    for candidate in candidates:
        state = states.get(candidate.tag)
        if state is None:
            pending = True
            continue
        phase = str(state.get("phase") or "")
        if phase in PROMOTER_FAILED_PHASES:
            failed.append((candidate, state))
        elif phase in PROMOTER_PENDING_PHASES:
            pending = True
        else:
            raise release_pipeline.PipelineError(
                f"unknown promoter phase for {candidate.tag}: {phase or '<empty>'}"
            )
    if not failed:
        return Condition(
            name="canary_failed",
            status="pending" if pending else "healthy",
        )
    severe = any(state.get("phase") == "failed_rollback_failed" for _, state in failed)
    signature = "|".join(
        f"{candidate.tag}:{state.get('phase')}:{state.get('failed_at', '')}"
        for candidate, state in failed
    )
    rows = []
    for candidate, state in failed:
        phase = str(state["phase"])
        rollback = (
            "ОТКАТ ТОЖЕ НЕ УДАЛСЯ"
            if phase == "failed_rollback_failed"
            else "canary возвращён на предыдущий proven"
        )
        rows.append(
            f"{candidate.tag}: {rollback}. Причина: {bounded_error(state.get('error'))}"
        )
    return Condition(
        name="canary_failed",
        status="problem",
        signature=signature,
        headline=(
            "Canary Xray и автоматический rollback требуют немедленной проверки"
            if severe
            else "Canary Xray не прошёл проверку"
        ),
        detail=(
            "\n".join(rows)
            + "\nНовый proven не опубликован, остальные узлы не затронуты."
        ),
        action=(
            "Проверь canary-узел, journalctl -u vpnbot-xray-release-promoter.service "
            "и JSON состояния. При failed_rollback_failed сначала восстанови canary "
            "на предыдущий точный proven."
        ),
        url=candidates[0].release_url,
        severity="critical" if severe else "warning",
    )


def collect_conditions(settings: Settings, now_epoch: int) -> list[Condition]:
    runs = fetch_actions(
        settings.actions_url,
        settings.request_timeout_seconds,
        settings.workflow_id,
    )
    releases = release_pipeline.list_forgejo_releases(settings.releases_url)
    candidates = unproven_candidates(releases)
    states = load_promoter_states(settings.promoter_state_dir)
    return [
        evaluate_patch_pipeline(
            runs,
            settings.workflow_id,
            now_epoch=now_epoch,
            stall_seconds=settings.stall_seconds,
        ),
        evaluate_candidate_stall(candidates, now_epoch, settings.stall_seconds),
        evaluate_canary(candidates, states),
    ]


def new_state() -> dict[str, Any]:
    return {"schema_version": STATE_SCHEMA_VERSION, "conditions": {}}


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return new_state()
    require_safe_regular_file(path, "release alert state")
    payload = release_pipeline.load_json(path)
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != STATE_SCHEMA_VERSION
        or not isinstance(payload.get("conditions"), dict)
    ):
        raise release_pipeline.PipelineError("invalid release alert state")
    unknown = set(payload["conditions"]) - set(CONDITION_NAMES)
    if unknown:
        raise release_pipeline.PipelineError(
            f"release alert state has unknown conditions: {sorted(unknown)}"
        )
    return payload


def write_state(path: Path, payload: dict[str, Any]) -> None:
    release_pipeline.write_atomic(
        path, release_pipeline.canonical_json_bytes(payload), mode=0o600
    )


def alert_text(condition: Condition, kind: str) -> str:
    icon = "🚨" if condition.severity == "critical" else "⚠️"
    prefix = "Повторное напоминание" if kind == "reminder" else "Безопасная остановка выпуска"
    lines = [
        f"{icon} Xray: {condition.headline}",
        "",
        prefix + ".",
        condition.detail,
        "",
        "Что делать:",
        condition.action,
    ]
    if condition.url:
        lines.extend(["", condition.url])
    return "\n".join(lines)[:4096]


def recovery_text(condition_name: str, record: dict[str, Any]) -> str:
    names = {
        "patch_pipeline": "Forgejo workflow снова завершился успешно",
        "candidate_stalled": "задержавшийся candidate получил proven",
        "canary_failed": "canary-контур снова подтвердил исправный выпуск",
    }
    previous = str(record.get("headline") or condition_name)
    return (
        "✅ Xray: состояние выпуска восстановлено\n\n"
        f"Контур: {names[condition_name]}.\n"
        f"Предыдущая проблема: {previous}.\n"
        "Стабильный канал по-прежнему принимает только proven-релизы."
    )


def telegram_sender(
    settings: Settings,
    runtime: BotRuntime,
    *,
    routes: Callable[[BotRuntime], list[TelegramRoute]] = telegram_routes,
    post: Callable[..., tuple[int, bytes] | None] = post_telegram,
    tls_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
) -> Callable[[str], int]:
    path = f"/bot{runtime.token}/sendMessage"

    def send(text: str) -> int:
        payload = release_pipeline.canonical_json_bytes(
            {
                "chat_id": settings.chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }
        )
        tls_context = tls_context_factory()
        attempted: list[str] = []
        answer: tuple[int, bytes] | None = None
        for route in routes(runtime):
            attempted.append(route.label())
            answer = post(
                route,
                path,
                payload,
                timeout=settings.request_timeout_seconds,
                tls_context=tls_context,
            )
            if answer is not None:
                break
        if answer is None:
            raise TelegramDeliveryError(
                TELEGRAM_CONNECT_FAILED,
                "no Telegram route accepted a connection; nothing was sent: "
                + ", ".join(attempted),
            )
        status, raw = answer
        if status != 200:
            raise TelegramDeliveryError(
                TELEGRAM_HTTP_STATUS, f"Telegram Bot API returned HTTP {status}"
            )
        if len(raw) > TELEGRAM_RESPONSE_LIMIT_BYTES:
            raise TelegramDeliveryError(
                TELEGRAM_RESPONSE_INVALID, "Telegram Bot API response is too large"
            )
        try:
            decoded = json.loads(raw)
            message_id = decoded["result"]["message_id"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise TelegramDeliveryError(
                TELEGRAM_RESPONSE_INVALID,
                "Telegram Bot API returned an invalid response",
            ) from exc
        if decoded.get("ok") is not True or not isinstance(message_id, int):
            raise TelegramDeliveryError(
                TELEGRAM_REJECTED, "Telegram Bot API rejected the message"
            )
        return message_id

    return send


def retry_allowed(record: dict[str, Any], now_epoch: int, retry_seconds: int) -> bool:
    last_attempt = int(record.get("last_attempt_epoch") or 0)
    return not last_attempt or now_epoch - last_attempt >= retry_seconds


def reconcile_condition(
    condition: Condition,
    state: dict[str, Any],
    state_path: Path,
    send: Callable[[str], int],
    settings: Settings,
    now_epoch: int,
) -> None:
    conditions = state["conditions"]
    record = conditions.setdefault(condition.name, {"active": False})
    record["last_observed_at"] = utc_now(now_epoch)
    record["last_status"] = condition.status

    if condition.status == "pending":
        write_state(state_path, state)
        return

    if condition.status == "problem":
        is_new = not record.get("active") or record.get("signature") != condition.signature
        if is_new:
            record.update(
                {
                    "active": True,
                    "signature": condition.signature,
                    "headline": condition.headline,
                    "first_seen_at": utc_now(now_epoch),
                    "last_attempt_epoch": 0,
                    "last_notified_epoch": 0,
                    "last_message_id": None,
                }
            )
        record["detail"] = condition.detail
        record["severity"] = condition.severity
        notified = int(record.get("last_notified_epoch") or 0)
        kind = "alert" if not notified else ""
        if notified and now_epoch - notified >= settings.reminder_seconds:
            kind = "reminder"
        if not kind or not retry_allowed(record, now_epoch, settings.retry_seconds):
            write_state(state_path, state)
            return
        record["pending_delivery"] = kind
        record["last_attempt_at"] = utc_now(now_epoch)
        record["last_attempt_epoch"] = now_epoch
        write_state(state_path, state)
        message_id = send(alert_text(condition, kind))
        record["last_notified_at"] = utc_now(now_epoch)
        record["last_notified_epoch"] = now_epoch
        record["last_message_id"] = message_id
        record.pop("pending_delivery", None)
        write_state(state_path, state)
        return

    if condition.status != "healthy":
        raise release_pipeline.PipelineError(
            f"invalid condition status for {condition.name}: {condition.status}"
        )
    if not record.get("active"):
        write_state(state_path, state)
        return
    if not retry_allowed(record, now_epoch, settings.retry_seconds):
        write_state(state_path, state)
        return
    record["pending_delivery"] = "recovery"
    record["last_attempt_at"] = utc_now(now_epoch)
    record["last_attempt_epoch"] = now_epoch
    write_state(state_path, state)
    message_id = send(recovery_text(condition.name, record))
    record["active"] = False
    record["resolved_at"] = utc_now(now_epoch)
    record["last_recovery_message_id"] = message_id
    record.pop("pending_delivery", None)
    write_state(state_path, state)


def reconcile(
    settings: Settings,
    conditions: list[Condition],
    send: Callable[[str], int],
    now_epoch: int,
) -> dict[str, Any]:
    settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if settings.state_dir.is_symlink():
        raise release_pipeline.PipelineError("release alert state directory is a symlink")
    settings.state_dir.chmod(0o700)
    path = settings.state_dir / "state.json"
    state = load_state(path)
    for condition in conditions:
        reconcile_condition(condition, state, path, send, settings, now_epoch)
    state["last_successful_check_at"] = utc_now(now_epoch)
    write_state(path, state)
    return state


def status_payload(conditions: list[Condition]) -> dict[str, Any]:
    return {
        condition.name: {
            "status": condition.status,
            "signature": condition.signature or None,
            "headline": condition.headline or None,
        }
        for condition in conditions
    }


@contextlib.contextmanager
def monitor_lock(path: Path) -> Any:
    with path.open("w", encoding="utf-8") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield lock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-status",
        action="store_true",
        help="read all sources and print the computed conditions without sending",
    )
    parser.add_argument(
        "--send-test",
        action="store_true",
        help="send one explicit installation test without changing incident state",
    )
    args = parser.parse_args()
    try:
        load_alert_environment()
        settings = load_settings()
        now_epoch = int(time.time())
        conditions = collect_conditions(settings, now_epoch)
        if args.print_status:
            print(json.dumps(status_payload(conditions), ensure_ascii=False, sort_keys=True))
            return 0
        runtime = load_bot_runtime(settings.bot_env_file)
        send = telegram_sender(settings, runtime)
        if args.send_test:
            message_id = send(
                "✅ Монитор автоматических выпусков Xray подключён.\n\n"
                "Он проверяет Forgejo workflow, задержавшиеся candidate-релизы и "
                "результат production-canary. Это тест доставки; аварии сейчас не "
                "создавались."
            )
            print(f"Telegram test message delivered: message_id={message_id}")
            return 0
        settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        settings.state_dir.chmod(0o700)
        lock_path = settings.state_dir / "monitor.lock"
        with monitor_lock(lock_path):
            state = reconcile(settings, conditions, send, now_epoch)
        active = sorted(
            name
            for name, record in state["conditions"].items()
            if record.get("active")
        )
        print(
            "Xray release alert check completed: "
            f"active={','.join(active) if active else 'none'}"
        )
        return 0
    except BlockingIOError:
        print("Another VPnBot Xray release alert check is active", file=sys.stderr)
        return 75
    except Exception as exc:
        print(f"vpnbot-xray-release-alert: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
