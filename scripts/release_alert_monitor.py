#!/usr/bin/env python3
"""Notify the VPnBot operator when the Xray release train stops safely."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import fcntl
import json
import os
import re
import shlex
import stat
import sys
import time
import urllib.error
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
            "zapretdiscordyoutube/vpnbot-xray-patches/actions/runs",
        ),
        releases_url=env(
            "VPNBOT_XRAY_ALERT_RELEASES_URL",
            "https://git.zapret.moe/api/v1/repos/"
            "zapretdiscordyoutube/vpnbot-xray-patches/releases",
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


def load_bot_token(path: Path) -> str:
    require_safe_regular_file(path, "VPnBot runtime env")
    token = ""
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        name, raw_value = line.split("=", 1)
        if name.strip() != "VPNBOT_BOT_TOKEN":
            continue
        if token:
            raise release_pipeline.PipelineError("duplicate VPNBOT_BOT_TOKEN in runtime env")
        token = parse_env_value(raw_value.strip(), f"VPNBOT_BOT_TOKEN at line {number}")
    if not re.fullmatch(r"[1-9][0-9]{5,}:[A-Za-z0-9_-]{20,}", token):
        raise release_pipeline.PipelineError("VPNBOT_BOT_TOKEN is missing or malformed")
    return token


def fetch_actions(url: str, timeout: int) -> list[dict[str, Any]]:
    separator = "&" if "?" in url else "?"
    payload = release_pipeline.request_json(f"{url}{separator}limit=50", timeout=timeout)
    if not isinstance(payload, dict):
        raise release_pipeline.PipelineError("Forgejo Actions API returned a non-object")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or not all(isinstance(item, dict) for item in runs):
        raise release_pipeline.PipelineError("Forgejo Actions API returned an invalid run list")
    return runs


def evaluate_patch_pipeline(runs: list[dict[str, Any]], workflow_id: str) -> Condition:
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
    runs = fetch_actions(settings.actions_url, settings.request_timeout_seconds)
    releases = release_pipeline.list_forgejo_releases(settings.releases_url)
    candidates = unproven_candidates(releases)
    states = load_promoter_states(settings.promoter_state_dir)
    return [
        evaluate_patch_pipeline(runs, settings.workflow_id),
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


def telegram_sender(settings: Settings, token: str) -> Callable[[str], int]:
    endpoint = f"https://api.telegram.org/bot{token}/sendMessage"

    def send(text: str) -> int:
        payload = release_pipeline.canonical_json_bytes(
            {
                "chat_id": settings.chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }
        )
        request = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "vpnbot-xray-release-alert/1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=settings.request_timeout_seconds
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise release_pipeline.PipelineError(
                f"Telegram Bot API returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise release_pipeline.PipelineError(
                f"Telegram Bot API request failed: {exc.reason}"
            ) from exc
        try:
            decoded = json.loads(raw)
            message_id = decoded["result"]["message_id"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise release_pipeline.PipelineError(
                "Telegram Bot API returned an invalid response"
            ) from exc
        if decoded.get("ok") is not True or not isinstance(message_id, int):
            raise release_pipeline.PipelineError("Telegram Bot API rejected the message")
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
        token = load_bot_token(settings.bot_env_file)
        send = telegram_sender(settings, token)
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
