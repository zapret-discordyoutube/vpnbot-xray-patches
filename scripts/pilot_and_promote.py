#!/usr/bin/env python3
"""Install the newest candidate on one canary and promote it after proof."""

from __future__ import annotations

import dataclasses
import fcntl
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import release_pipeline


@dataclasses.dataclass(frozen=True)
class Settings:
    releases_url: str
    token_file: Path
    canary_node: str
    canary_host: str
    canary_port: int
    canary_user: str
    identity_file: Path
    known_hosts_file: Path
    updater_path: str
    xray_path: str
    config_dir: str
    service_name: str
    state_dir: Path
    canary_script: Path
    timeout_seconds: int


def env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default)).strip()


def load_settings() -> Settings:
    script_dir = Path(__file__).resolve().parent
    settings = Settings(
        releases_url=env(
            "VPNBOT_XRAY_FORGEJO_RELEASES_URL",
            "https://git.zapret.moe/api/v1/repos/zapretkvn/vpnbot-xray-patches/releases",
        ),
        token_file=Path(env("VPNBOT_XRAY_FORGEJO_TOKEN_FILE")),
        canary_node=env("VPNBOT_XRAY_CANARY_NODE"),
        canary_host=env("VPNBOT_XRAY_CANARY_HOST"),
        canary_port=int(env("VPNBOT_XRAY_CANARY_SSH_PORT", "10222")),
        canary_user=env("VPNBOT_XRAY_CANARY_SSH_USER", "root"),
        identity_file=Path(env("VPNBOT_XRAY_CANARY_IDENTITY_FILE", "/root/.ssh/id_ed25519")),
        known_hosts_file=Path(env("VPNBOT_XRAY_CANARY_KNOWN_HOSTS_FILE", "/root/.ssh/known_hosts")),
        updater_path=env("VPNBOT_XRAY_CANARY_UPDATER", "/usr/local/bin/vpnbot-xray-core-updater"),
        xray_path=env("VPNBOT_XRAY_CANARY_BINARY", "/opt/vpnbot/xray-core/bin/xray"),
        config_dir=env("VPNBOT_XRAY_CANARY_CONFIG_DIR", "/opt/vpnbot/xray-core/config"),
        service_name=env("VPNBOT_XRAY_CANARY_SERVICE", "vpnbot-xray.service"),
        state_dir=Path(env("VPNBOT_XRAY_PROMOTER_STATE_DIR", "/var/lib/vpnbot-xray-release-promoter")),
        canary_script=Path(
            env("VPNBOT_XRAY_CANARY_SCRIPT", str(script_dir / "canary_active_revoke.py"))
        ),
        timeout_seconds=max(60, int(env("VPNBOT_XRAY_PROMOTER_TIMEOUT_SECONDS", "900"))),
    )
    if not settings.releases_url.startswith("https://"):
        raise release_pipeline.PipelineError("Forgejo releases URL must use HTTPS")
    for label, value in {
        "canary node": settings.canary_node,
        "canary host": settings.canary_host,
        "canary user": settings.canary_user,
    }.items():
        if not value or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise release_pipeline.PipelineError(f"invalid {label}")
    if not 1 <= settings.canary_port <= 65535:
        raise release_pipeline.PipelineError("invalid canary SSH port")
    for label, path in {
        "token file": settings.token_file,
        "SSH identity": settings.identity_file,
        "known_hosts": settings.known_hosts_file,
        "canary script": settings.canary_script,
    }.items():
        if not path.is_file() or path.is_symlink():
            raise release_pipeline.PipelineError(f"{label} is missing or unsafe: {path}")
    token_mode = stat.S_IMODE(settings.token_file.stat().st_mode)
    if token_mode & 0o077:
        raise release_pipeline.PipelineError("Forgejo token file must not be group/world-readable")
    for value in (
        settings.updater_path,
        settings.xray_path,
        settings.config_dir,
        settings.service_name,
    ):
        if not re.fullmatch(r"[A-Za-z0-9_./@+-]+", value):
            raise release_pipeline.PipelineError(f"unsafe remote setting: {value}")
    return settings


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_token(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if not token or any(character.isspace() for character in token):
        raise release_pipeline.PipelineError("Forgejo token file is empty or malformed")
    return token


def ssh_base(settings: Settings) -> list[str]:
    return [
        "ssh",
        "-i",
        str(settings.identity_file),
        "-p",
        str(settings.canary_port),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={settings.known_hosts_file}",
        "-o",
        "ConnectTimeout=15",
        f"{settings.canary_user}@{settings.canary_host}",
    ]


def remote_command(
    settings: Settings,
    args: list[str],
    *,
    stdin: bytes | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    remote = shlex.join(args)
    return subprocess.run(
        [*ssh_base(settings), remote],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout or settings.timeout_seconds,
    )


def require_remote_success(result: subprocess.CompletedProcess[bytes], action: str) -> str:
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    if result.returncode != 0:
        raise release_pipeline.PipelineError(
            f"{action} failed with exit={result.returncode}: {stderr or stdout or '<no output>'}"
        )
    return stdout


def remote_version(settings: Settings) -> tuple[str, str]:
    output = require_remote_success(
        remote_command(settings, [settings.xray_path, "version"], timeout=30),
        "reading canary Xray version",
    )
    first_line = output.splitlines()[0] if output else ""
    match = re.search(r"\bXray\s+([0-9]+(?:\.[0-9]+){2}(?:-[A-Za-z0-9_.-]+)?)", first_line)
    if not match:
        raise release_pipeline.PipelineError(f"cannot parse canary Xray version: {first_line}")
    return output, f"v{match.group(1)}"


def updater(settings: Settings, tag: str, channel: str) -> str:
    if not (
        release_pipeline.CANDIDATE_RE.fullmatch(tag)
        or release_pipeline.PROVEN_RE.fullmatch(tag)
    ):
        raise release_pipeline.PipelineError(f"unsafe updater target tag: {tag}")
    cpu_profile = "v3" if channel == "candidate" else "auto"
    result = remote_command(
        settings,
        [
            "/usr/bin/env",
            f"XRAY_CORE_RELEASE_CHANNEL={channel}",
            f"XRAY_CORE_VERSION={tag}",
            f"XRAY_CORE_CPU_PROFILE={cpu_profile}",
            settings.updater_path,
            "--force",
        ],
    )
    output = require_remote_success(result, f"installing {tag} on canary")
    if channel == "candidate" and "cpu_profile=v3" not in output:
        raise release_pipeline.PipelineError(
            "candidate updater did not prove the required GOAMD64 v3 artifact"
        )
    return output


def write_state(path: Path, payload: dict[str, Any]) -> None:
    release_pipeline.write_atomic(path, release_pipeline.canonical_json_bytes(payload), mode=0o600)


def state_path(settings: Settings, candidate_tag: str) -> Path:
    if not release_pipeline.CANDIDATE_RE.fullmatch(candidate_tag):
        raise release_pipeline.PipelineError("invalid candidate tag for state path")
    return settings.state_dir / f"{candidate_tag}.json"


def select_candidate(
    settings: Settings, token: str
) -> tuple[dict[str, Any], dict[str, Any], bytes] | None:
    releases = release_pipeline.list_forgejo_releases(settings.releases_url, token=token)
    known_tags = {str(item.get("tag_name") or "") for item in releases if not item.get("draft")}
    for candidate in releases:
        tag = str(candidate.get("tag_name") or "")
        if (
            candidate.get("draft")
            or not candidate.get("prerelease")
            or not release_pipeline.CANDIDATE_RE.fullmatch(tag)
        ):
            continue
        manifest = release_pipeline.read_release_manifest(candidate, token=token)
        if manifest is None:
            raise release_pipeline.PipelineError(f"candidate {tag} has no release manifest")
        if manifest["release"]["candidate_tag"] != tag:
            raise release_pipeline.PipelineError(f"candidate {tag} manifest tag mismatch")
        proven_tag = str(manifest["release"]["proven_tag"])
        if proven_tag in known_tags:
            continue
        manifest_asset = release_pipeline.release_assets(candidate)[release_pipeline.MANIFEST_NAME]
        manifest_bytes = release_pipeline.request_bytes(
            release_pipeline.asset_url(manifest_asset), token=token
        )
        return candidate, manifest, manifest_bytes
    return None


def ensure_previous_is_proven(settings: Settings, token: str, tag: str) -> None:
    release = release_pipeline.release_by_tag(settings.releases_url, tag, token=token)
    if release is None or release.get("draft") or release.get("prerelease"):
        raise release_pipeline.PipelineError(
            f"canary current version {tag} is not an available proven rollback target"
        )


def resolve_previous_proven_tag(
    settings: Settings,
    token: str,
    version_statement: str,
) -> str:
    if release_pipeline.CAPABILITY not in version_statement:
        raise release_pipeline.PipelineError(
            "canary current Xray lacks the required active-revoke capability"
        )
    exact = re.search(r"v[0-9]+(?:\.[0-9]+){2}-vpnbot\.[1-9][0-9]*", version_statement)
    if exact:
        tag = exact.group(0)
        ensure_previous_is_proven(settings, token, tag)
        return tag
    numeric = re.search(r"\bXray\s+([0-9]+(?:\.[0-9]+){2})\b", version_statement)
    if not numeric:
        raise release_pipeline.PipelineError(
            "cannot map the canary current Xray version to a proven rollback release"
        )
    prefix = f"v{numeric.group(1)}-vpnbot."
    releases = release_pipeline.list_forgejo_releases(settings.releases_url, token=token)
    for release in releases:
        tag = str(release.get("tag_name") or "")
        if (
            not release.get("draft")
            and not release.get("prerelease")
            and release_pipeline.PROVEN_RE.fullmatch(tag)
            and tag.startswith(prefix)
        ):
            return tag
    raise release_pipeline.PipelineError(
        f"no proven rollback release matches installed Xray {numeric.group(1)}"
    )


def run_canary(settings: Settings, expected_proven_tag: str) -> dict[str, Any]:
    script = settings.canary_script.read_bytes()
    result = remote_command(
        settings,
        [
            "/usr/bin/python3",
            "-",
            "--xray",
            settings.xray_path,
            "--config-dir",
            settings.config_dir,
            "--service",
            settings.service_name,
            "--expected-tag",
            expected_proven_tag,
            "--capability",
            release_pipeline.CAPABILITY,
            "--live-audit-capability",
            release_pipeline.LIVE_USER_AUDIT_CAPABILITY,
            "--cutoff-seconds",
            "10",
        ],
        stdin=script,
    )
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    last_line = stdout.splitlines()[-1] if stdout else ""
    try:
        payload = json.loads(last_line)
    except json.JSONDecodeError as exc:
        raise release_pipeline.PipelineError(
            f"canary returned non-JSON output: {stderr or stdout or '<no output>'}"
        ) from exc
    if result.returncode != 0 or payload.get("result") != "passed":
        raise release_pipeline.PipelineError(
            f"active-revoke canary failed: {payload.get('error') or stderr or stdout}"
        )
    checks = payload.get("checks")
    if not isinstance(checks, dict) or not checks or not all(value is True for value in checks.values()):
        raise release_pipeline.PipelineError("canary returned incomplete checks")
    return payload


def promote(
    settings: Settings,
    token: str,
    candidate_tag: str,
    proof_path: Path,
) -> None:
    environment = os.environ.copy()
    environment["FORGEJO_TOKEN"] = token
    result = subprocess.run(
        [
            sys.executable,
            str(Path(release_pipeline.__file__).resolve()),
            "promote",
            "--forgejo-releases-url",
            settings.releases_url,
            "--candidate-tag",
            candidate_tag,
            "--proof",
            str(proof_path),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=settings.timeout_seconds,
        env=environment,
    )
    if result.returncode != 0:
        raise release_pipeline.PipelineError(
            result.stderr.strip() or result.stdout.strip() or "candidate promotion failed"
        )
    print(result.stdout.strip())


def process_candidate(
    settings: Settings,
    token: str,
    candidate: dict[str, Any],
    manifest: dict[str, Any],
    manifest_bytes: bytes,
) -> None:
    candidate_tag = str(manifest["release"]["candidate_tag"])
    proven_tag = str(manifest["release"]["proven_tag"])
    state_file = state_path(settings, candidate_tag)
    proof_file = settings.state_dir / f"{candidate_tag}.proof.json"
    state: dict[str, Any] = {}
    if state_file.exists():
        loaded = release_pipeline.load_json(state_file)
        if not isinstance(loaded, dict):
            raise release_pipeline.PipelineError(f"invalid promoter state: {state_file}")
        state = loaded
    manifest_hash = release_pipeline.sha256_bytes(manifest_bytes)
    if state and state.get("manifest_sha256") != manifest_hash:
        raise release_pipeline.PipelineError("candidate manifest changed after the pilot started")

    if state.get("phase") == "pilot_passed":
        if not proof_file.is_file():
            raise release_pipeline.PipelineError("pilot state exists without its proof file")
        promote(settings, token, candidate_tag, proof_file)
        state["phase"] = "promoted"
        state["promoted_at"] = utc_now()
        write_state(state_file, state)
        return

    release_pipeline.validated_candidate_payloads(candidate, token=token)
    current_statement, _ = remote_version(settings)
    previous_tag = str(
        state.get("previous_proven_tag")
        or resolve_previous_proven_tag(settings, token, current_statement)
    )
    ensure_previous_is_proven(settings, token, previous_tag)
    state = {
        "schema_version": 1,
        "phase": "installing",
        "candidate_tag": candidate_tag,
        "proven_tag": proven_tag,
        "manifest_sha256": manifest_hash,
        "canary_node": settings.canary_node,
        "previous_proven_tag": previous_tag,
        "previous_version_statement": state.get("previous_version_statement") or current_statement,
        "started_at": state.get("started_at") or utc_now(),
    }
    write_state(state_file, state)

    try:
        updater_output = updater(settings, candidate_tag, "candidate")
        state["phase"] = "installed"
        state["updater_output"] = updater_output[-2000:]
        state["installed_at"] = utc_now()
        write_state(state_file, state)
        canary = run_canary(settings, proven_tag)
    except Exception as pilot_error:
        rollback_error = ""
        try:
            updater(settings, previous_tag, "stable")
        except Exception as exc:
            rollback_error = f"; rollback also failed: {exc}"
        state["phase"] = "failed_rolled_back" if not rollback_error else "failed_rollback_failed"
        state["failed_at"] = utc_now()
        state["error"] = f"{pilot_error}{rollback_error}"
        write_state(state_file, state)
        raise release_pipeline.PipelineError(state["error"]) from pilot_error

    installed_statement, _ = remote_version(settings)
    checks = dict(canary["checks"])
    checks["candidate_manifest_valid"] = True
    checks["candidate_assets_valid"] = True
    checks["candidate_installed_by_atomic_updater"] = True
    proof = {
        "schema_version": 1,
        "result": "passed",
        "candidate_tag": candidate_tag,
        "proven_tag": proven_tag,
        "manifest_sha256": manifest_hash,
        "canary_node": settings.canary_node,
        "canary_host": settings.canary_host,
        "started_at": state["started_at"],
        "passed_at": utc_now(),
        "previous_version_statement": state["previous_version_statement"],
        "installed_version_statement": installed_statement,
        "checks": checks,
        "active_revoke": canary.get("active_revoke"),
    }
    write_state(proof_file, proof)
    state["phase"] = "pilot_passed"
    state["passed_at"] = proof["passed_at"]
    state["proof_file"] = str(proof_file)
    write_state(state_file, state)
    promote(settings, token, candidate_tag, proof_file)
    state["phase"] = "promoted"
    state["promoted_at"] = utc_now()
    write_state(state_file, state)


def main() -> int:
    try:
        settings = load_settings()
        settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        settings.state_dir.chmod(0o700)
        lock_path = settings.state_dir / "promoter.lock"
        with lock_path.open("w", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            token = load_token(settings.token_file)
            selected = select_candidate(settings, token)
            if selected is None:
                print("No unproven VPnBot Xray candidate is waiting")
                return 0
            candidate, manifest, manifest_bytes = selected
            process_candidate(settings, token, candidate, manifest, manifest_bytes)
            return 0
    except BlockingIOError:
        print("Another VPnBot Xray promoter run is active", file=sys.stderr)
        return 75
    except Exception as exc:
        print(f"vpnbot-xray-release-promoter: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
