#!/usr/bin/env python3
"""Deterministic candidate/proven release control for VPnBot Xray builds."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import mimetypes
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 2
CAPABILITY = "vpnbot-active-revoke-v3"
BUILD_PROFILE = "linux-cpu-profiles-v2"
OFFICIAL_REPOSITORY = "https://github.com/XTLS/Xray-core.git"
OFFICIAL_RELEASES_FEED = "https://github.com/XTLS/Xray-core/releases.atom"
OFFICIAL_RELEASE_TAG_PATH = "/XTLS/Xray-core/releases/tag/"
ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
MANIFEST_NAME = "vpnbot-xray-release-manifest.json"
PROOF_NAME = "vpnbot-xray-pilot-proof.json"
TAG_RE = re.compile(r"^v(?P<version>[0-9]+(?:\.[0-9]+){2})$")
PROVEN_RE = re.compile(r"^(v[0-9]+(?:\.[0-9]+){2})-vpnbot\.(?P<edition>[1-9][0-9]*)$")
CANDIDATE_RE = re.compile(
    r"^(v[0-9]+(?:\.[0-9]+){2})-vpnbot\.(?P<edition>[1-9][0-9]*)-candidate\.(?P<candidate>[1-9][0-9]*)$"
)
SAFE_ENV_RE = re.compile(r"^[A-Za-z0-9_./:@+-]+$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

GOAMD64_V3_LINUX_FLAGS = (
    "abm",
    "avx",
    "avx2",
    "bmi1",
    "bmi2",
    "cx16",
    "f16c",
    "fma",
    "lahf_lm",
    "movbe",
    "pni",
    "popcnt",
    "sse4_1",
    "sse4_2",
    "ssse3",
    "xsave",
)

ARTIFACT_PROFILES: dict[str, dict[str, Any]] = {
    "Xray-linux-64.zip": {
        "goarch": "amd64",
        "goamd64": "v1",
        "cpu_profile": "baseline",
        "required_linux_cpu_flags": [],
    },
    "Xray-linux-64-v3.zip": {
        "goarch": "amd64",
        "goamd64": "v3",
        "cpu_profile": "v3",
        "required_linux_cpu_flags": list(GOAMD64_V3_LINUX_FLAGS),
    },
    "Xray-linux-arm64-v8a.zip": {
        "goarch": "arm64",
        "goamd64": "",
        "cpu_profile": "native",
        "required_linux_cpu_flags": [],
    },
    "Xray-linux-arm32-v7a.zip": {
        "goarch": "arm",
        "goamd64": "",
        "cpu_profile": "native",
        "required_linux_cpu_flags": [],
    },
}


class PipelineError(RuntimeError):
    """A fail-closed release pipeline error."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_atomic(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    try:
        temporary.write_bytes(payload)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def request_bytes(
    url: str,
    *,
    token: str = "",
    method: str = "GET",
    payload: bytes | None = None,
    content_type: str = "application/json",
    accept: str = "application/json",
    timeout: int = 90,
) -> bytes:
    headers = {
        "Accept": accept,
        "User-Agent": "vpnbot-xray-release-pipeline/1",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    if payload is not None:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise PipelineError(f"HTTP {exc.code} for {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise PipelineError(f"request failed for {url}: {exc.reason}") from exc


def request_json(
    url: str,
    *,
    token: str = "",
    method: str = "GET",
    payload: Any | None = None,
    timeout: int = 90,
) -> Any:
    raw_payload = canonical_json_bytes(payload) if payload is not None else None
    raw = request_bytes(url, token=token, method=method, payload=raw_payload, timeout=timeout)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PipelineError(f"non-JSON response from {url}") from exc


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot read JSON {path}: {exc}") from exc


def read_patch_rows(repository_root: Path) -> list[dict[str, str]]:
    series = repository_root / "patches" / "series"
    rows: list[dict[str, str]] = []
    for number, raw_line in enumerate(series.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2 or not HEX64_RE.fullmatch(fields[0]):
            raise PipelineError(f"invalid patches/series row {number}")
        name = fields[1]
        if not re.fullmatch(r"[0-9]{4}-[A-Za-z0-9._-]+\.patch", name):
            raise PipelineError(f"unsafe patch name in patches/series: {name}")
        path = repository_root / "patches" / name
        if not path.is_file() or path.is_symlink():
            raise PipelineError(f"patch is missing or unsafe: {name}")
        actual = sha256_file(path)
        if actual != fields[0]:
            raise PipelineError(f"patch digest mismatch: {name}")
        rows.append({"name": name, "sha256": actual})
    if len(rows) != 3:
        raise PipelineError(f"expected exactly three patches, got {len(rows)}")
    return rows


def patchset_sha256(rows: list[dict[str, str]]) -> str:
    material = "".join(f"{row['sha256']}  {row['name']}\n" for row in rows).encode("utf-8")
    return sha256_bytes(material)


def git_output(repository_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository_root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if result.returncode != 0:
        raise PipelineError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def latest_official_release() -> str:
    raw = request_bytes(
        OFFICIAL_RELEASES_FEED,
        accept="application/atom+xml, application/xml;q=0.9",
    )
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise PipelineError("official Xray release feed is invalid XML") from exc
    if root.tag != f"{{{ATOM_NAMESPACE}}}feed":
        raise PipelineError("official Xray release feed has an unexpected root")

    for entry in root.findall(f"{{{ATOM_NAMESPACE}}}entry"):
        for link in entry.findall(f"{{{ATOM_NAMESPACE}}}link"):
            if str(link.get("rel") or "alternate") != "alternate":
                continue
            href = str(link.get("href") or "").strip()
            parsed = urllib.parse.urlsplit(href)
            if (
                parsed.scheme != "https"
                or parsed.netloc.lower() != "github.com"
                or parsed.query
                or parsed.fragment
                or not parsed.path.startswith(OFFICIAL_RELEASE_TAG_PATH)
            ):
                continue
            tag = urllib.parse.unquote(parsed.path.removeprefix(OFFICIAL_RELEASE_TAG_PATH))
            if "/" not in tag and TAG_RE.fullmatch(tag):
                return tag
    raise PipelineError("official Xray release feed contains no safe release tag")


def _run_git(repository: Path, *args: str, timeout: int = 180) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PipelineError(f"git {' '.join(args)} failed: {exc}") from exc
    if result.returncode != 0:
        raise PipelineError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def official_git_metadata(tag: str) -> tuple[str, int, str, str]:
    if not TAG_RE.fullmatch(tag):
        raise PipelineError(f"invalid official Xray tag: {tag}")
    with tempfile.TemporaryDirectory(prefix="vpnbot-xray-official-") as raw_tmp:
        repository = Path(raw_tmp) / "xray"
        repository.mkdir(mode=0o700)
        _run_git(repository, "init", "-q")
        _run_git(repository, "remote", "add", "origin", OFFICIAL_REPOSITORY)
        _run_git(
            repository,
            "fetch",
            "--quiet",
            "--depth",
            "1",
            "origin",
            f"refs/tags/{tag}:refs/tags/{tag}",
        )
        commit = _run_git(repository, "rev-parse", f"{tag}^{{commit}}")
        if not HEX40_RE.fullmatch(commit):
            raise PipelineError(f"official tag {tag} did not resolve to a full commit")
        raw_epoch = _run_git(repository, "show", "-s", "--format=%ct", commit)
        if not raw_epoch.isdigit() or int(raw_epoch) <= 0:
            raise PipelineError(f"official commit {commit} has an invalid timestamp")
        epoch = int(raw_epoch)
        go_mod = _run_git(repository, "show", f"{commit}:go.mod")

    match = re.search(r"(?m)^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$", go_mod)
    if not match:
        raise PipelineError("official go.mod does not declare a Go version")
    commit_time = (
        dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return commit, epoch, commit_time, match.group(1)


def release_assets(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {}
    for item in release.get("assets") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            if name in assets:
                raise PipelineError(f"release contains duplicate asset name: {name}")
            assets[name] = item
    return assets


def asset_url(asset: dict[str, Any]) -> str:
    url = str(asset.get("browser_download_url") or asset.get("url") or "").strip()
    if not url:
        raise PipelineError(f"release asset {asset.get('name')} has no download URL")
    return url


def read_release_manifest(release: dict[str, Any], *, token: str = "") -> dict[str, Any] | None:
    asset = release_assets(release).get(MANIFEST_NAME)
    if asset is None:
        return None
    raw = request_bytes(asset_url(asset), token=token)
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PipelineError(f"invalid manifest in release {release.get('tag_name')}") from exc
    validate_manifest(manifest)
    return manifest


def list_forgejo_releases(url: str, *, token: str = "") -> list[dict[str, Any]]:
    separator = "&" if "?" in url else "?"
    payload = request_json(f"{url}{separator}limit=100", token=token)
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise PipelineError("Forgejo releases API did not return a release list")
    return payload


def same_source_and_patches(manifest: dict[str, Any], commit: str, patchset: str) -> bool:
    return (
        manifest.get("upstream", {}).get("commit") == commit
        and manifest.get("patches", {}).get("set_sha256") == patchset
        and manifest.get("capability") == CAPABILITY
        and manifest.get("build_profile") == BUILD_PROFILE
    )


def safe_env_line(name: str, value: str) -> str:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or not SAFE_ENV_RE.fullmatch(value):
        raise PipelineError(f"unsafe build environment value for {name}")
    return f"{name}={value}\n"


def discover(args: argparse.Namespace) -> int:
    repository_root = args.repository_root.resolve()
    patches = read_patch_rows(repository_root)
    patchset = patchset_sha256(patches)
    upstream_tag = latest_official_release()
    upstream_commit, epoch, commit_time, go_version = official_git_metadata(upstream_tag)
    patch_commit = git_output(repository_root, "rev-parse", "HEAD")
    if not HEX40_RE.fullmatch(patch_commit):
        raise PipelineError("patch repository HEAD is not a full commit SHA")

    forgejo_token = str(os.environ.get("FORGEJO_TOKEN") or "").strip()
    releases = list_forgejo_releases(args.forgejo_releases_url, token=forgejo_token)
    editions: list[int] = []
    matching_candidate = ""
    matching_candidate_needs_resume = False
    matching_proven = ""
    for release in releases:
        tag = str(release.get("tag_name") or "").strip()
        proven_match = PROVEN_RE.fullmatch(tag)
        candidate_match = CANDIDATE_RE.fullmatch(tag)
        match = proven_match or candidate_match
        if match and match.group(1) == upstream_tag:
            editions.append(int(match.group("edition")))
        if (
            candidate_match
            and candidate_match.group(1) == upstream_tag
            and release.get("prerelease")
            and release.get("draft")
            and str(release.get("target_commitish") or "") == patch_commit
        ):
            matching_candidate = tag
            matching_candidate_needs_resume = True
        manifest = read_release_manifest(release, token=forgejo_token)
        if manifest is None or not same_source_and_patches(manifest, upstream_commit, patchset):
            continue
        if not release.get("prerelease") and PROVEN_RE.fullmatch(tag):
            matching_proven = tag
        elif release.get("prerelease") and CANDIDATE_RE.fullmatch(tag):
            matching_candidate = tag
            matching_candidate_needs_resume = bool(release.get("draft"))

    action = "build"
    if matching_proven and not args.force:
        action = "noop"
        candidate_tag = ""
        proven_tag = matching_proven
    elif matching_candidate and not args.force:
        action = "build" if matching_candidate_needs_resume else "noop"
        candidate_tag = matching_candidate
        manifest_release = next(
            item for item in releases if str(item.get("tag_name") or "") == matching_candidate
        )
        existing_manifest = read_release_manifest(manifest_release, token=forgejo_token)
        if existing_manifest is not None:
            proven_tag = str(existing_manifest["release"]["proven_tag"])
        else:
            candidate_match = CANDIDATE_RE.fullmatch(matching_candidate)
            assert candidate_match is not None
            proven_tag = (
                f"{candidate_match.group(1)}-vpnbot.{candidate_match.group('edition')}"
            )
    else:
        edition = max(editions, default=0) + 1
        proven_tag = f"{upstream_tag}-vpnbot.{edition}"
        candidate_tag = f"{proven_tag}-candidate.1"

    values = {
        "PIPELINE_ACTION": action,
        "XRAY_UPSTREAM_REPOSITORY": OFFICIAL_REPOSITORY,
        "XRAY_UPSTREAM_TAG": upstream_tag,
        "XRAY_UPSTREAM_COMMIT": upstream_commit,
        "VPNBOT_RELEASE_TAG": proven_tag,
        "VPNBOT_CANDIDATE_TAG": candidate_tag or "none",
        "GO_VERSION": go_version,
        "SOURCE_DATE_EPOCH": str(epoch),
        "PATCHSET_SHA256": patchset,
        "PATCH_REPOSITORY_COMMIT": patch_commit,
    }
    env_payload = "".join(safe_env_line(name, value) for name, value in values.items()).encode("utf-8")
    write_atomic(args.output_env, env_payload)

    metadata = {
        "action": action,
        "official_release_feed": OFFICIAL_RELEASES_FEED,
        "upstream": {
            "repository": OFFICIAL_REPOSITORY,
            "tag": upstream_tag,
            "commit": upstream_commit,
            "commit_time": commit_time,
            "source_date_epoch": epoch,
        },
        "patch_repository_commit": patch_commit,
        "patches": {"set_sha256": patchset, "items": patches},
        "release": {"candidate_tag": candidate_tag or None, "proven_tag": proven_tag},
        "go_version": go_version,
    }
    write_atomic(args.output_metadata, canonical_json_bytes(metadata))
    print(
        f"pipeline_action={action} upstream={upstream_tag} commit={upstream_commit} "
        f"candidate={candidate_tag or '<existing>'} proven={proven_tag}"
    )
    return 0


def parse_build_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        if "=" not in raw_line:
            raise PipelineError(f"invalid build env row {number}")
        name, value = raw_line.split("=", 1)
        if name in values or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or not SAFE_ENV_RE.fullmatch(value):
            raise PipelineError(f"unsafe build env row {number}")
        values[name] = value
    required = {
        "XRAY_UPSTREAM_REPOSITORY",
        "XRAY_UPSTREAM_TAG",
        "XRAY_UPSTREAM_COMMIT",
        "VPNBOT_RELEASE_TAG",
        "VPNBOT_CANDIDATE_TAG",
        "GO_VERSION",
        "SOURCE_DATE_EPOCH",
        "PATCHSET_SHA256",
        "PATCH_REPOSITORY_COMMIT",
    }
    missing = sorted(required - values.keys())
    if missing:
        raise PipelineError(f"build env misses: {', '.join(missing)}")
    return values


def manifest_command(args: argparse.Namespace) -> int:
    root = args.repository_root.resolve()
    values = parse_build_env(args.build_env)
    patches = read_patch_rows(root)
    calculated_patchset = patchset_sha256(patches)
    if calculated_patchset != values["PATCHSET_SHA256"]:
        raise PipelineError("patch set changed after discovery")
    if git_output(root, "rev-parse", "HEAD") != values["PATCH_REPOSITORY_COMMIT"]:
        raise PipelineError("patch repository HEAD changed after discovery")
    if values["VPNBOT_CANDIDATE_TAG"] == "none":
        raise PipelineError("cannot create a manifest for a no-op release")

    expected_names = {
        "Xray-linux-64.zip",
        "Xray-linux-64.zip.dgst",
        "Xray-linux-64-v3.zip",
        "Xray-linux-64-v3.zip.dgst",
        "Xray-linux-arm64-v8a.zip",
        "Xray-linux-arm64-v8a.zip.dgst",
        "Xray-linux-arm32-v7a.zip",
        "Xray-linux-arm32-v7a.zip.dgst",
    }
    actual_files = {path.name: path for path in args.assets_dir.iterdir() if path.is_file() and not path.is_symlink()}
    if set(actual_files) != expected_names:
        raise PipelineError(
            f"release asset set mismatch: expected={sorted(expected_names)} actual={sorted(actual_files)}"
        )
    assets = {}
    for name, path in sorted(actual_files.items()):
        metadata: dict[str, Any] = {
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        if name in ARTIFACT_PROFILES:
            metadata.update(ARTIFACT_PROFILES[name])
        assets[name] = metadata
    epoch = int(values["SOURCE_DATE_EPOCH"])
    commit_time = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "capability": CAPABILITY,
        "build_profile": BUILD_PROFILE,
        "upstream": {
            "repository": values["XRAY_UPSTREAM_REPOSITORY"],
            "tag": values["XRAY_UPSTREAM_TAG"],
            "commit": values["XRAY_UPSTREAM_COMMIT"],
            "commit_time": commit_time,
            "source_date_epoch": epoch,
        },
        "patch_repository": {"commit": values["PATCH_REPOSITORY_COMMIT"]},
        "patches": {"set_sha256": calculated_patchset, "items": patches},
        "release": {
            "candidate_tag": values["VPNBOT_CANDIDATE_TAG"],
            "proven_tag": values["VPNBOT_RELEASE_TAG"],
        },
        "toolchain": {"go_version": values["GO_VERSION"]},
        "assets": assets,
    }
    validate_manifest(manifest)
    output = args.assets_dir / MANIFEST_NAME
    write_atomic(output, canonical_json_bytes(manifest))
    print(f"wrote {output} sha256={sha256_file(output)}")
    return 0


def validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") not in {1, SCHEMA_VERSION}:
        raise PipelineError("unsupported release manifest schema")
    schema_version = int(manifest["schema_version"])
    if manifest.get("capability") != CAPABILITY:
        raise PipelineError("release manifest capability mismatch")
    if schema_version == SCHEMA_VERSION and manifest.get("build_profile") != BUILD_PROFILE:
        raise PipelineError("release manifest build profile mismatch")
    upstream = manifest.get("upstream")
    release = manifest.get("release")
    patches = manifest.get("patches")
    assets = manifest.get("assets")
    patch_repository = manifest.get("patch_repository")
    if not all(isinstance(item, dict) for item in (upstream, release, patches, assets, patch_repository)):
        raise PipelineError("release manifest object structure is invalid")
    if upstream.get("repository") != OFFICIAL_REPOSITORY:
        raise PipelineError("release manifest points to a non-official upstream")
    if not TAG_RE.fullmatch(str(upstream.get("tag") or "")):
        raise PipelineError("release manifest upstream tag is invalid")
    if not HEX40_RE.fullmatch(str(upstream.get("commit") or "")):
        raise PipelineError("release manifest upstream commit is invalid")
    if not HEX40_RE.fullmatch(str(patch_repository.get("commit") or "")):
        raise PipelineError("release manifest patch repository commit is invalid")
    if not HEX64_RE.fullmatch(str(patches.get("set_sha256") or "")):
        raise PipelineError("release manifest patch set hash is invalid")
    items = patches.get("items")
    if not isinstance(items, list) or len(items) != 3:
        raise PipelineError("release manifest must contain exactly three patches")
    for item in items:
        if (
            not isinstance(item, dict)
            or not re.fullmatch(r"[0-9]{4}-[A-Za-z0-9._-]+\.patch", str(item.get("name") or ""))
            or not HEX64_RE.fullmatch(str(item.get("sha256") or ""))
        ):
            raise PipelineError("release manifest contains an invalid patch row")
    candidate_tag = str(release.get("candidate_tag") or "")
    proven_tag = str(release.get("proven_tag") or "")
    if not CANDIDATE_RE.fullmatch(candidate_tag) or not PROVEN_RE.fullmatch(proven_tag):
        raise PipelineError("release manifest candidate/proven tag is invalid")
    if not candidate_tag.startswith(f"{proven_tag}-candidate."):
        raise PipelineError("candidate tag does not belong to proven tag")
    if not isinstance(assets, dict) or not assets:
        raise PipelineError("release manifest contains no assets")
    if schema_version == 1:
        expected_asset_names = {
            "Xray-linux-64.zip",
            "Xray-linux-64.zip.dgst",
            "Xray-linux-arm64-v8a.zip",
            "Xray-linux-arm64-v8a.zip.dgst",
            "Xray-linux-arm32-v7a.zip",
            "Xray-linux-arm32-v7a.zip.dgst",
        }
    else:
        expected_asset_names = set(ARTIFACT_PROFILES) | {
            f"{name}.dgst" for name in ARTIFACT_PROFILES
        }
    if set(assets) != expected_asset_names:
        raise PipelineError("release manifest asset set does not match build profile")
    for name, item in assets.items():
        if name not in expected_asset_names:
            raise PipelineError(f"release manifest contains unexpected asset: {name}")
        if (
            not isinstance(item, dict)
            or not HEX64_RE.fullmatch(str(item.get("sha256") or ""))
            or not isinstance(item.get("size"), int)
            or item["size"] <= 0
        ):
            raise PipelineError(f"release manifest asset metadata is invalid: {name}")
        if schema_version == SCHEMA_VERSION and name in ARTIFACT_PROFILES:
            expected_profile = ARTIFACT_PROFILES[name]
            actual_profile = {
                key: item.get(key)
                for key in (
                    "goarch",
                    "goamd64",
                    "cpu_profile",
                    "required_linux_cpu_flags",
                )
            }
            if actual_profile != expected_profile:
                raise PipelineError(
                    f"release manifest CPU profile is invalid: {name}"
                )


def token_from_environment() -> str:
    token = str(os.environ.get("FORGEJO_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()
    if not token:
        raise PipelineError("FORGEJO_TOKEN is required")
    if any(character.isspace() for character in token):
        raise PipelineError("FORGEJO_TOKEN contains whitespace")
    return token


def release_by_tag(releases_url: str, tag: str, *, token: str) -> dict[str, Any] | None:
    url = f"{releases_url.rstrip('/')}/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        payload = request_json(url, token=token)
    except PipelineError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    if not isinstance(payload, dict):
        raise PipelineError(f"Forgejo returned a non-release for tag {tag}")
    return payload


def create_release(
    releases_url: str,
    *,
    token: str,
    tag: str,
    target: str,
    prerelease: bool,
    title: str,
    body: str,
    draft: bool = True,
) -> dict[str, Any]:
    payload = request_json(
        releases_url.rstrip("/"),
        token=token,
        method="POST",
        payload={
            "tag_name": tag,
            "target_commitish": target,
            "name": title,
            "body": body,
            "draft": draft,
            "prerelease": prerelease,
            "hide_archive_links": True,
        },
    )
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), int):
        raise PipelineError(f"Forgejo did not create release {tag}")
    return payload


def publish_release(
    releases_url: str,
    release: dict[str, Any],
    *,
    token: str,
    prerelease: bool,
) -> dict[str, Any]:
    payload = request_json(
        f"{releases_url.rstrip('/')}/{int(release['id'])}",
        token=token,
        method="PATCH",
        payload={"draft": False, "prerelease": prerelease},
    )
    if (
        not isinstance(payload, dict)
        or payload.get("draft")
        or bool(payload.get("prerelease")) != prerelease
    ):
        raise PipelineError(f"Forgejo did not publish release {release.get('tag_name')}")
    return payload


def multipart_attachment(name: str, payload: bytes) -> tuple[bytes, str]:
    boundary = f"vpnbot-{uuid.uuid4().hex}"
    content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(
        (
            f'Content-Disposition: form-data; name="attachment"; filename="{name}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode()
    )
    body.extend(payload)
    body.extend(f"\r\n--{boundary}--\r\n".encode())
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def upload_asset(releases_url: str, release_id: int, name: str, payload: bytes, *, token: str) -> None:
    body, content_type = multipart_attachment(name, payload)
    url = (
        f"{releases_url.rstrip('/')}/{release_id}/assets?"
        + urllib.parse.urlencode({"name": name})
    )
    raw = request_bytes(
        url,
        token=token,
        method="POST",
        payload=body,
        content_type=content_type,
        timeout=300,
    )
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PipelineError(f"Forgejo returned invalid upload response for {name}") from exc
    if not isinstance(decoded, dict) or str(decoded.get("name") or "") != name:
        raise PipelineError(f"Forgejo did not accept release asset {name}")


def ensure_release_assets(
    releases_url: str,
    release: dict[str, Any],
    expected: dict[str, bytes],
    *,
    token: str,
) -> None:
    existing = release_assets(release)
    unexpected = sorted(set(existing) - set(expected))
    if unexpected:
        raise PipelineError(
            f"release {release.get('tag_name')} contains unexpected assets: {', '.join(unexpected)}"
        )
    for name, payload in sorted(expected.items()):
        current = existing.get(name)
        if current is not None:
            downloaded = request_bytes(asset_url(current), token=token, timeout=300)
            if sha256_bytes(downloaded) != sha256_bytes(payload):
                raise PipelineError(f"existing release asset differs from local bytes: {name}")
            continue
        upload_asset(releases_url, int(release["id"]), name, payload, token=token)


def candidate_notes(manifest: dict[str, Any]) -> str:
    return (
        "Автоматически собранный кандидат VPnBot из точного официального "
        f"XTLS/Xray-core {manifest['upstream']['tag']} ({manifest['upstream']['commit']}).\n\n"
        "Этот prerelease не предназначен для стабильного канала. Он станет proven-релизом "
        "только после живого пилота на выделенном production-узле. Архивы при продвижении "
        "не пересобираются."
    )


def publish_candidate(args: argparse.Namespace) -> int:
    token = token_from_environment()
    manifest_path = args.assets_dir / MANIFEST_NAME
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    tag = str(manifest["release"]["candidate_tag"])
    expected = {
        name: (args.assets_dir / name).read_bytes()
        for name in manifest["assets"]
    }
    expected[MANIFEST_NAME] = manifest_path.read_bytes()
    release = release_by_tag(args.forgejo_releases_url, tag, token=token)
    if release is None:
        release = create_release(
            args.forgejo_releases_url,
            token=token,
            tag=tag,
            target=str(manifest["patch_repository"]["commit"]),
            prerelease=True,
            title=f"{tag} — candidate",
            body=candidate_notes(manifest),
        )
    if not release.get("prerelease"):
        raise PipelineError(f"candidate tag {tag} is not a prerelease")
    ensure_release_assets(args.forgejo_releases_url, release, expected, token=token)
    if release.get("draft"):
        release = publish_release(
            args.forgejo_releases_url,
            release,
            token=token,
            prerelease=True,
        )
    if release.get("draft") or not release.get("prerelease"):
        raise PipelineError(f"candidate tag {tag} was not published as a prerelease")
    print(f"candidate release is complete: {tag}")
    return 0


def validated_candidate_payloads(
    candidate: dict[str, Any], *, token: str
) -> tuple[dict[str, Any], bytes, dict[str, bytes]]:
    if not candidate.get("prerelease") or candidate.get("draft"):
        raise PipelineError("candidate release is not a published prerelease")
    assets = release_assets(candidate)
    manifest_asset = assets.get(MANIFEST_NAME)
    if manifest_asset is None:
        raise PipelineError("candidate release has no manifest")
    manifest_bytes = request_bytes(asset_url(manifest_asset), token=token)
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise PipelineError("candidate manifest is invalid JSON") from exc
    validate_manifest(manifest)
    if manifest["release"]["candidate_tag"] != candidate.get("tag_name"):
        raise PipelineError("candidate release tag does not match its manifest")
    payloads: dict[str, bytes] = {}
    expected_names = set(manifest["assets"])
    if not expected_names.issubset(assets):
        raise PipelineError("candidate release is missing manifest-listed assets")
    for name, metadata in manifest["assets"].items():
        raw = request_bytes(asset_url(assets[name]), token=token, timeout=300)
        if len(raw) != metadata["size"] or sha256_bytes(raw) != metadata["sha256"]:
            raise PipelineError(f"candidate asset does not match its manifest: {name}")
        payloads[name] = raw
    return manifest, manifest_bytes, payloads


def validate_proof(proof: Any, manifest: dict[str, Any], manifest_bytes: bytes) -> None:
    if not isinstance(proof, dict) or proof.get("schema_version") != 1:
        raise PipelineError("unsupported pilot proof schema")
    if proof.get("result") != "passed":
        raise PipelineError("pilot proof is not passed")
    if proof.get("candidate_tag") != manifest["release"]["candidate_tag"]:
        raise PipelineError("pilot proof candidate tag mismatch")
    if proof.get("manifest_sha256") != sha256_bytes(manifest_bytes):
        raise PipelineError("pilot proof manifest hash mismatch")
    checks = proof.get("checks")
    if not isinstance(checks, dict) or not checks or not all(value is True for value in checks.values()):
        raise PipelineError("pilot proof contains failed or missing checks")


def proven_notes(manifest: dict[str, Any], proof: dict[str, Any]) -> str:
    return (
        "Проверенный VPnBot Xray-core на основе точного официального "
        f"XTLS/Xray-core {manifest['upstream']['tag']} ({manifest['upstream']['commit']}).\n\n"
        f"Candidate {manifest['release']['candidate_tag']} успешно прошёл production-пилот "
        f"на узле {proof.get('canary_node', '<unknown>')}. Архивы скопированы из candidate "
        "без пересборки; их SHA-256 закреплены в манифесте."
    )


def promote(args: argparse.Namespace) -> int:
    token = token_from_environment()
    proof = load_json(args.proof)
    candidate = release_by_tag(args.forgejo_releases_url, args.candidate_tag, token=token)
    if candidate is None:
        raise PipelineError(f"candidate release does not exist: {args.candidate_tag}")
    manifest, manifest_bytes, payloads = validated_candidate_payloads(candidate, token=token)
    validate_proof(proof, manifest, manifest_bytes)
    proven_tag = str(manifest["release"]["proven_tag"])
    proof_bytes = canonical_json_bytes(proof)
    expected = dict(payloads)
    expected[MANIFEST_NAME] = manifest_bytes
    expected[PROOF_NAME] = proof_bytes

    release = release_by_tag(args.forgejo_releases_url, proven_tag, token=token)
    if release is None:
        release = create_release(
            args.forgejo_releases_url,
            token=token,
            tag=proven_tag,
            target=str(manifest["patch_repository"]["commit"]),
            prerelease=False,
            title=f"{proven_tag} — proven",
            body=proven_notes(manifest, proof),
        )
    if release.get("prerelease"):
        raise PipelineError(f"proven tag {proven_tag} is marked as a prerelease")
    ensure_release_assets(args.forgejo_releases_url, release, expected, token=token)

    refreshed_candidate = release_by_tag(args.forgejo_releases_url, args.candidate_tag, token=token)
    if refreshed_candidate is None:
        raise PipelineError("candidate disappeared while it was being promoted")
    refreshed_manifest, refreshed_bytes, _ = validated_candidate_payloads(refreshed_candidate, token=token)
    if refreshed_manifest != manifest or sha256_bytes(refreshed_bytes) != sha256_bytes(manifest_bytes):
        raise PipelineError("candidate manifest changed while it was being promoted")
    if release.get("draft"):
        release = publish_release(
            args.forgejo_releases_url,
            release,
            token=token,
            prerelease=False,
        )
    if release.get("draft") or release.get("prerelease"):
        raise PipelineError(f"proven tag {proven_tag} was not published as stable")
    print(f"proven release is complete: {proven_tag}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover", help="resolve the newest official Xray release")
    discover_parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parent.parent)
    discover_parser.add_argument("--forgejo-releases-url", required=True)
    discover_parser.add_argument("--output-env", type=Path, required=True)
    discover_parser.add_argument("--output-metadata", type=Path, required=True)
    discover_parser.add_argument("--force", action="store_true")
    discover_parser.set_defaults(func=discover)

    manifest_parser = subparsers.add_parser("manifest", help="write the immutable candidate manifest")
    manifest_parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parent.parent)
    manifest_parser.add_argument("--build-env", type=Path, required=True)
    manifest_parser.add_argument("--assets-dir", type=Path, required=True)
    manifest_parser.set_defaults(func=manifest_command)

    publish_parser = subparsers.add_parser("publish-candidate", help="publish or verify a candidate release")
    publish_parser.add_argument("--forgejo-releases-url", required=True)
    publish_parser.add_argument("--assets-dir", type=Path, required=True)
    publish_parser.set_defaults(func=publish_candidate)

    promote_parser = subparsers.add_parser("promote", help="copy a proven candidate to a stable release")
    promote_parser.add_argument("--forgejo-releases-url", required=True)
    promote_parser.add_argument("--candidate-tag", required=True)
    promote_parser.add_argument("--proof", type=Path, required=True)
    promote_parser.set_defaults(func=promote)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except PipelineError as exc:
        print(f"release-pipeline: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
