#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

BUILD_ENV_FILE="${VPNBOT_BUILD_ENV_FILE:-${REPOSITORY_ROOT}/upstream.env}"
[[ -f "$BUILD_ENV_FILE" && ! -L "$BUILD_ENV_FILE" ]] || {
    printf 'prepare-source: build environment is not a regular file: %s\n' "$BUILD_ENV_FILE" >&2
    exit 1
}
# shellcheck source=../upstream.env
source "$BUILD_ENV_FILE"

fail() {
    printf 'prepare-source: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

[[ $# -eq 1 ]] || fail "usage: $0 DESTINATION"
readonly DESTINATION="$1"
[[ -n "$DESTINATION" && "$DESTINATION" != / ]] || fail "unsafe destination"

for command_name in git sha256sum find; do
    require_command "$command_name"
done

[[ "$XRAY_UPSTREAM_REPOSITORY" == "https://github.com/XTLS/Xray-core.git" ]] \
    || fail "the Xray source must be the official XTLS GitHub repository"
[[ "$XRAY_UPSTREAM_TAG" =~ ^v[0-9]+([.][0-9]+){2}$ ]] \
    || fail "invalid upstream tag: $XRAY_UPSTREAM_TAG"
[[ "$XRAY_UPSTREAM_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || fail "invalid upstream commit: $XRAY_UPSTREAM_COMMIT"
[[ "${VPNBOT_RELEASE_TAG:-}" =~ ^v[0-9]+([.][0-9]+){2}-vpnbot[.][0-9]+$ ]] \
    || fail "invalid VPnBot proven release tag: ${VPNBOT_RELEASE_TAG:-<unset>}"

if [[ -e "$DESTINATION" ]]; then
    [[ -d "$DESTINATION" && ! -L "$DESTINATION" ]] \
        || fail "destination is not a regular directory"
    [[ -z "$(find "$DESTINATION" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
        || fail "destination is not empty: $DESTINATION"
else
    mkdir -p -- "$DESTINATION"
fi

git -C "$DESTINATION" init -q
git -C "$DESTINATION" remote add origin "$XRAY_UPSTREAM_REPOSITORY"
git -C "$DESTINATION" fetch --quiet --depth 1 origin \
    "refs/tags/${XRAY_UPSTREAM_TAG}:refs/tags/${XRAY_UPSTREAM_TAG}"

resolved_commit="$(git -C "$DESTINATION" rev-parse "${XRAY_UPSTREAM_TAG}^{commit}")"
[[ "$resolved_commit" == "$XRAY_UPSTREAM_COMMIT" ]] \
    || fail "official tag resolves to $resolved_commit instead of $XRAY_UPSTREAM_COMMIT"

git -C "$DESTINATION" checkout -q --detach "$XRAY_UPSTREAM_COMMIT"
git -C "$DESTINATION" config user.name "VPnBot reproducible build"
git -C "$DESTINATION" config user.email "build@zapret.moe"

while read -r expected_digest patch_name extra; do
    [[ -z "${expected_digest}${patch_name}${extra}" ]] && continue
    [[ -z "$extra" && "$expected_digest" =~ ^[0-9a-f]{64}$ ]] \
        || fail "invalid patches/series row"
    [[ "$patch_name" =~ ^[0-9]{4}-[A-Za-z0-9._-]+[.]patch$ ]] \
        || fail "unsafe patch name: $patch_name"
    patch_path="${REPOSITORY_ROOT}/patches/${patch_name}"
    [[ -f "$patch_path" && ! -L "$patch_path" ]] \
        || fail "missing patch: $patch_name"
    printf '%s  %s\n' "$expected_digest" "$patch_path" | sha256sum --check --status - \
        || fail "patch digest mismatch: $patch_name"
    git -C "$DESTINATION" am --quiet --committer-date-is-author-date "$patch_path"
done < "${REPOSITORY_ROOT}/patches/series"

[[ "$(git -C "$DESTINATION" rev-list --count "${XRAY_UPSTREAM_COMMIT}..HEAD")" == 3 ]] \
    || fail "the prepared source does not contain exactly three VPnBot patches"
grep -Fq 'vpnbot-active-revoke-v3' "${DESTINATION}/VPNBOT_ACTIVE_REVOKE.md" \
    || fail "the active-revocation capability marker is missing"
grep -Fq 'VPnBot capability: vpnbot-active-revoke-v3' "${DESTINATION}/core/core.go" \
    || fail "the runtime capability marker is missing"
git -C "$DESTINATION" diff --check "$XRAY_UPSTREAM_COMMIT..HEAD"

printf 'Prepared official XTLS/Xray-core %s with VPnBot capability %s\n' \
    "$XRAY_UPSTREAM_TAG" "vpnbot-active-revoke-v3"
