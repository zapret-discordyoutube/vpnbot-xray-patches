#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

# shellcheck source=../upstream.env
source "${REPOSITORY_ROOT}/upstream.env"

fail() {
    printf 'build-release: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

[[ $# -eq 1 ]] || fail "usage: $0 OUTPUT_DIRECTORY"
readonly OUTPUT_ARGUMENT="$1"
[[ -n "$OUTPUT_ARGUMENT" && "$OUTPUT_ARGUMENT" != / ]] || fail "unsafe output directory"

for command_name in curl git go openssl sha256sum touch zip find; do
    require_command "$command_name"
done

if [[ -e "$OUTPUT_ARGUMENT" ]]; then
    [[ -d "$OUTPUT_ARGUMENT" && ! -L "$OUTPUT_ARGUMENT" ]] \
        || fail "output path is not a regular directory"
    [[ -z "$(find "$OUTPUT_ARGUMENT" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
        || fail "output directory is not empty: $OUTPUT_ARGUMENT"
else
    mkdir -p -- "$OUTPUT_ARGUMENT"
fi
OUTPUT_DIRECTORY="$(cd -- "$OUTPUT_ARGUMENT" && pwd -P)"
readonly OUTPUT_DIRECTORY

TEMP_DIRECTORY="$(mktemp -d)"
readonly TEMP_DIRECTORY
trap 'rm -rf -- "$TEMP_DIRECTORY"' EXIT HUP INT TERM

"${SCRIPT_DIR}/prepare-source.sh" "${TEMP_DIRECTORY}/xray"
readonly SOURCE_DIRECTORY="${TEMP_DIRECTORY}/xray"
mkdir -p -- "${TEMP_DIRECTORY}/resources"

for asset in geoip geosite; do
    curl --fail --location --silent --show-error \
        --connect-timeout 15 --max-time 180 --retry 3 --retry-all-errors \
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/${asset}.dat" \
        --output "${TEMP_DIRECTORY}/resources/${asset}.dat"
    [[ -s "${TEMP_DIRECTORY}/resources/${asset}.dat" ]] \
        || fail "downloaded ${asset}.dat is empty"
done

build_target() {
    local archive_name="$1" goarch="$2" goarm="$3"
    local package_directory="${TEMP_DIRECTORY}/${archive_name%.zip}"
    mkdir -p -- "$package_directory"

    (
        cd "$SOURCE_DIRECTORY"
        CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" \
            go build -o "${package_directory}/xray" \
            -trimpath -buildvcs=false -gcflags="all=-l=4" \
            -ldflags="-X github.com/xtls/xray-core/core.build=${VPNBOT_RELEASE_TAG} -s -w -buildid=" \
            ./main
    )

    chmod 0755 "${package_directory}/xray"
    if [[ "$goarch" == amd64 ]]; then
        "${package_directory}/xray" version \
            | grep -Fq 'VPnBot capability: vpnbot-active-revoke-v3' \
            || fail "the built Xray binary does not expose the v3 capability marker"
    fi
    cp -- "${SOURCE_DIRECTORY}/README.md" "${package_directory}/README.md"
    cp -- "${SOURCE_DIRECTORY}/LICENSE" "${package_directory}/LICENSE"
    cp -- "${TEMP_DIRECTORY}/resources/geoip.dat" "${package_directory}/geoip.dat"
    cp -- "${TEMP_DIRECTORY}/resources/geosite.dat" "${package_directory}/geosite.dat"
    touch -d '2026-07-28 00:00:00 UTC' "${package_directory}"/*

    (
        cd "$package_directory"
        zip -X -9 -q "${OUTPUT_DIRECTORY}/${archive_name}" \
            xray geoip.dat geosite.dat README.md LICENSE
    )

    : > "${OUTPUT_DIRECTORY}/${archive_name}.dgst"
    for method in md5 sha1 sha256 sha512; do
        openssl dgst "-${method}" "${OUTPUT_DIRECTORY}/${archive_name}" \
            | sed 's/([^)]*)//g' >> "${OUTPUT_DIRECTORY}/${archive_name}.dgst"
    done
    sha256sum "${OUTPUT_DIRECTORY}/${archive_name}"
}

build_target Xray-linux-64.zip amd64 ""
build_target Xray-linux-arm64-v8a.zip arm64 ""
build_target Xray-linux-arm32-v7a.zip arm 7
