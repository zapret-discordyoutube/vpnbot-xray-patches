#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
TEMP_DIRECTORY="$(mktemp -d)"
readonly TEMP_DIRECTORY
trap 'rm -rf -- "$TEMP_DIRECTORY"' EXIT HUP INT TERM

"${SCRIPT_DIR}/prepare-source.sh" "${TEMP_DIRECTORY}/xray"

cd "${TEMP_DIRECTORY}/xray"
go test -timeout 30m \
    ./common \
    ./main/commands/all/api \
    ./proxy/vless/inbound \
    ./proxy/trojan \
    ./proxy/vmess/inbound \
    ./proxy/shadowsocks

go test -timeout 30m ./testing/scenarios \
    -run 'TestCommanderRemove(Trojan|VMess|Shadowsocks)UserInterrupts'
