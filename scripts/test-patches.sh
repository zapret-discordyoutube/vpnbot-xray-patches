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

# 0004: inbounds that receive client sockets from the node's 443 dispatcher, with the race detector.
go test -race -timeout 10m ./transport/internet ./transport/internet/tcp
