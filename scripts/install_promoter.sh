#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

if [[ "$(id -u)" -ne 0 ]]; then
    printf 'install-promoter: run as root\n' >&2
    exit 1
fi

install -d -m 0755 /usr/local/libexec/vpnbot-xray-release-promoter
install -m 0755 \
    "${REPOSITORY_ROOT}/scripts/release_pipeline.py" \
    "${REPOSITORY_ROOT}/scripts/canary_active_revoke.py" \
    "${REPOSITORY_ROOT}/scripts/pilot_and_promote.py" \
    "${REPOSITORY_ROOT}/scripts/release_alert_monitor.py" \
    /usr/local/libexec/vpnbot-xray-release-promoter/
install -m 0644 \
    "${REPOSITORY_ROOT}/systemd/vpnbot-xray-release-promoter.service" \
    "${REPOSITORY_ROOT}/systemd/vpnbot-xray-release-promoter.timer" \
    "${REPOSITORY_ROOT}/systemd/vpnbot-xray-release-alert.service" \
    "${REPOSITORY_ROOT}/systemd/vpnbot-xray-release-alert.timer" \
    /etc/systemd/system/
install -d -m 0700 /var/lib/vpnbot-xray-release-promoter
install -d -m 0700 /var/lib/vpnbot-xray-release-alert
systemctl daemon-reload

if [[ -f /etc/vpnbot-xray-release-promoter.env ]]; then
    chmod 0600 /etc/vpnbot-xray-release-promoter.env
    systemctl enable --now vpnbot-xray-release-promoter.timer
    printf 'Installed and enabled vpnbot-xray-release-promoter.timer\n'
else
    printf '%s\n' \
        'Installed promoter files, but the timer was not enabled.' \
        'Create /etc/vpnbot-xray-release-promoter.env from the example, then run:' \
        'systemctl enable --now vpnbot-xray-release-promoter.timer'
fi

if [[ -f /etc/vpnbot-xray-release-alert.env ]]; then
    chmod 0600 /etc/vpnbot-xray-release-alert.env
    systemctl enable --now vpnbot-xray-release-alert.timer
    printf 'Installed and enabled vpnbot-xray-release-alert.timer\n'
else
    printf '%s\n' \
        'Installed release alert files, but the timer was not enabled.' \
        'Create /etc/vpnbot-xray-release-alert.env from the example, then run:' \
        'systemctl enable --now vpnbot-xray-release-alert.timer'
fi
