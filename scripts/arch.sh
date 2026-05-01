#!/usr/bin/env bash
# arch.sh — CVE-2026-31431 ("Copy Fail") mitigation for Arch Linux.
#
# Arch is rolling; the patched kernel typically arrives within days of
# upstream. This script queries pacman for the currently installed and
# available `linux` package versions.
#
# If you run a different kernel package (linux-lts, linux-zen, linux-hardened),
# override KERNEL_PKG below.
# See: https://security.archlinux.org/CVE-2026-31431

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

EXPECTED_DISTRO_IDS=(arch)
KERNEL_PKG="linux"

PATCHED_KERNEL_VERSION="PENDING"

distro_running_kernel_version() {
    # pacman version of the installed kernel package, e.g. "6.8.9.arch1-1".
    LC_ALL=C pacman -Q "$KERNEL_PKG" 2>/dev/null | awk '{print $2}' || true
}

distro_available_kernel_version() {
    # Refresh repo metadata, then ask pacman for the sync version.
    # We compare with vercmp against the installed version below.
    pacman -Sy --noconfirm >/dev/null 2>&1 || true
    local sync_ver
    sync_ver="$(LC_ALL=C pacman -Si "$KERNEL_PKG" 2>/dev/null | awk -F': *' '$1=="Version" {print $2; exit}')"
    [[ -z "$sync_ver" ]] && return 0
    local current
    current="$(distro_running_kernel_version)"
    if [[ -n "$current" ]] && [[ "$(LC_ALL=C vercmp "$sync_ver" "$current")" -le 0 ]]; then
        return 0
    fi
    printf '%s\n' "$sync_ver"
}

distro_install_kernel() {
    pacman -S --noconfirm "$KERNEL_PKG"
}

run_algorithm "$@"
