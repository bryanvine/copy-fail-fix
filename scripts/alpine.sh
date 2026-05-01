#!/usr/bin/env bash
# alpine.sh — CVE-2026-31431 ("Copy Fail") mitigation for Alpine Linux.
#
# Alpine ships several kernel flavors; this script defaults to linux-lts
# (the standard server choice). Override KERNEL_PKG to linux-virt for
# minimal VMs or linux-edge for edge releases.
# See: https://secdb.alpinelinux.org/

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

EXPECTED_DISTRO_IDS=(alpine)
KERNEL_PKG="linux-lts"

PATCHED_KERNEL_VERSION="PENDING"

distro_running_kernel_version() {
    # apk's installed-version syntax, e.g. "6.6.71-r0".
    apk info -v "$KERNEL_PKG" 2>/dev/null | sed -E "s/^${KERNEL_PKG}-//;q" || true
}

distro_available_kernel_version() {
    # `apk version` shows current vs. available. With -l '<' it lists
    # packages that have a newer version available.
    apk update >/dev/null 2>&1 || true
    local line
    line="$(apk version -l '<' 2>/dev/null | awk -v p="$KERNEL_PKG" '$1 ~ "^"p"-" {print; exit}')"
    [[ -z "$line" ]] && return 0
    # Format: "linux-lts-6.6.71-r0 < 6.6.75-r0"
    awk '{print $3}' <<<"$line"
}

distro_install_kernel() {
    apk add --upgrade "$KERNEL_PKG"
}

run_algorithm "$@"
