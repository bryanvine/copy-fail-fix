#!/usr/bin/env bash
# opensuse.sh — CVE-2026-31431 ("Copy Fail") mitigation for openSUSE Leap
# and Tumbleweed.
#
# Uses zypper. KERNEL_PKG defaults to kernel-default; override to
# kernel-default-base, kernel-azure, etc. if you run a flavor.
# See: https://www.suse.com/security/cve/CVE-2026-31431/

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

EXPECTED_DISTRO_IDS=(opensuse-leap opensuse-tumbleweed opensuse sles)
KERNEL_PKG="kernel-default"

PATCHED_KERNEL_VERSION="PENDING"

distro_running_kernel_version() {
    rpm -q --queryformat '%{VERSION}-%{RELEASE}\n' "$KERNEL_PKG" 2>/dev/null \
        | head -n1 || true
}

distro_available_kernel_version() {
    local sync_ver current
    sync_ver="$(LC_ALL=C zypper --non-interactive info "$KERNEL_PKG" 2>/dev/null \
                 | awk -F': *' '/^Version/ {print $2; exit}')"
    [[ -z "$sync_ver" ]] && return 0
    current="$(distro_running_kernel_version)"
    if [[ -n "$current" ]] && [[ "$(LC_ALL=C rpm --eval "%{lua: print(rpm.vercmp(\"$sync_ver\", \"$current\"))}")" -le 0 ]]; then
        return 0
    fi
    printf '%s\n' "$sync_ver"
}

distro_install_kernel() {
    zypper --non-interactive update "$KERNEL_PKG"
}

run_algorithm "$@"
