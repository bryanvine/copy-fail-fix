#!/usr/bin/env bash
# fedora.sh — CVE-2026-31431 ("Copy Fail") mitigation for Fedora.
#
# Same dnf-based logic as rhel.sh; separate file so the comments and the
# patch-status table can track Fedora's faster release cadence
# independently. Fedora typically ships kernel patches faster than RHEL.
# See: https://bodhi.fedoraproject.org/

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

EXPECTED_DISTRO_IDS=(fedora)
KERNEL_PKG="kernel"

PATCHED_KERNEL_VERSION="PENDING"

distro_running_kernel_version() {
    rpm -q --queryformat '%{VERSION}-%{RELEASE}\n' "kernel-$(uname -r)" 2>/dev/null \
        | head -n1 || true
}

distro_available_kernel_version() {
    local out
    out="$(LC_ALL=C dnf -q list --upgrades "$KERNEL_PKG" 2>/dev/null | tail -n +2 || true)"
    [[ -z "$out" ]] && return 0
    awk '$1 ~ /^kernel\./ {print $2; exit}' <<<"$out"
}

distro_install_kernel() {
    dnf -y upgrade "$KERNEL_PKG"
}

run_algorithm "$@"
