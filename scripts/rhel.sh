#!/usr/bin/env bash
# rhel.sh — CVE-2026-31431 ("Copy Fail") mitigation for RHEL/Rocky/AlmaLinux.
#
# Algorithm: see lib.sh's run_algorithm. Uses dnf to query and install the
# kernel package. The "kernel" package on RHEL installs a versioned kernel
# alongside the running one rather than upgrading in-place, but `dnf upgrade
# kernel` is the correct command — it adds a new kernel version that becomes
# the default after reboot.
#
# Bumping the patched version: see the Red Hat CVE tracker for the fixed
# RHEL kernel version (e.g. 4.18.0-553.30.1.el8_10) and set below.
# See: https://access.redhat.com/security/cve/CVE-2026-31431

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- Per-distro constants ------------------------------------------------
# rhel covers the RHEL family. Rocky/AlmaLinux declare ID_LIKE="rhel ...",
# which assert_distro accepts.
EXPECTED_DISTRO_IDS=(rhel rocky almalinux centos)
KERNEL_PKG="kernel"

PATCHED_KERNEL_VERSION="PENDING"

# ---- Per-distro hooks ----------------------------------------------------
distro_running_kernel_version() {
    # rpm version-release of the running kernel. Format e.g. 4.18.0-553.30.1.el8_10
    rpm -q --queryformat '%{VERSION}-%{RELEASE}\n' "kernel-$(uname -r)" 2>/dev/null \
        | head -n1 || true
}

distro_available_kernel_version() {
    # `dnf check-update` exits 100 when updates are available, 0 if none.
    # We want the candidate version of the kernel package only.
    local out
    out="$(LC_ALL=C dnf -q list --upgrades "$KERNEL_PKG" 2>/dev/null | tail -n +2 || true)"
    [[ -z "$out" ]] && return 0
    awk '$1 ~ /^kernel\./ {print $2; exit}' <<<"$out"
}

distro_install_kernel() {
    dnf -y upgrade "$KERNEL_PKG"
}

run_algorithm "$@"
