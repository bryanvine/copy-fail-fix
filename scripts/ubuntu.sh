#!/usr/bin/env bash
# ubuntu.sh — CVE-2026-31431 ("Copy Fail") mitigation for Ubuntu.
#
# What this does, in plain English:
#   1. If running as a non-root user, re-execs itself under sudo.
#   2. Confirms the host is Ubuntu (refuse otherwise unless --force).
#   3. If a patched kernel is already running (per PATCHED_KERNEL_VERSION
#      below), removes any leftover mitigation file and exits.
#   4. Otherwise, asks apt whether a candidate kernel package at or above
#      the patched version is available. If yes, prompts to install it
#      and tells you to reboot.
#   5. If no patched kernel is available yet (or you declined), writes
#      /etc/modprobe.d/cve-2026-31431.conf to blacklist the vulnerable
#      algif_aead module, then verifies via an AF_ALG socket probe.
#
# Bumping the patched version: when Ubuntu publishes a USN with the fix,
# set PATCHED_KERNEL_VERSION below to the package version (e.g. 6.8.0-115.115)
# and update README.md's patch-status table.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- Per-distro constants ------------------------------------------------
EXPECTED_DISTRO_IDS=(ubuntu)
KERNEL_PKG="linux-image-generic"

# Ubuntu has not yet shipped a patched kernel as of repo creation.
# Compare against package version (e.g. "6.8.0-115.115"), matching what
# `dpkg-query -W -f='${Version}'` returns for linux-image-<uname -r>.
# See: https://ubuntu.com/security/CVE-2026-31431
PATCHED_KERNEL_VERSION="PENDING"

# ---- Per-distro hooks ----------------------------------------------------
distro_running_kernel_version() {
    # Resolve the running kernel's package version (not uname -r), so it's
    # directly comparable against PATCHED_KERNEL_VERSION and apt's candidate.
    dpkg-query -W -f='${Version}\n' "linux-image-$(uname -r)" 2>/dev/null || true
}

distro_available_kernel_version() {
    # Returns the candidate version if it is strictly newer than what's
    # currently installed; otherwise returns empty string.
    local current candidate
    current="$(distro_running_kernel_version)"
    candidate="$(LC_ALL=C apt-cache policy "$KERNEL_PKG" 2>/dev/null \
                 | awk '/^[[:space:]]*Candidate:/ {print $2; exit}')"
    if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
        return 0
    fi
    if [[ -n "$current" ]] && ! dpkg --compare-versions "$candidate" gt "$current"; then
        return 0
    fi
    printf '%s\n' "$candidate"
}

distro_install_kernel() {
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y "$KERNEL_PKG"
}

# ---- Run -----------------------------------------------------------------
run_algorithm "$@"
