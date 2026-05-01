#!/usr/bin/env bash
# debian.sh — CVE-2026-31431 ("Copy Fail") mitigation for Debian.
#
# Same algorithm as ubuntu.sh, but uses Debian's kernel meta-package
# (linux-image-amd64 — adjust to linux-image-arm64 etc. on other arches).
#
# Bumping the patched version: when the Debian Security Tracker lists a
# fixed kernel package, set PATCHED_KERNEL_VERSION to that version and
# update README.md's patch-status table.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- Per-distro constants ------------------------------------------------
EXPECTED_DISTRO_IDS=(debian)
# Architecture-aware default. Override KERNEL_PKG below if you use a custom
# kernel meta-package (e.g. linux-image-cloud-amd64).
KERNEL_PKG="linux-image-$(dpkg --print-architecture 2>/dev/null || echo amd64)"

# See: https://security-tracker.debian.org/tracker/CVE-2026-31431
PATCHED_KERNEL_VERSION="PENDING"

# ---- Per-distro hooks ----------------------------------------------------
distro_running_kernel_version() {
    dpkg-query -W -f='${Version}\n' "linux-image-$(uname -r)" 2>/dev/null || true
}

distro_available_kernel_version() {
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

run_algorithm "$@"
