#!/usr/bin/env bash
# shellcheck shell=bash
# Shared library for copy-fail-fix scripts.
# Sourced by every per-distro script and by universal.sh.
# Do NOT execute directly.

# Guard against accidental execution.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "lib.sh is meant to be sourced, not executed." >&2
    exit 64
fi

set -euo pipefail

# ---------------------------------------------------------------------------
# CLI flag state. Defaults; parse_args may flip these.
# ---------------------------------------------------------------------------
CFF_YES=0
CFF_FORCE=0
CFF_CHECK=0
CFF_UNDO=0

# shellcheck disable=SC2034  # used by Task 3 (mitigation actions)
CFF_MITIGATION_FILE="/etc/modprobe.d/cve-2026-31431.conf"

# ---------------------------------------------------------------------------
# Logging helpers. Coloured when stdout is a TTY.
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    _CFF_BOLD=$'\033[1m'; _CFF_RED=$'\033[31m'; _CFF_YEL=$'\033[33m'
    _CFF_GRN=$'\033[32m'; _CFF_DIM=$'\033[2m'; _CFF_RST=$'\033[0m'
else
    _CFF_BOLD=""; _CFF_RED=""; _CFF_YEL=""; _CFF_GRN=""; _CFF_DIM=""; _CFF_RST=""
fi

cff_info()  { printf '%b[*]%b %s\n' "$_CFF_BOLD"  "$_CFF_RST" "$*"; }
cff_ok()    { printf '%b[+]%b %s\n' "$_CFF_GRN"   "$_CFF_RST" "$*"; }
cff_warn()  { printf '%b[!]%b %s\n' "$_CFF_YEL"   "$_CFF_RST" "$*" >&2; }
cff_err()   { printf '%b[x]%b %s\n' "$_CFF_RED"   "$_CFF_RST" "$*" >&2; }
cff_dim()   { printf '%b%s%b\n'     "$_CFF_DIM"   "$*" "$_CFF_RST"; }

# Print "would: <cmd>" in --check mode, otherwise run the command.
cff_run() {
    if (( CFF_CHECK )); then
        cff_dim "would run: $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing. Supports -y/--yes, --force, --check, --undo, -h/--help.
# Unknown flags are an error.
# ---------------------------------------------------------------------------
parse_args() {
    # shellcheck disable=SC2034  # CFF_UNDO/CFF_MITIGATION_FILE used by later tasks
    while (( $# )); do
        case "$1" in
            -y|--yes)   CFF_YES=1 ;;
            --force)    CFF_FORCE=1 ;;
            --check)    CFF_CHECK=1 ;;
            --undo)     CFF_UNDO=1 ;;
            -h|--help)
                cff_print_help
                exit 0
                ;;
            *)
                cff_err "unknown flag: $1"
                cff_print_help >&2
                exit 64
                ;;
        esac
        shift
    done
}

cff_print_help() {
    cat <<EOF
Usage: $(basename "${0}") [flags]

Mitigates CVE-2026-31431 ("Copy Fail") on this host. Installs the patched
kernel for your distro if available, otherwise blacklists the vulnerable
algif_aead module.

Flags:
  -y, --yes      Non-interactive; do not prompt before installing kernel.
      --force    Bypass distro-mismatch check.
      --check    Read-only preview. Print actions without changing anything.
      --undo     Remove the modprobe mitigation file (use after kernel patch).
  -h, --help     This help.
EOF
}

# ---------------------------------------------------------------------------
# Privilege.
# ---------------------------------------------------------------------------
require_root() {
    if (( EUID == 0 )); then
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        cff_info "re-executing under sudo..."
        exec sudo -E -- "$0" "$@"
    fi
    cff_err "this script must run as root and sudo is not available."
    exit 77
}

# ---------------------------------------------------------------------------
# Distro detection. Sources /etc/os-release into _CFF_OS_*.
# ---------------------------------------------------------------------------
detect_distro() {
    if [[ ! -r /etc/os-release ]]; then
        cff_err "/etc/os-release not readable; cannot determine distro."
        exit 65
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    _CFF_OS_ID="${ID:-unknown}"
    _CFF_OS_LIKE="${ID_LIKE:-}"
    _CFF_OS_VER="${VERSION_ID:-}"
}

# Verify the running script matches the host distro.
# Usage: assert_distro ubuntu  OR  assert_distro rhel rocky almalinux
assert_distro() {
    detect_distro
    local id
    for id in "$@"; do
        if [[ "$_CFF_OS_ID" == "$id" ]]; then
            return 0
        fi
        # Also accept distros that declare ID_LIKE matching (e.g., Rocky has ID_LIKE="rhel fedora")
        if [[ " $_CFF_OS_LIKE " == *" $id "* ]]; then
            return 0
        fi
    done
    cff_warn "this script is for: $* — host reports ID=$_CFF_OS_ID"
    if (( CFF_FORCE )); then
        cff_warn "--force given; continuing anyway."
        return 0
    fi
    cff_err "refusing to run on a non-matching distro. Pass --force to override."
    exit 65
}

# ---------------------------------------------------------------------------
# Version comparison. Returns 0 if $1 >= $2.
# Uses dpkg --compare-versions when available (handles Debian-style epochs);
# falls back to sort -V otherwise.
# ---------------------------------------------------------------------------
kver_ge() {
    local a="$1" b="$2"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg --compare-versions "$a" ge "$b"
        return
    fi
    local smallest
    smallest=$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n 1)
    [[ "$smallest" == "$b" ]]
}

# ---------------------------------------------------------------------------
# y/N prompt. Honours CFF_YES (always yes) and non-TTY stdin (defaults to no
# unless CFF_YES is set).
# ---------------------------------------------------------------------------
prompt_yes_no() {
    local msg="$1"
    if (( CFF_YES )); then
        cff_dim "$msg [auto-yes]"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        cff_warn "non-interactive (no TTY); refusing without --yes."
        return 1
    fi
    local reply
    read -r -p "$msg [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}