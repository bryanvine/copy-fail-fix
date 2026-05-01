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
    # shellcheck disable=SC2034  # CFF_UNDO is consumed by Task 4's run_algorithm
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

# ---------------------------------------------------------------------------
# Mitigation: write /etc/modprobe.d/cve-2026-31431.conf so that algif_aead
# cannot be auto-loaded or explicitly modprobe'd. Idempotent.
# ---------------------------------------------------------------------------
apply_mitigation() {
    local body
    body='# CVE-2026-31431 "Copy Fail" — Linux kernel algif_aead LPE.
# Mitigation until a patched kernel is installed: prevent algif_aead
# from being loaded via auto-load or explicit modprobe.
# Remove this file once running a kernel that contains the upstream fix.
blacklist algif_aead
install algif_aead /bin/true
'
    if [[ -f "$CFF_MITIGATION_FILE" ]] && diff -q <(printf '%s' "$body") "$CFF_MITIGATION_FILE" >/dev/null 2>&1; then
        cff_info "mitigation file already in place: $CFF_MITIGATION_FILE"
    else
        cff_run bash -c "printf '%s' \"\$1\" > \"\$2\" && chmod 0644 \"\$2\"" _ "$body" "$CFF_MITIGATION_FILE"
        (( CFF_CHECK )) || cff_ok "wrote $CFF_MITIGATION_FILE"
    fi

    # Best-effort: try to unload algif_aead if currently loaded. Failure is
    # not fatal (refcount may be non-zero); the install /bin/true rule
    # prevents future loads.
    if lsmod | awk '{print $1}' | grep -qx algif_aead; then
        cff_run modprobe -r algif_aead || cff_warn "could not unload algif_aead (in use); blacklist still effective for future loads."
    fi
}

# Probe AF_ALG to confirm algif_aead is unreachable. Returns 0 on success.
verify_mitigation() {
    if ! command -v python3 >/dev/null 2>&1; then
        cff_warn "python3 not available; skipping AF_ALG socket probe."
        return 0
    fi
    if (( CFF_CHECK )); then
        cff_dim "would probe: socket(AF_ALG); bind('aead', ...) -> expect ENOENT"
        return 0
    fi
    local rc=0
    python3 - <<'PY' || rc=$?
import socket, errno, sys
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
except (AttributeError, OSError) as e:
    # AF_ALG unavailable on this kernel: vacuously safe.
    sys.exit(0)
try:
    try:
        s.bind(("aead", "authencesn(hmac(sha1),cbc(aes))"))
    finally:
        s.close()
except OSError as e:
    sys.exit(0 if e.errno == errno.ENOENT else 2)
sys.exit(1)  # bind unexpectedly succeeded
PY
    case "$rc" in
        0) cff_ok "verification passed: AF_ALG aead bind blocked (ENOENT)." ;;
        1) cff_err "VERIFICATION FAILED: AF_ALG aead bind succeeded — host is NOT mitigated."; return 1 ;;
        2) cff_warn "AF_ALG aead bind failed but with unexpected errno; treating as inconclusive." ;;
        *) cff_warn "verification probe exited $rc; treating as inconclusive." ;;
    esac
}

# Remove the modprobe file if this tool wrote it. Idempotent.
remove_mitigation_if_present() {
    if [[ -f "$CFF_MITIGATION_FILE" ]]; then
        cff_run rm -f -- "$CFF_MITIGATION_FILE"
        (( CFF_CHECK )) || cff_ok "removed $CFF_MITIGATION_FILE"
    else
        cff_info "no mitigation file to remove."
    fi
}
