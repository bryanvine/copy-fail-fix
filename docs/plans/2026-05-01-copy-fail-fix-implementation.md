# copy-fail-fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public GitHub repo containing per-distro shell scripts that mitigate CVE-2026-31431 by either installing a patched kernel (when the distro has shipped one) or applying an `algif_aead` modprobe blacklist.

**Architecture:** A shared `scripts/lib.sh` exposes the universal pieces (root-check, distro-detect, version-compare, mitigation write, AF_ALG verification, and the orchestrating `run_algorithm` function). Each per-distro script is a thin wrapper that sets three constants and three functions, then calls `run_algorithm`. `universal.sh` calls a simpler `run_mitigation_only` for unsupported distros.

**Tech Stack:** Bash 4+, Python 3.6+ (for the AF_ALG socket probe), GitHub Actions + ShellCheck for CI. No external dependencies beyond what every supported distro already ships.

**Spec:** [`docs/specs/2026-04-30-copy-fail-fix-design.md`](../specs/2026-04-30-copy-fail-fix-design.md)

---

## File Structure

| Path | Responsibility |
|---|---|
| `LICENSE` | MIT license. |
| `.gitignore` | Standard Bash/editor noise. |
| `README.md` | TL;DR, per-distro usage, patch-status table, undo, contributing. |
| `scripts/lib.sh` | All shared logic: root-check, distro-detect, version compare, mitigation file write/remove, AF_ALG verification probe, CLI flag parsing, `run_algorithm` and `run_mitigation_only` orchestrators. Sourced by every other script. |
| `scripts/universal.sh` | Mitigation-only fallback. ~10 lines. |
| `scripts/ubuntu.sh` | Ubuntu constants + apt hooks; calls `run_algorithm`. |
| `scripts/debian.sh` | Debian constants + apt hooks. |
| `scripts/rhel.sh` | RHEL/Rocky/AlmaLinux constants + dnf hooks. |
| `scripts/fedora.sh` | Fedora constants + dnf hooks. |
| `scripts/arch.sh` | Arch constants + pacman hooks. |
| `scripts/opensuse.sh` | openSUSE Leap/Tumbleweed constants + zypper hooks. |
| `scripts/alpine.sh` | Alpine constants + apk hooks. |
| `.github/workflows/shellcheck.yml` | Run `shellcheck` on every `.sh` on push/PR. |

---

## Conventions

- Every shell file starts with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Every distro script sources `lib.sh` via `source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"`.
- All version comparisons go through `kver_ge`. Each distro's three hook functions return version strings in the same format as that distro's `PATCHED_KERNEL_VERSION`.
- Commit messages follow `area: short summary` (e.g., `lib: add kernel version comparison`, `ubuntu: scaffold per-distro script`). Sign-off lines as in the existing spec commit.
- After each task, run `shellcheck` against any modified `.sh` file. ShellCheck must exit 0.

---

## Task 1: Repository skeleton (LICENSE, .gitignore, README stub)

**Files:**
- Create: `LICENSE`
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Write `LICENSE`**

```text
MIT License

Copyright (c) 2026 Bryan Vine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Write `.gitignore`**

```text
# Editors
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Local artifacts
/tmp/
*.log
```

- [ ] **Step 3: Write `README.md` (stub — full content lands in Task 12)**

```markdown
# copy-fail-fix

Per-distro mitigation scripts for [CVE-2026-31431 ("Copy Fail")](https://ubuntu.com/security/CVE-2026-31431) — a Linux kernel `algif_aead` local privilege escalation.

> Status: under construction. Full README and scripts land shortly.

## License

MIT — see [LICENSE](LICENSE).
```

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add LICENSE .gitignore README.md
git commit -m "chore: repo skeleton (license, gitignore, readme stub)"
```

---

## Task 2: scripts/lib.sh — utilities (root, distro, version, prompts, args)

**Files:**
- Create: `scripts/lib.sh`

- [ ] **Step 1: Create `scripts/lib.sh` with the utility section**

```bash
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
        return $?
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
```

- [ ] **Step 2: Lint**

```bash
cd /apps/copy-fail-fix
shellcheck scripts/lib.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Source-test core helpers in a subshell**

`parse_args` exits the process on `--help` and on unknown flags, so the test
calls must be wrapped in `( ... )` subshells to keep the test driver alive.

```bash
bash -c '
set -euo pipefail
source /apps/copy-fail-fix/scripts/lib.sh

# Version compare smoke tests.
kver_ge "6.8.0-115" "6.8.0-110" || { echo "FAIL ge1"; exit 1; }
kver_ge "6.8.0-110" "6.8.0-110" || { echo "FAIL eq"; exit 1; }
kver_ge "6.8.0-100" "6.8.0-110" && { echo "FAIL lt"; exit 1; } || true

# Help: subshell exits 0; outer shell continues.
( parse_args --help >/dev/null )

# Unknown flag: subshell exits 64; capture rc with the set -e-safe idiom.
rc=0
( parse_args --bogus 2>/dev/null ) || rc=$?
test "$rc" -eq 64 || { echo "FAIL bad flag (rc=$rc)"; exit 1; }

# Distro detect populates vars.
detect_distro
[[ -n "${_CFF_OS_ID:-}" ]] || { echo "FAIL detect"; exit 1; }

echo "lib.sh utilities OK on $_CFF_OS_ID $_CFF_OS_VER"
'
```
Expected: `lib.sh utilities OK on ubuntu 24.04`

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/lib.sh
git commit -m "lib: add utilities (logging, args, root, distro, kver_ge)"
```

---

## Task 3: scripts/lib.sh — mitigation actions

**Files:**
- Modify: `scripts/lib.sh` (append)

- [ ] **Step 1: Append the mitigation block to `scripts/lib.sh`**

Append the following to the end of `scripts/lib.sh`:

```bash

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
        cff_ok "wrote $CFF_MITIGATION_FILE"
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
        cff_ok "removed $CFF_MITIGATION_FILE"
    else
        cff_info "no mitigation file to remove."
    fi
}
```

- [ ] **Step 2: Lint**

```bash
cd /apps/copy-fail-fix
shellcheck scripts/lib.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Source-test the new functions (without trampling the existing prod mitigation file)**

```bash
sudo bash -c '
set -euo pipefail
# Use a sandbox path so we do not touch the real /etc file in this test.
CFF_MITIGATION_FILE_REAL=/etc/modprobe.d/cve-2026-31431.conf
TMPFILE=$(mktemp /tmp/cff-test.XXXXXX.conf)
source /apps/copy-fail-fix/scripts/lib.sh
CFF_MITIGATION_FILE="$TMPFILE"
rm -f "$CFF_MITIGATION_FILE"

apply_mitigation
[[ -f "$CFF_MITIGATION_FILE" ]] || { echo "FAIL: mitigation file not written"; exit 1; }
grep -q "blacklist algif_aead" "$CFF_MITIGATION_FILE" || { echo "FAIL: missing blacklist line"; exit 1; }
grep -q "install algif_aead /bin/true" "$CFF_MITIGATION_FILE" || { echo "FAIL: missing install line"; exit 1; }

# Idempotency: second call should be a no-op.
apply_mitigation

# verify_mitigation should pass (real mitigation already applied to host previously).
verify_mitigation || { echo "FAIL: verify"; exit 1; }

remove_mitigation_if_present
[[ ! -f "$CFF_MITIGATION_FILE" ]] || { echo "FAIL: not removed"; exit 1; }

echo "mitigation actions OK"
'
```
Expected ending in `mitigation actions OK`. The real `/etc/modprobe.d/cve-2026-31431.conf` from prior incident response remains untouched.

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/lib.sh
git commit -m "lib: add apply/verify/remove mitigation actions"
```

---

## Task 4: scripts/lib.sh — orchestration (run_algorithm, run_mitigation_only)

**Files:**
- Modify: `scripts/lib.sh` (append)

- [ ] **Step 1: Append the orchestration block**

Append to the end of `scripts/lib.sh`:

```bash

# ---------------------------------------------------------------------------
# Orchestrators. Distro scripts call run_algorithm; universal.sh calls
# run_mitigation_only.
#
# Contract for run_algorithm:
#   Caller MUST set the following globals before calling:
#     - EXPECTED_DISTRO_IDS  (bash array)
#     - KERNEL_PKG           (string, e.g. "linux-image-generic")
#     - PATCHED_KERNEL_VERSION (string, "PENDING" or a version comparable
#                               to what the distro hooks below return)
#   Caller MUST define the following functions:
#     - distro_running_kernel_version    (echo current kernel package version)
#     - distro_available_kernel_version  (echo candidate version, empty if none newer)
#     - distro_install_kernel            (install KERNEL_PKG; reboot is user's job)
# ---------------------------------------------------------------------------
run_algorithm() {
    parse_args "$@"

    # --undo short-circuits everything else.
    if (( CFF_UNDO )); then
        require_root "$@"
        remove_mitigation_if_present
        cff_info "undo complete. If you have NOT yet rebooted into a patched"
        cff_info "kernel, your host may again be vulnerable."
        return 0
    fi

    require_root "$@"
    assert_distro "${EXPECTED_DISTRO_IDS[@]}"

    cff_info "host: $_CFF_OS_ID $_CFF_OS_VER, running kernel: $(uname -r)"
    cff_info "patched kernel target: $PATCHED_KERNEL_VERSION"

    # Step 4: already on or past the patched version?
    if [[ "$PATCHED_KERNEL_VERSION" != "PENDING" ]]; then
        local running
        running="$(distro_running_kernel_version)"
        if [[ -n "$running" ]] && kver_ge "$running" "$PATCHED_KERNEL_VERSION"; then
            cff_ok "running kernel ($running) already includes the fix."
            remove_mitigation_if_present
            return 0
        fi
    fi

    # Step 5: a patched package available from the repo?
    if [[ "$PATCHED_KERNEL_VERSION" != "PENDING" ]]; then
        local available
        available="$(distro_available_kernel_version || true)"
        if [[ -n "$available" ]] && kver_ge "$available" "$PATCHED_KERNEL_VERSION"; then
            cff_info "candidate kernel $available is at or above the patched target."
            if prompt_yes_no "Install $KERNEL_PKG ($available) now?"; then
                cff_run distro_install_kernel
                cff_warn "kernel installed. REBOOT REQUIRED to activate it."
                cff_info "after reboot, re-run this script to verify and (auto-)remove the mitigation file."
                return 0
            fi
            cff_warn "user declined kernel install; falling through to mitigation."
        else
            cff_info "no patched kernel available in repos yet."
        fi
    else
        cff_info "patched version not yet recorded for this distro; applying mitigation."
    fi

    # Step 6: mitigation.
    apply_mitigation
    verify_mitigation
    cff_ok "mitigation in place. Re-run this script after your distro publishes a patched kernel."
}

# Universal-script path: just the modprobe blacklist + verify, no
# package-manager interaction.
run_mitigation_only() {
    parse_args "$@"

    if (( CFF_UNDO )); then
        require_root "$@"
        remove_mitigation_if_present
        return 0
    fi

    require_root "$@"
    detect_distro
    cff_info "host: $_CFF_OS_ID $_CFF_OS_VER, running kernel: $(uname -r)"
    cff_info "universal mode: applying modprobe blacklist only (no package-manager interaction)."

    apply_mitigation
    verify_mitigation
    cff_ok "mitigation in place."
}
```

- [ ] **Step 2: Lint**

```bash
cd /apps/copy-fail-fix
shellcheck scripts/lib.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/lib.sh
git commit -m "lib: add run_algorithm and run_mitigation_only orchestrators"
```

---

## Task 5: scripts/universal.sh

**Files:**
- Create: `scripts/universal.sh`

- [ ] **Step 1: Write `scripts/universal.sh`**

```bash
#!/usr/bin/env bash
# universal.sh — distro-agnostic mitigation for CVE-2026-31431.
#
# Use this on Linux distributions not directly supported by per-distro
# scripts (e.g. Gentoo, NixOS, immutable distros). It applies only the
# modprobe blacklist mitigation and does NOT attempt to install a patched
# kernel via your package manager — you'll need to handle that yourself.
#
# What this does, in plain English:
#   1. Re-runs itself under sudo if needed.
#   2. Writes /etc/modprobe.d/cve-2026-31431.conf so the kernel cannot
#      auto-load or explicitly modprobe the vulnerable algif_aead module.
#   3. Tries to unload algif_aead if it's currently loaded (best effort).
#   4. Verifies via an AF_ALG socket bind probe that the exploit path
#      is closed (errno == ENOENT).
#
# Flags: -y/--yes, --force, --check, --undo, -h/--help.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

run_mitigation_only "$@"
```

- [ ] **Step 2: Make executable + lint**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/universal.sh
shellcheck scripts/universal.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Smoke test in `--check` mode**

```bash
sudo /apps/copy-fail-fix/scripts/universal.sh --check
```
Expected: prints `host:` line, `universal mode: applying modprobe blacklist only`, `would run: bash -c ...` for the file write, and a successful (or skipped) verification block. No file actually created or modified.

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/universal.sh
git commit -m "universal: add distro-agnostic mitigation entry point"
```

---

## Task 6: scripts/ubuntu.sh

**Files:**
- Create: `scripts/ubuntu.sh`

- [ ] **Step 1: Write `scripts/ubuntu.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/ubuntu.sh
shellcheck scripts/ubuntu.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Smoke test in `--check` mode (host IS Ubuntu)**

```bash
sudo /apps/copy-fail-fix/scripts/ubuntu.sh --check
```
Expected: prints `host: ubuntu 24.04 ...`, `patched kernel target: PENDING`, `patched version not yet recorded for this distro; applying mitigation.`, `would run: ...` for the file write, and a verification block. Exit 0. Real `/etc/modprobe.d/cve-2026-31431.conf` is unchanged.

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/ubuntu.sh
git commit -m "ubuntu: add per-distro mitigation script"
```

---

## Task 7: scripts/debian.sh

**Files:**
- Create: `scripts/debian.sh`

- [ ] **Step 1: Write `scripts/debian.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/debian.sh
shellcheck scripts/debian.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Smoke test in `--check --force` mode (host is Ubuntu, not Debian)**

```bash
sudo /apps/copy-fail-fix/scripts/debian.sh --check --force
```
Expected: prints distro warning, then proceeds; final action is "would run" for mitigation file. Exit 0.

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/debian.sh
git commit -m "debian: add per-distro mitigation script"
```

---

## Task 8: scripts/rhel.sh (RHEL 8/9, Rocky, AlmaLinux)

**Files:**
- Create: `scripts/rhel.sh`

- [ ] **Step 1: Write `scripts/rhel.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/rhel.sh
shellcheck scripts/rhel.sh
```
Expected: no output, exit 0.

- [ ] **Step 3: Smoke test in `--check --force` mode (host is Ubuntu)**

```bash
sudo /apps/copy-fail-fix/scripts/rhel.sh --check --force
```
Expected: prints distro warning, falls through to mitigation print path. Note: `rpm` and `dnf` are not present on the dev host, so `distro_running_kernel_version` will return empty — script still proceeds because PATCHED is PENDING. Exit 0.

- [ ] **Step 4: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/rhel.sh
git commit -m "rhel: add per-distro mitigation script (rhel/rocky/alma/centos)"
```

---

## Task 9: scripts/fedora.sh

**Files:**
- Create: `scripts/fedora.sh`

- [ ] **Step 1: Write `scripts/fedora.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint + smoke test**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/fedora.sh
shellcheck scripts/fedora.sh
sudo /apps/copy-fail-fix/scripts/fedora.sh --check --force
```
Expected: shellcheck silent; `--check --force` exits 0.

- [ ] **Step 3: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/fedora.sh
git commit -m "fedora: add per-distro mitigation script"
```

---

## Task 10: scripts/arch.sh

**Files:**
- Create: `scripts/arch.sh`

- [ ] **Step 1: Write `scripts/arch.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint + smoke test**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/arch.sh
shellcheck scripts/arch.sh
sudo /apps/copy-fail-fix/scripts/arch.sh --check --force
```
Expected: shellcheck silent; smoke test exits 0.

- [ ] **Step 3: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/arch.sh
git commit -m "arch: add per-distro mitigation script"
```

---

## Task 11: scripts/opensuse.sh

**Files:**
- Create: `scripts/opensuse.sh`

- [ ] **Step 1: Write `scripts/opensuse.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint + smoke test**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/opensuse.sh
shellcheck scripts/opensuse.sh
sudo /apps/copy-fail-fix/scripts/opensuse.sh --check --force
```
Expected: shellcheck silent; smoke test exits 0.

- [ ] **Step 3: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/opensuse.sh
git commit -m "opensuse: add per-distro mitigation script (leap/tumbleweed)"
```

---

## Task 12: scripts/alpine.sh

**Files:**
- Create: `scripts/alpine.sh`

- [ ] **Step 1: Write `scripts/alpine.sh`**

```bash
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
```

- [ ] **Step 2: Make executable + lint + smoke test**

```bash
cd /apps/copy-fail-fix
chmod +x scripts/alpine.sh
shellcheck scripts/alpine.sh
sudo /apps/copy-fail-fix/scripts/alpine.sh --check --force
```
Expected: shellcheck silent; smoke test exits 0.

- [ ] **Step 3: Commit**

```bash
cd /apps/copy-fail-fix
git add scripts/alpine.sh
git commit -m "alpine: add per-distro mitigation script"
```

---

## Task 13: README.md (full content)

**Files:**
- Modify: `README.md` (replace stub)

- [ ] **Step 1: Replace the stub README with full content**

Overwrite `README.md` with:

```markdown
# copy-fail-fix

Per-distro mitigation scripts for [CVE-2026-31431 ("Copy Fail")](https://ubuntu.com/security/CVE-2026-31431) — a Linux kernel `algif_aead` local privilege escalation that affects essentially every distro shipped since 2017.

Each script either installs a patched kernel from your distribution's repos (when one is available) or, if not, blacklists the vulnerable `algif_aead` kernel module so the exploit path is closed until you can reboot onto a fixed kernel.

## TL;DR

Pick the script for your distro, audit it, run it as root.

```bash
# Ubuntu
sudo bash scripts/ubuntu.sh

# Debian
sudo bash scripts/debian.sh

# RHEL / Rocky / AlmaLinux / CentOS Stream
sudo bash scripts/rhel.sh

# Fedora
sudo bash scripts/fedora.sh

# Arch
sudo bash scripts/arch.sh

# openSUSE Leap / Tumbleweed
sudo bash scripts/opensuse.sh

# Alpine
sudo bash scripts/alpine.sh

# Anything else (Gentoo, NixOS, immutable distros, ...)
sudo bash scripts/universal.sh
```

Use `--check` first if you want a preview that changes nothing.

## What each script does

Per-distro scripts run this algorithm; `universal.sh` skips steps 4–5.

1. **Sudo up.** Re-execs under `sudo` if not already root.
2. **Confirm the distro.** Refuses to run on a mismatched host unless `--force`.
3. **Read `uname -r`.**
4. **Already patched?** If `PATCHED_KERNEL_VERSION` is recorded for your distro and your running kernel is at or above it, the script removes any leftover mitigation file and exits.
5. **Patch available?** Asks your package manager. If a candidate kernel ≥ the patched version is available, prompts you (`--yes` to skip) to install it. After install, you reboot manually.
6. **Mitigate.** If no patched kernel is available yet (or you declined), writes `/etc/modprobe.d/cve-2026-31431.conf` with `blacklist algif_aead` and `install algif_aead /bin/true`, then verifies via an `AF_ALG` socket-bind probe that the exploit path is closed.

## Patch status

`PATCHED_KERNEL_VERSION = PENDING` means the maintainers haven't yet recorded a fixed kernel version for that distro. Each row updates via a one-line PR.

| Distro | Kernel package | Patched version | Last checked |
|---|---|---|---|
| Ubuntu (24.04) | `linux-image-generic` | PENDING | 2026-05-01 |
| Debian | `linux-image-amd64` | PENDING | 2026-05-01 |
| RHEL / Rocky / Alma | `kernel` | PENDING | 2026-05-01 |
| Fedora | `kernel` | PENDING | 2026-05-01 |
| Arch | `linux` | PENDING | 2026-05-01 |
| openSUSE | `kernel-default` | PENDING | 2026-05-01 |
| Alpine | `linux-lts` | PENDING | 2026-05-01 |

## Flags

| Flag | Meaning |
|---|---|
| `-y`, `--yes` | Non-interactive; skip the kernel-install prompt. |
| `--force` | Bypass the distro-mismatch check. |
| `--check` | Read-only preview; print what would happen, change nothing. |
| `--undo` | Remove `/etc/modprobe.d/cve-2026-31431.conf`. Use after a patched kernel is installed. |
| `-h`, `--help` | Usage info. |

## Verifying the mitigation manually

The scripts run this probe automatically. To check yourself:

```bash
python3 - <<'PY'
import socket, errno
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", "authencesn(hmac(sha1),cbc(aes))"))
    print("BAD: bind succeeded — host is NOT mitigated")
    s.close()
except OSError as e:
    print(f"OK: bind blocked, errno={e.errno} ({e.strerror})" if e.errno == errno.ENOENT
          else f"INCONCLUSIVE: errno={e.errno}")
PY
```

A mitigated or patched host prints `OK: bind blocked, errno=2 ...`.

## Undoing

After your distro publishes a fixed kernel and you reboot onto it, remove the modprobe blacklist so applications that legitimately use AF_ALG aead can work again:

```bash
sudo bash scripts/<your-distro>.sh --undo
```

## Contributing

When your distro publishes a fixed kernel:

1. Edit one line in `scripts/<distro>.sh` — set `PATCHED_KERNEL_VERSION` to the fixed package version (in the format `dpkg-query -W` / `rpm -q VERSION-RELEASE` / `pacman -Q` returns).
2. Update the corresponding row in this README's patch-status table.
3. Open a PR titled `<distro>: fix shipped in <version>`.

## Disclaimer

Security mitigation tooling. Audit any script you find on the internet before piping it into `sudo bash`. The maintainers accept no liability under the MIT license.

## License

[MIT](LICENSE).
```

- [ ] **Step 2: Commit**

```bash
cd /apps/copy-fail-fix
git add README.md
git commit -m "docs: write full README (usage, status, flags, contributing)"
```

---

## Task 14: ShellCheck CI workflow

**Files:**
- Create: `.github/workflows/shellcheck.yml`

- [ ] **Step 1: Write `.github/workflows/shellcheck.yml`**

```yaml
name: shellcheck

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install shellcheck
        run: sudo apt-get update && sudo apt-get install -y shellcheck

      - name: Run shellcheck on every .sh
        run: |
          set -euo pipefail
          mapfile -t FILES < <(find scripts -name '*.sh' -type f | sort)
          if (( ${#FILES[@]} == 0 )); then
            echo "no shell scripts found" >&2
            exit 1
          fi
          shellcheck "${FILES[@]}"
```

- [ ] **Step 2: Sanity-check the YAML locally**

```bash
cd /apps/copy-fail-fix
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/shellcheck.yml"))' && echo "yaml ok"
```
Expected: `yaml ok`.

- [ ] **Step 3: Commit**

```bash
cd /apps/copy-fail-fix
git add .github/workflows/shellcheck.yml
git commit -m "ci: shellcheck on push and pull_request"
```

---

## Task 15: Final integration check

**Files:** none (runs read-only checks against all scripts)

- [ ] **Step 1: ShellCheck every script**

```bash
cd /apps/copy-fail-fix
shellcheck scripts/*.sh
```
Expected: no output, exit 0.

- [ ] **Step 2: `--check --force` every distro script + `--check` universal**

```bash
cd /apps/copy-fail-fix
sudo bash scripts/universal.sh --check
for s in ubuntu debian rhel fedora arch opensuse alpine; do
  echo "=== $s ==="
  sudo bash "scripts/$s.sh" --check --force || { echo "FAIL: $s"; exit 1; }
done
echo "all scripts passed --check"
```
Expected: ends with `all scripts passed --check`.

- [ ] **Step 3: `--help` smoke test**

```bash
cd /apps/copy-fail-fix
bash scripts/universal.sh --help | head -5
bash scripts/ubuntu.sh --help | head -5
```
Expected: `Usage: universal.sh [flags]` / `Usage: ubuntu.sh [flags]` and following lines visible.

- [ ] **Step 4: Confirm prod mitigation file untouched**

```bash
sudo cat /etc/modprobe.d/cve-2026-31431.conf | head -5
```
Expected: header comment `# CVE-2026-31431 "Copy Fail" — Linux kernel algif_aead LPE.` (the file written during the original incident response is intact).

- [ ] **Step 5: No commit; this task is verification only.**

---

## Task 16: Create GitHub repo + push

**Files:** none locally; creates the remote.

- [ ] **Step 1: Create the public GitHub repo**

```bash
cd /apps/copy-fail-fix
gh repo create bryanvine/copy-fail-fix \
    --public \
    --description "Per-distro mitigation scripts for CVE-2026-31431 (\"Copy Fail\") Linux kernel LPE." \
    --source=. \
    --remote=origin \
    --push
```
Expected: ends with the repo URL printed by `gh`. `git remote -v` shows `origin` pointing to `github.com/bryanvine/copy-fail-fix.git`.

- [ ] **Step 2: Verify CI ran and is green**

```bash
sleep 30
gh run list --limit 3
```
Expected: a `shellcheck` run on `main`, status `completed`, conclusion `success`. If still queued/running, re-run after a short wait.

- [ ] **Step 3: Final report**

Print a summary in the terminal: repo URL, CI status, list of files. No commit.

```bash
cd /apps/copy-fail-fix
echo "Repo:  $(gh repo view --json url -q .url)"
echo "CI:    $(gh run list --limit 1 --json status,conclusion -q '.[0] | "\(.status)/\(.conclusion)"')"
echo "Files:"
git ls-files
```

---

## Self-review (executed before handoff)

**Spec coverage:**
- Repository layout → Tasks 1, 5–14. ✓
- Per-distro algorithm → Task 4 (run_algorithm). ✓
- `lib.sh` responsibilities → Tasks 2–4. ✓
- Per-distro constants table → each per-distro task (6–12) sets the documented constants. ✓
- `PATCHED_KERNEL_VERSION = PENDING` initial state → Tasks 6–12. ✓
- CLI flags (`-y`, `--force`, `--check`, `--undo`, `-h`) → Task 2 (parse_args), Task 4 (`--undo` short-circuit). ✓
- Error handling (`set -euo pipefail`, distro mismatch, install failure, verify failure) → Tasks 2–4. ✓
- Testing strategy (shellcheck CI + manual `--check`) → Tasks 14, 15. ✓
- Patch-tracking workflow → README contributing section, Task 13. ✓

**Placeholder scan:** No "TBD" / "implement later" / "add appropriate error handling" patterns. Every code block is concrete. The `PENDING` literal is a documented sentinel value, not a placeholder for the engineer to fill. ✓

**Type/name consistency:** `apply_mitigation`, `verify_mitigation`, `remove_mitigation_if_present`, `run_algorithm`, `run_mitigation_only`, `distro_running_kernel_version`, `distro_available_kernel_version`, `distro_install_kernel`, `EXPECTED_DISTRO_IDS`, `KERNEL_PKG`, `PATCHED_KERNEL_VERSION`, `CFF_MITIGATION_FILE`, `CFF_YES`, `CFF_FORCE`, `CFF_CHECK`, `CFF_UNDO`. Each name appears identically across all tasks that reference it. ✓
