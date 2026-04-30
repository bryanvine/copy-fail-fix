# Design: copy-fail-fix

**Date:** 2026-04-30
**Status:** Approved (design phase)
**CVE:** [CVE-2026-31431](https://ubuntu.com/security/CVE-2026-31431) ("Copy Fail")

## Problem

CVE-2026-31431 is a Linux kernel local privilege escalation in `algif_aead.c`. A
732-byte unprivileged exploit can obtain root on virtually every Linux
distribution shipped since 2017. Disclosure occurred 2026-04-29; the upstream
fix landed mainline 2026-04-01. As of repo-creation date no major distribution
has shipped a patched kernel package. Sysadmins need a fast, auditable way to
mitigate the exploit until their distribution publishes a fixed kernel.

## Goals

1. Provide a per-distribution shell script that does the right thing on each
   of the seven most common production Linux distributions.
2. Give sysadmins a script they can read end-to-end in under a minute and
   understand before running.
3. Keep the mitigation reversible: a single `--undo` flag removes it once the
   patched kernel is in place.
4. Track patch availability over time via a `PATCHED_KERNEL_VERSION` constant
   the maintainers bump as distros ship fixes.

## Non-goals

- Not a general CVE-mitigation framework. Single-CVE scope.
- No automatic reboot. Scripts tell the user a reboot is needed; user owns
  the timing.
- No Docker-based CI matrix executing each distro's script in its native
  container. ShellCheck only at this stage. (Reconsider if the repo gets
  contributors.)
- No detection of whether the host is *already exploited*. This is a
  forward-looking mitigation tool, not an incident-response tool.

## Repository layout

```
copy-fail-fix/
├── README.md
├── LICENSE                       # MIT
├── scripts/
│   ├── lib.sh                    # shared helpers, sourced by all
│   ├── universal.sh              # mitigation-only fallback
│   ├── ubuntu.sh
│   ├── debian.sh
│   ├── rhel.sh                   # RHEL 8/9, Rocky, AlmaLinux
│   ├── fedora.sh
│   ├── arch.sh
│   ├── opensuse.sh               # Leap + Tumbleweed
│   └── alpine.sh
└── .github/workflows/
    └── shellcheck.yml
```

## Per-distro script algorithm

All seven distro scripts share this skeleton, parameterized at the top with
distro-specific constants. Version comparisons use `kver_ge` from `lib.sh`.

In `--check` mode every action step (`remove_mitigation_file_if_present`,
`distro_install_kernel`, `apply_mitigation`) is replaced with a print-only
description; `verify_mitigation` is still allowed (it's read-only).

```
1. require_root
       Re-exec with sudo -E if not uid 0; refuse if no sudo.
2. assert_distro
       Parse /etc/os-release; warn-and-confirm on mismatch unless --force.
3. running_kver=$(uname -r)
4. if PATCHED_KERNEL_VERSION != "PENDING" and kver_ge "$running_kver" "$PATCHED":
       remove_mitigation_file_if_present
       echo "Already on patched kernel."
       exit 0
5. if PATCHED_KERNEL_VERSION != "PENDING":
       available=$(distro_check_available_kernel)
       if kver_ge "$available" "$PATCHED":
           prompt_unless_yes "Install $available?"
           distro_install_kernel
           echo "Reboot required."
           exit 0
6. apply_mitigation       # write /etc/modprobe.d/cve-2026-31431.conf
   verify_mitigation      # AF_ALG bind probe must return ENOENT
   echo "Mitigation in place. Re-run after distro publishes fix."
```

`universal.sh` skips steps 4-5; it only ever applies the modprobe mitigation
and is the recommended path for distros not in the supported list (Gentoo,
NixOS, immutable distros, etc.).

## Shared library: `scripts/lib.sh`

| Function | Purpose |
|---|---|
| `require_root` | Re-exec with `sudo -E` if needed; abort if no sudo. |
| `detect_distro` | Source `/etc/os-release`, export `$ID` and `$VERSION_ID`. |
| `assert_distro <expected_ids>` | Warn and require `--force` if mismatch. |
| `kver_ge "$a" "$b"` | Kernel version compare. Uses `dpkg --compare-versions` if available; falls back to `sort -V`. |
| `apply_mitigation` | Write `/etc/modprobe.d/cve-2026-31431.conf` with `blacklist algif_aead` and `install algif_aead /bin/true`. Idempotent. |
| `verify_mitigation` | Inline Python: `socket(AF_ALG, SOCK_SEQPACKET, 0); bind(("aead", "authencesn(...)"))` must raise OSError with `errno.ENOENT`. |
| `remove_mitigation_if_present` | Delete the modprobe file if it exists; idempotent. |
| `prompt_yes_no <msg>` | Respects `--yes` flag and non-TTY stdin (defaults to "no" in non-TTY without `--yes`). |

## Per-distro constants

| Distro | `KERNEL_PKG` | `INSTALL_CMD` | `CHECK_AVAILABLE` |
|---|---|---|---|
| ubuntu | `linux-image-generic` | `apt-get install --only-upgrade -y` | `apt-cache policy` |
| debian | `linux-image-amd64` | `apt-get install --only-upgrade -y` | `apt-cache policy` |
| rhel | `kernel` | `dnf -y upgrade` | `dnf check-update` |
| fedora | `kernel` | `dnf -y upgrade` | `dnf check-update` |
| arch | `linux` | `pacman -Sy --noconfirm` | `pacman -Si` |
| opensuse | `kernel-default` | `zypper -n update` | `zypper info` |
| alpine | `linux-lts` (note `linux-virt` alt) | `apk upgrade` | `apk version` |

`PATCHED_KERNEL_VERSION` starts as `"PENDING"` for all seven distros. Each is
bumped via a one-line PR when that distro publishes its fix.

## CLI flags (consistent across all scripts)

| Flag | Behavior |
|---|---|
| `-y`, `--yes` | Non-interactive; skip kernel-install prompt. |
| `--force` | Bypass distro-mismatch check. |
| `--check` | Read-only preview; print what would happen, change nothing. |
| `--undo` | Remove the modprobe mitigation file. Use after kernel patch is in place. |
| `-h`, `--help` | Usage info. |

## Error handling

- `set -euo pipefail` at the top of every script.
- Distro mismatch → loud warning, abort unless `--force`.
- Package-manager install failure → fall through to mitigation, then exit
  non-zero so callers/CI can detect partial success.
- Verification failure → exit non-zero with a clear message; never claim
  success when the AF_ALG bind probe still works.

## Testing strategy

**In CI:** GitHub Actions runs `shellcheck` against every `.sh` file on every
push and PR. Catches the most common shell mistakes for ~zero cost.

**Manual smoke test before first push:** Author runs `ubuntu.sh --check` on
their own (Ubuntu 24.04, vulnerable) host. This exercises the no-patch-yet
branch end-to-end. The mitigation has already been applied to that host as
part of incident response, so `--check` is the natural fit.

**Out of scope:** Per-distro Docker matrix execution. Worth adding if the
repo gains contributors; not worth it for v1.

## Patch-tracking workflow

The repo's value over time depends on `PATCHED_KERNEL_VERSION` staying
current. Process:

1. Watch each distro's CVE tracker / security advisory feed.
2. When one ships, edit two places in the repo:
   - One line in `scripts/<distro>.sh` (the constant)
   - One row in the README's "Patch status" table (with the date)
3. Open a PR titled `<distro>: fix shipped in <version>`, merge.

## Open questions / future work

- Should the verification step also probe `algif_skcipher` and `algif_hash`?
  They share the AF_ALG family but are not affected by this CVE. Current
  design probes only `aead` (the affected type). YAGNI; revisit only if a
  related CVE shows up.
- Should `--undo` also unblacklist if the user previously had their own
  blacklist entry for `algif_aead`? Current design only deletes the file
  this tool wrote. Acceptable for v1; documented.
- Should there be a Homebrew/snap/etc package? No — the value of these
  scripts is being copy-pasteable shell. Distribution as packages defeats
  the audit-before-running model.
