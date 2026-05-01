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
