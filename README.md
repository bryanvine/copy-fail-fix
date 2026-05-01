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
