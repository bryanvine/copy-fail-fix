---
layout: post
title: "Copy Fail (CVE-2026-31431): a 732-byte Python script roots every Linux server you own"
date: 2026-04-30
categories: [linux, security]
tags: [linux, security, cve, kernel]
description: "What CVE-2026-31431 actually is, why it affects every Linux distribution shipped since 2017, and how to mitigate it without a reboot."
---

I spent Thursday afternoon patching my own infrastructure for a Linux kernel CVE that has been silently sitting in every major distribution for nine years. By the end of the day I'd packaged the mitigation as per-distro shell scripts so other people don't have to figure it out from scratch: [github.com/bryanvine/copy-fail-fix](https://github.com/bryanvine/copy-fail-fix).

This post is what I wish I'd been able to read on Thursday morning.

## TL;DR

* CVE-2026-31431 ("Copy Fail") is a Linux kernel local privilege escalation. CVSS 7.8.
* Disclosed publicly 2026-04-29. Mainline patched 2026-04-01.
* As of writing, **no major distribution has shipped a fixed kernel package yet**. Running `apt upgrade` will not fix it today.
* A 732-byte Python script gives any unprivileged local user root on Ubuntu, Debian, RHEL, Rocky, Alma, Fedora, Arch, openSUSE, Alpine, and effectively every other Linux distribution in active use.
* The bug requires the `algif_aead` kernel module. Almost nothing on a typical server actually needs it. **You can blacklist it right now and close the exploit path without rebooting.**
* My repo: [copy-fail-fix](https://github.com/bryanvine/copy-fail-fix) — per-distro audit-friendly shell scripts that either install your distro's patched kernel (when one exists) or apply the modprobe blacklist mitigation.

## What the bug actually is

The vulnerability lives in `algif_aead.c`, a corner of the kernel that exposes AEAD (Authenticated Encryption with Associated Data) cryptographic operations to userspace via the `AF_ALG` socket family. `AF_ALG` is the kernel's "give me kernel-accelerated crypto without userspace libraries" interface. It's used by IPsec, by parts of dm-crypt, and by a handful of crypto-heavy userspace tools — but for the typical web server, database server, or container host, it's a feature you've probably never knowingly used.

The bug is the result of three innocuous-looking changes that combined badly:

1. **2011** — `authencesn`, an AEAD wrapper used by IPsec, was added to the kernel's crypto API.
2. **2015** — `AF_ALG` socket support for AEAD was introduced, exposing those wrappers to userspace.
3. **2017** — An in-place optimization was added to `algif_aead.c` to avoid an unnecessary buffer copy on the AEAD fast path.

The 2017 optimization assumed certain invariants about how AEAD requests were structured. Those invariants don't hold for `authencesn`. The interaction creates a logic error that lets a local user perform a deterministic, controlled 4-byte write into the page cache of any readable file on the system.

In practice that's all an attacker needs. Pick a setuid binary, edit four well-chosen bytes (e.g. flip a permission check or change a pointer), run it. Pop a root shell. The exploit has no race condition, no kernel offset to leak, and no per-distribution variation. It just works.

The published proof-of-concept is **732 bytes of Python**. No exotic dependencies. No tuning per kernel version. The same script roots every affected distribution.

## How widespread is "every distro since 2017"?

The kernel changes that combine to produce this bug have been in every stable Linux kernel released since 2017. As of disclosure on 2026-04-29, the affected lineup includes:

| Distribution | Kernel | Status as of 2026-04-30 |
|---|---|---|
| Ubuntu 24.04 LTS (and most older LTS) | 6.8 / 5.15 / 5.4 | Vulnerable; no patched package yet |
| Debian (stable, oldstable) | 6.1 / 5.10 | Vulnerable |
| RHEL 8 / 9 (and rebuilds: Rocky, Alma) | 4.18 / 5.14 | Vulnerable |
| Fedora | 6.x | Vulnerable; fast lane likely patches first |
| Arch | 6.x rolling | Vulnerable until rolling pulls the fix |
| openSUSE Leap / Tumbleweed | 5.14 / rolling | Vulnerable |
| Alpine | 6.x (linux-lts / linux-virt) | Vulnerable |

Ubuntu 26.04 ("Resolute") and forward kernels are not affected because the relevant code path was rewritten before that release. If you're on something newer than April 2026 mainline, you're fine.

Mainline Linux merged the patch on 2026-04-01, four weeks before public disclosure. The catch is that distributions need to backport the patch, run it through their QA, build new kernel packages, and push them to their security archives. As of writing that work is in flight but not yet shipped. So `apt-cache madison linux-image-generic` on Ubuntu 24.04 still returns the same vulnerable `6.8.0-110.110` you're already running.

## The mitigation that doesn't need a kernel update

Both [Canonical's advisory](https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available) and the [Help Net Security writeup](https://www.helpnetsecurity.com/2026/04/30/copyfail-linux-lpe-vulnerability-cve-2026-31431/) point at the same workaround: prevent the vulnerable module from loading.

The bug requires the `algif_aead` kernel module to be active. By default that module isn't loaded — but the kernel auto-loads it on demand the first time anyone calls `socket(AF_ALG, …)` with `aead` as the algorithm type. Any unprivileged user can trigger the auto-load by opening a socket. That's what makes the bug exploitable.

If you blacklist the module so the kernel won't auto-load it, and use the `install … /bin/true` directive to defeat explicit `modprobe` calls too, the exploit path is closed. No reboot, no service interruption, no kernel rebuild.

```text
# /etc/modprobe.d/cve-2026-31431.conf
blacklist algif_aead
install algif_aead /bin/true
```

You can verify the mitigation with a one-liner:

```python
import socket, errno
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", "authencesn(hmac(sha1),cbc(aes))"))
    print("BAD: bind succeeded — host is NOT mitigated")
    s.close()
except OSError as e:
    if e.errno == errno.ENOENT:
        print("OK: bind blocked, exploit path closed")
    else:
        print(f"INCONCLUSIVE: errno={e.errno}")
```

A mitigated host prints `OK: bind blocked` because the kernel can't find an AEAD handler for the requested algorithm — the module that would provide it can't load.

## What about apps that legitimately use AF_ALG?

Almost nothing on a typical server uses the `aead` type specifically. `AF_ALG` itself has a few users — StrongSwan and libreswan use it for IPsec — but those use other algorithm types (`skcipher`, `hash`) which this mitigation doesn't touch. WireGuard does its own crypto in kernel space without `AF_ALG`. OpenSSL uses `AF_ALG` only behind an explicit engine that almost nobody enables. Modern crypto libraries (libsodium, BoringSSL, etc.) don't use it.

If you're running IPsec with StrongSwan and have explicitly enabled kernel-accelerated AEAD via `AF_ALG`, this mitigation might affect you. Test in staging before deploying. For everyone else, the blacklist is safe.

On the host where I tested this, the `algif_aead` module wasn't even loaded at the moment of the disclosure — but any local user could have triggered the auto-load and the exploit. The blacklist prevents that.

## copy-fail-fix

[github.com/bryanvine/copy-fail-fix](https://github.com/bryanvine/copy-fail-fix) is a public repo of per-distro shell scripts. Pick the one for your distro, audit it (each is ~40 lines), run it as root.

```bash
sudo bash scripts/ubuntu.sh
```

What each script does:

1. Re-execs itself under sudo if it isn't already root.
2. Confirms the host actually matches the script (refuses otherwise unless `--force`).
3. Checks if the running kernel is already at or above the patched version. If so, removes any leftover blacklist file and exits.
4. Asks the package manager whether a patched kernel is now available. If yes, prompts to install it (`--yes` to skip the prompt for automation). After install, reboot manually.
5. If no patched kernel exists yet (or you decline the install), writes the modprobe blacklist and verifies via the `AF_ALG` socket probe that the exploit path is closed.

There's a `--check` mode for a read-only preview that changes nothing, a `--undo` flag for removing the mitigation after you reboot onto a patched kernel, and a `universal.sh` fallback for distros not directly supported (Gentoo, NixOS, immutable distros).

The repo ships with `PATCHED_KERNEL_VERSION="PENDING"` for every distro because no distro has shipped a fixed kernel yet. As distros publish their patches, contributors update one line in the relevant script and the README's status table. The script then auto-detects the patched kernel via the package manager and offers to install it.

## Why a separate repo and not a one-line gist?

Because security tooling that runs as root deserves auditability.

A gist gets piped into `sudo bash` without anyone reading it. The community trains itself to do this for one-off scripts and then learns nothing when something malicious slips in. A real repo with per-distro scripts you can read end-to-end in 60 seconds, with a public commit history and CI that runs ShellCheck on every change, gives sysadmins a chance to actually audit what they're running before they run it.

The repo also commits the design spec and implementation plan in `docs/`, so anyone curious about how the mitigation logic was built can read along. ShellCheck CI on every push catches the obvious shell footguns. There's no telemetry, no analytics, no curl-to-bash entry point.

## What to do right now

1. **Today**: run the script for your distro, or apply the modprobe blacklist by hand if you'd rather. Verify with the Python probe above.
2. **This week**: watch your distro's CVE tracker for the patched kernel. Links are in the repo's status table. When your distro ships, install it and reboot.
3. **After reboot**: run the script again with `--undo` to remove the modprobe blacklist so applications that legitimately use `AF_ALG` aead can work normally.

This bug is reliable, the exploit is published, and the kernel fix is real-but-not-yet-shipped to most servers. If you have any local users on a Linux machine you don't fully trust, or you run any container workload with relaxed security boundaries, the mitigation is worth the five minutes today. Don't wait for your distro's USN.

If you find a bug in the scripts or want to add a distro that isn't covered, the repo accepts PRs. The patch-status table in the README is the natural place to start contributing as kernels ship — it's a one-line update per distro per fix.

---

*Sources: [Ubuntu Security Notice for CVE-2026-31431](https://ubuntu.com/security/CVE-2026-31431), [Help Net Security disclosure writeup](https://www.helpnetsecurity.com/2026/04/30/copyfail-linux-lpe-vulnerability-cve-2026-31431/), [Canonical's "fixes available" blog post](https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available).*
