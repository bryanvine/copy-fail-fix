---
layout: home
title: copy-fail-fix
---

Per-distro shell scripts that mitigate **CVE-2026-31431 ("Copy Fail")** — a Linux kernel `algif_aead` local privilege escalation that affects every major Linux distribution shipped since 2017.

> A 732-byte Python script gives any unprivileged local user root on the box.

**Source code:** [github.com/bryanvine/copy-fail-fix](https://github.com/bryanvine/copy-fail-fix)

## Why this matters

CVE-2026-31431 was disclosed publicly on 2026-04-29. Mainline Linux merged the fix on 2026-04-01, but as of writing **no major distribution has shipped a patched kernel package** yet — `apt upgrade` won't fix it.

There's a battle-tested workaround that doesn't require a reboot: blacklist the `algif_aead` kernel module so the kernel can't auto-load it. The exploit relies on the module being loadable on demand by any unprivileged user; the blacklist closes that path.

`copy-fail-fix` is a small set of per-distro shell scripts that:

- Check whether your distro has shipped a patched kernel; if so, prompt to install it.
- Otherwise apply the modprobe blacklist mitigation.
- Verify the mitigation via an `AF_ALG` socket-bind probe.
- Provide `--check` (read-only preview) and `--undo` (cleanup after kernel patch) flags.

## Quick start

```bash
git clone https://github.com/bryanvine/copy-fail-fix
cd copy-fail-fix
sudo bash scripts/ubuntu.sh    # or debian, rhel, fedora, arch, opensuse, alpine
```

See the [README on GitHub](https://github.com/bryanvine/copy-fail-fix#readme) for full docs, the patch-status table, and how to contribute.
