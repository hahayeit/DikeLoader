# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path

from dikeloader.exceptions import JailbreakError
from dikeloader.jailbreak.detect import JailbreakInfo, probe_jailbreak
from dikeloader.jailbreak.ssh import SSHSession

REMOTE_IPA = "/var/mobile/Documents/dikeloader-install.ipa"


def _helper_path(ssh: SSHSession, info: JailbreakInfo | None = None) -> str:
    info = info or probe_jailbreak(ssh)
    if info.trollstore_helper:
        return info.trollstore_helper
    code, out, _err = ssh.run(
        'command -v trollstorehelper; '
        'ls /var/containers/Bundle/Application/*/TrollStore.app/trollstorehelper 2>/dev/null; '
        'ls /var/containers/Bundle/Application/*/TrollHelper.app/trollstorehelper 2>/dev/null'
    )
    for line in (out or "").splitlines():
        line = line.strip()
        if line.endswith("trollstorehelper"):
            return line
    raise JailbreakError(
        "TrollStore is not installed. On iOS 16.1 + Dopamine, install TrollStore "
        "(TrollHelper package or TrollStore IPA) so apps can be CoreTrust-signed permanently."
    )


def install_ipa_trollstore(ssh: SSHSession, ipa: Path, info: JailbreakInfo | None = None) -> str:
    """Copy an IPA over SSH and install it with TrollStore's CoreTrust helper."""
    if not ipa.is_file():
        raise JailbreakError(f"IPA missing: {ipa}")
    helper = _helper_path(ssh, info)
    ssh.put(ipa, REMOTE_IPA)
    ssh.check(f'chmod 0644 "{REMOTE_IPA}"')
    out = ssh.check(f'"{helper}" install "{REMOTE_IPA}"', timeout=180)
    ssh.run(f'rm -f "{REMOTE_IPA}"')
    return out.strip() or "TrollStore installed the app (CoreTrust, no 7-day expiry)."
