# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass

from dikeloader.device.installer import list_user_apps
from dikeloader.jailbreak.ssh import SSHSession

DOPAMINE_IDS = ("com.opa334.Dopamine", "com.opa334.dopamine")
TROLLSTORE_IDS = (
    "com.opa334.TrollStore",
    "com.opa334.TrollStoreLite",
    "com.opa334.TrollHelper",
)
LIVECONTAINER_IDS = (
    "com.kdt.livecontainer",
    "com.kdt.livecontainer.sidecar",
    "livecontainer.LiveContainer",
)


@dataclass
class JailbreakInfo:
    ssh_ok: bool
    rootless: bool
    dopamine: bool
    trollstore: bool
    livecontainer: bool
    trollstore_helper: str = ""
    jb_prefix: str = ""
    detail: str = ""

    @property
    def summary(self) -> str:
        parts = []
        if self.dopamine:
            parts.append("Dopamine")
        elif self.rootless:
            parts.append("rootless jailbreak")
        if self.trollstore:
            parts.append("TrollStore")
        if self.livecontainer:
            parts.append("LiveContainer")
        if self.ssh_ok:
            parts.append("SSH")
        return " · ".join(parts) if parts else "jailbreak not detected"


def _has_app(apps: list[dict[str, str]], ids: tuple[str, ...]) -> bool:
    have = {a.get("bundle_id", "") for a in apps}
    return any(item in have for item in ids)


def probe_jailbreak(ssh: SSHSession | None, udid: str | None = None) -> JailbreakInfo:
    apps: list[dict[str, str]] = []
    if udid:
        try:
            apps = list_user_apps(udid)
        except Exception:
            apps = []

    dopamine_app = _has_app(apps, DOPAMINE_IDS)
    troll_app = _has_app(apps, TROLLSTORE_IDS)
    live_app = _has_app(apps, LIVECONTAINER_IDS)

    if ssh is None:
        return JailbreakInfo(
            ssh_ok=False,
            rootless=False,
            dopamine=dopamine_app,
            trollstore=troll_app,
            livecontainer=live_app,
            detail="SSH not connected. Dopamine is semi-untethered — open Dopamine after a reboot.",
        )

    code, out, _err = ssh.run(
        'if test -d /var/jb; then echo ROOTLESS:/var/jb; elif test -d /usr/libexec/ellekit; then echo ROOTFUL; else echo NONE; fi; '
        'uname -a; '
        '(command -v trollstorehelper || true); '
        '(ls /var/containers/Bundle/Application/*/TrollStore.app/trollstorehelper 2>/dev/null || true); '
        '(ls /var/containers/Bundle/Application/*/TrollHelper.app/trollstorehelper 2>/dev/null || true)'
    )
    text = out.strip()
    rootless = "ROOTLESS:" in text
    prefix = "/var/jb" if rootless else ""
    helper = ""
    for line in text.splitlines():
        line = line.strip()
        if line.endswith("trollstorehelper") and " " not in line:
            helper = line
            break
        if "/trollstorehelper" in line:
            helper = line.split()[-1]
            break

    code_d, out_d, _ = ssh.run(
        'ls /var/jb/Applications/Dopamine.app >/dev/null 2>&1 && echo DOP || '
        'ls /Applications/Dopamine.app >/dev/null 2>&1 && echo DOP || echo NO'
    )
    dopamine = dopamine_app or "DOP" in out_d

    return JailbreakInfo(
        ssh_ok=code == 0,
        rootless=rootless,
        dopamine=dopamine,
        trollstore=troll_app or bool(helper),
        livecontainer=live_app,
        trollstore_helper=helper,
        jb_prefix=prefix,
        detail=text[:400],
    )
