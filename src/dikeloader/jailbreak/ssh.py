# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
from typing import Any

from dikeloader.exceptions import JailbreakError
from dikeloader.jailbreak.iproxy import ensure_usb_ssh_tunnel
from dikeloader.store.secrets import get_ssh_password, set_ssh_password
from dikeloader.store.settings import Settings

JB_PATH = (
    "export PATH=/var/jb/usr/sbin:/var/jb/usr/bin:/var/jb/sbin:/var/jb/bin"
    ":/usr/sbin:/usr/bin:/sbin:/bin:$PATH; "
    "export JBRAND=${JBRAND:-}; "
)


class SSHSession:
    def __init__(self, client: Any) -> None:
        self.client = client

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    def run(self, command: str, timeout: int = 120) -> tuple[int, str, str]:
        stdin, stdout, stderr = self.client.exec_command(JB_PATH + command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return code, out, err

    def check(self, command: str, timeout: int = 120) -> str:
        code, out, err = self.run(command, timeout=timeout)
        if code != 0:
            detail = (err or out or f"exit {code}").strip()
            raise JailbreakError(detail[:500] or f"SSH command failed ({code}).")
        return out

    def put(self, local: str | Path, remote: str) -> None:
        sftp = self.client.open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()

    def exists(self, remote: str) -> bool:
        code, out, _err = self.run(f'test -e "{remote}" && echo YES || echo NO')
        return code == 0 and "YES" in out


def connect_ssh(settings: Settings, udid: str | None = None, password: str | None = None) -> SSHSession:
    try:
        import paramiko
    except ImportError as exc:
        raise JailbreakError("paramiko is not installed. Re-run scripts\\bootstrap.ps1.") from exc

    password = password if password is not None else get_ssh_password(settings.ssh_user)
    if not password:
        raise JailbreakError(
            "Set the iPhone SSH password (Dopamine OpenSSH default is alpine — change it)."
        )

    host = "127.0.0.1"
    port = settings.usb_ssh_port
    if settings.prefer_wifi and settings.wifi_ssh_host.strip():
        host = settings.wifi_ssh_host.strip()
        port = settings.wifi_ssh_port
    elif settings.use_usb_ssh:
        if not udid:
            raise JailbreakError("Connect the iPhone over USB for SSH, or enter a Wi-Fi IP.")
        ensure_usb_ssh_tunnel(udid, settings.usb_ssh_port, 22)
        host = "127.0.0.1"
        port = settings.usb_ssh_port
    elif settings.wifi_ssh_host.strip():
        host = settings.wifi_ssh_host.strip()
        port = settings.wifi_ssh_port
    else:
        raise JailbreakError("Enter the iPhone Wi-Fi IP or enable USB SSH.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=settings.ssh_user,
            password=password,
            timeout=12,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=12,
            auth_timeout=12,
        )
    except Exception as exc:
        raise JailbreakError(
            "SSH to the iPhone failed. On Dopamine: install OpenSSH from Sileo, "
            f"keep the phone unlocked, and check the password. ({exc})"
        ) from exc
    set_ssh_password(settings.ssh_user, password)
    return SSHSession(client)
