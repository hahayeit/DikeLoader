# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass
import subprocess
import sys

from dikeloader.paths import vendor_dir
from dikeloader.sign.zsign import find_zsign


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _apple_usb_service_running() -> tuple[bool, str]:
    if sys.platform != "win32":
        return True, "Not Windows; USB mux is provided by the OS."
    names = (
        "Apple Mobile Device Service",
        "AppleMobileDeviceService",
        "Apple Mobile Device Service (CoreFoundation)",
    )
    for name in names:
        try:
            proc = subprocess.run(
                ["sc", "query", name],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            return False, f"Could not query Windows services: {exc}"
        blob = (proc.stdout or "") + (proc.stderr or "")
        if "RUNNING" in blob.upper():
            return True, f"Windows service '{name}' is running."
        if proc.returncode == 0 and "STOPPED" in blob.upper():
            return False, f"Windows service '{name}' is installed but stopped."
    return (
        False,
        "Apple Mobile Device Support is not running. Install Apple Devices "
        "from the Microsoft Store (or iTunes) and reconnect the iPhone.",
    )


def run_doctor() -> list[Check]:
    checks: list[Check] = []

    checks.append(
        Check(
            "Python",
            sys.version_info >= (3, 11),
            f"{sys.version.split()[0]} ({sys.executable})",
        )
    )

    zsign = find_zsign()
    checks.append(
        Check(
            "zsign",
            zsign is not None,
            str(zsign) if zsign else f"Missing. Run: python -m dikeloader fetch-zsign  (looked in {vendor_dir()})",
        )
    )

    try:
        import pymobiledevice3  # noqa: F401

        checks.append(Check("pymobiledevice3", True, "Installed."))
    except Exception as exc:
        checks.append(Check("pymobiledevice3", False, str(exc)))

    try:
        import cryptography  # noqa: F401

        checks.append(Check("cryptography", True, "Installed."))
    except Exception as exc:
        checks.append(Check("cryptography", False, str(exc)))

    try:
        import anisette  # noqa: F401

        checks.append(Check("anisette", True, "Local Apple device identity library is installed."))
    except Exception as exc:
        checks.append(Check("anisette", False, str(exc)))

    ok, detail = _apple_usb_service_running()
    checks.append(Check("Apple USB drivers", ok, detail))

    try:
        from dikeloader.device.connection import list_usb_devices

        devices = list_usb_devices()
        if devices:
            names = ", ".join(f"{d.name} (iOS {d.ios_version}, {d.connection_type})" for d in devices)
            checks.append(Check("Connected iPhone", True, names))
            paired = all(d.paired for d in devices)
            checks.append(
                Check(
                    "Pairing",
                    paired,
                    "Trusted." if paired else "Unlock the iPhone and tap Trust This Computer.",
                )
            )
            product = devices[0].product_type
            ios = devices[0].ios_version
            checks.append(
                Check(
                    "iPhone 14 / iOS 16 target",
                    ios.startswith("16."),
                    f"{product or devices[0].name} · iOS {ios} (DikeLoader is built for iOS 16.1 + Dopamine)",
                )
            )
        else:
            checks.append(
                Check(
                    "Connected iPhone",
                    False,
                    "No USB/Wi-Fi iPhone found. Use a data cable or Wi-Fi sync, unlock, and tap Trust.",
                )
            )
    except Exception as exc:
        checks.append(Check("Connected iPhone", False, str(exc)))

    try:
        import paramiko  # noqa: F401

        checks.append(Check("paramiko (SSH)", True, "Installed."))
    except Exception as exc:
        checks.append(Check("paramiko (SSH)", False, str(exc)))

    try:
        from dikeloader.jailbreak.detect import probe_jailbreak
        from dikeloader.jailbreak.ssh import connect_ssh
        from dikeloader.store.settings import load_settings

        settings = load_settings()
        from dikeloader.device.connection import list_usb_devices

        devices = list_usb_devices()
        udid = devices[0].udid if devices else None
        if udid:
            try:
                ssh = connect_ssh(settings, udid=udid)
            except Exception as exc:
                checks.append(Check("Dopamine SSH", False, str(exc)))
            else:
                try:
                    info = probe_jailbreak(ssh, udid)
                    checks.append(
                        Check(
                            "Dopamine / jailbreak",
                            info.rootless or info.dopamine,
                            info.summary + (" · " + info.jb_prefix if info.jb_prefix else ""),
                        )
                    )
                    checks.append(
                        Check(
                            "TrollStore (CoreTrust)",
                            info.trollstore,
                            info.trollstore_helper or "Install TrollStore / TrollHelper on the iPhone.",
                        )
                    )
                    checks.append(
                        Check(
                            "LiveContainer",
                            info.livecontainer,
                            "Installed." if info.livecontainer else "Optional. Install via TrollStore to load apps in-container.",
                        )
                    )
                finally:
                    ssh.close()
        else:
            checks.append(Check("Dopamine SSH", False, "Connect the iPhone first."))
    except Exception as exc:
        checks.append(Check("Dopamine SSH", False, str(exc)))

    from dikeloader.service.refresh import task_installed

    checks.append(
        Check(
            "Auto-refresh task",
            True,
            "Installed (Apple ID apps only)." if task_installed() else "Not installed. Use the app or: python -m dikeloader service-install",
        )
    )

    return checks


def format_doctor(checks: list[Check] | None = None) -> str:
    checks = checks if checks is not None else run_doctor()
    lines = ["DikeLoader doctor (iPhone 14 · iOS 16.1 · Dopamine)", ""]
    for item in checks:
        mark = "OK" if item.ok else "FAIL"
        lines.append(f"[{mark}] {item.name}: {item.detail}")
    lines.append("")
    if all(c.ok for c in checks):
        lines.append("Ready.")
    else:
        lines.append("Fix the FAIL items before sideloading.")
    return "\n".join(lines)
