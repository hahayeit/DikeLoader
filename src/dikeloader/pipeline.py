# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import shutil
import tempfile

from dikeloader.apple.gsa import TwoFactorFn, login_apple_id
from dikeloader.apple.provision import provision_for_app
from dikeloader.device.connection import get_device
from dikeloader.device.installer import install_ipa
from dikeloader.exceptions import JailbreakError, KikeError, PackageError
from dikeloader.inject.dylib import prepare_ipa
from dikeloader.ipa.inspect import inspect_package
from dikeloader.jailbreak.debs import install_deb as jb_install_deb
from dikeloader.jailbreak.detect import probe_jailbreak
from dikeloader.jailbreak.livecontainer import install_into_livecontainer
from dikeloader.jailbreak.ssh import connect_ssh
from dikeloader.jailbreak.trollstore import install_ipa_trollstore
from dikeloader.paths import ipa_cache_dir
from dikeloader.sign.zsign import sign_ipa
from dikeloader.store.accounts import remember_account
from dikeloader.store.installs import InstallRecord, record_install
from dikeloader.store.secrets import set_apple_password
from dikeloader.store.settings import Settings, load_settings

ProgressFn = Callable[[str, int], None]


def _safe_id(bundle_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", bundle_id)


def _copy_as_ipa(source: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    return dest


def _dylib_paths(raw: list[str] | None) -> list[Path]:
    return [Path(p) for p in (raw or []) if p and Path(p).is_file()]


def sideload(
    package_path: str | Path,
    email: str = "",
    password: str = "",
    *,
    udid: str | None = None,
    strip_extensions: bool = True,
    two_factor: TwoFactorFn | None = None,
    progress: ProgressFn | None = None,
    remember: bool = True,
    method: str | None = None,
    settings: Settings | None = None,
    dylibs: list[str] | None = None,
    ssh_password: str | None = None,
) -> InstallRecord:
    def note(msg: str, pct: int = 0) -> None:
        if progress:
            progress(msg, pct)

    settings = settings or load_settings()
    method = method or settings.install_method
    dylib_files = _dylib_paths(dylibs if dylibs is not None else settings.inject_dylibs)

    path = Path(package_path)
    note("Reading package", 2)
    info = inspect_package(path)

    note("Connecting to iPhone", 8)
    device = get_device(udid)
    if not device.paired:
        raise KikeError("Unlock the iPhone and tap Trust This Computer.")

    cache = ipa_cache_dir() / f"{_safe_id(info.bundle_id)}.ipa"
    _copy_as_ipa(path, cache)

    with tempfile.TemporaryDirectory(prefix="dikeloader-") as tmp:
        prepared = Path(tmp) / f"{_safe_id(info.bundle_id)}-ready.ipa"
        if method == "apple":
            if device.developer_mode is False:
                raise KikeError(
                    "Turn on Developer Mode first: Settings → Privacy & Security → Developer Mode, then reboot."
                )
            if not email or not password:
                raise KikeError("Apple ID signing needs an Apple ID and password.")
            note("Signing in to Apple", 15)
            session = login_apple_id(email, password, two_factor=two_factor)
            if remember:
                set_apple_password(email, password)
                remember_account(email)

            def provision_note(msg: str) -> None:
                note(msg, 30)

            artifacts = provision_for_app(session, device, info, progress=provision_note)
            note("Signing IPA (SHA-256)", 55)
            signed = Path(tmp) / f"{_safe_id(info.bundle_id)}-signed.ipa"
            sign_ipa(
                cache,
                signed,
                artifacts.p12_path,
                artifacts.p12_password,
                artifacts.profile_path,
                strip_extensions=strip_extensions,
                dylibs=dylib_files,
            )
            prepared = signed
            note("Installing on iPhone", 75)

            def install_progress(percent: int, stage: str) -> None:
                note(stage, 75 + min(20, max(0, percent) // 5))

            install_ipa(device.udid, prepared, progress=install_progress, upgrade=False)
            expiry = artifacts.expiry
            if expiry is None and artifacts.free_team:
                expiry = datetime.now(timezone.utc) + timedelta(days=7)
            record = InstallRecord(
                bundle_id=info.bundle_id,
                name=info.display_name,
                email=session.email,
                udid=device.udid,
                cache_path=str(cache),
                signed_at=datetime.now(timezone.utc).isoformat(),
                expires_at=expiry.isoformat() if expiry else None,
                team_id=artifacts.team_id,
                version=info.version,
                method="apple",
            )
        else:
            if dylib_files:
                note("Ad-hoc sign + dylib inject", 20)
            else:
                note("Preparing IPA for jailbreak install", 20)
            prepare_ipa(cache, prepared, dylib_files)
            note("Opening SSH to Dopamine", 40)
            ssh = connect_ssh(settings, udid=device.udid, password=ssh_password)
            try:
                jb = probe_jailbreak(ssh, device.udid)
                if method == "trollstore":
                    note("TrollStore CoreTrust install", 70)
                    install_ipa_trollstore(ssh, prepared, jb)
                elif method == "livecontainer":
                    note("Copying into LiveContainer", 70)
                    install_into_livecontainer(ssh, prepared)
                elif method == "appsync":
                    note("AppSync / lockdown install", 70)
                    install_ipa(device.udid, prepared, upgrade=False)
                else:
                    raise JailbreakError(f"Unknown install method: {method}")
            finally:
                ssh.close()
            record = InstallRecord(
                bundle_id=info.bundle_id,
                name=info.display_name,
                email=email or "",
                udid=device.udid,
                cache_path=str(cache),
                signed_at=datetime.now(timezone.utc).isoformat(),
                expires_at=None,
                team_id="",
                version=info.version,
                method=method,
            )

    record_install(record)
    note("Done", 100)
    return record


def install_deb_package(
    deb_path: str | Path,
    *,
    udid: str | None = None,
    settings: Settings | None = None,
    ssh_password: str | None = None,
    progress: ProgressFn | None = None,
) -> str:
    def note(msg: str, pct: int = 0) -> None:
        if progress:
            progress(msg, pct)

    settings = settings or load_settings()
    path = Path(deb_path)
    note("Connecting", 10)
    device = get_device(udid)
    note("SSH", 30)
    ssh = connect_ssh(settings, udid=device.udid, password=ssh_password)
    try:
        note("dpkg -i", 60)
        return jb_install_deb(ssh, path)
    finally:
        ssh.close()


def refresh_install(
    bundle_id: str,
    email: str,
    password: str,
    *,
    udid: str | None = None,
    strip_extensions: bool = True,
    two_factor: TwoFactorFn | None = None,
    progress: ProgressFn | None = None,
) -> InstallRecord:
    from dikeloader.store.installs import list_installs

    matches = [r for r in list_installs() if r.bundle_id == bundle_id]
    if udid:
        matches = [r for r in matches if r.udid == udid] or matches
    if not matches:
        raise PackageError("DikeLoader has no cached copy of that app. Drop the .ipa / .tipa again.")
    row = matches[-1]
    if row.method in {"trollstore", "livecontainer", "appsync"}:
        raise PackageError(
            "This app was installed with TrollStore/LiveContainer/AppSync — it does not expire. No refresh needed."
        )
    cache = Path(row.cache_path)
    if not cache.is_file():
        raise PackageError(
            f"The cached IPA for {bundle_id} is gone. Drop the original .ipa / .tipa and install it again."
        )
    return sideload(
        cache,
        email,
        password,
        udid=udid or row.udid,
        strip_extensions=strip_extensions,
        two_factor=two_factor,
        progress=progress,
        remember=True,
        method="apple",
    )


def refresh_all_apple(
    email: str,
    password: str,
    *,
    two_factor: TwoFactorFn | None = None,
    progress: ProgressFn | None = None,
) -> list[InstallRecord]:
    from dikeloader.store.installs import list_installs

    done: list[InstallRecord] = []
    for row in list_installs():
        if row.method != "apple":
            continue
        days = row.days_left()
        if days is not None and days > 2:
            continue
        cache = Path(row.cache_path)
        if not cache.is_file():
            continue
        done.append(
            sideload(
                cache,
                email,
                password,
                udid=row.udid or None,
                two_factor=two_factor,
                progress=progress,
                method="apple",
            )
        )
    return done
