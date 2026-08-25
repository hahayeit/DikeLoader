# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from dikeloader.device.connection import maybe_await, run_async, with_lockdown
from dikeloader.exceptions import InstallError


ProgressCb = Callable[[int, str], None]


def _handler(progress: ProgressCb | None, stage: str) -> Callable[..., None] | None:
    if progress is None:
        return None

    def inner(percent: Any, *_args: Any) -> None:
        try:
            value = int(percent)
        except (TypeError, ValueError):
            value = 0
        progress(value, stage)

    return inner


async def _service(lockdown: Any):
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    svc = InstallationProxyService(lockdown=lockdown)
    entered = False
    if hasattr(svc, "__aenter__"):
        svc = await svc.__aenter__()
        entered = True
    return svc, entered


async def _exit_service(svc: Any, entered: bool) -> None:
    if entered and hasattr(svc, "__aexit__"):
        await maybe_await(svc.__aexit__(None, None, None))


async def _install(udid: str, ipa_path: Path, progress: ProgressCb | None, upgrade: bool) -> None:
    path = Path(ipa_path)
    if not path.is_file():
        raise InstallError(f"Signed IPA is missing: {path}")

    async def work(lockdown: Any) -> None:
        svc, entered = await _service(lockdown)
        try:
            cmd = "Upgrade" if upgrade else "Install"
            handler = _handler(progress, "Installing on iPhone")
            await maybe_await(svc.install_from_local(path, cmd=cmd, handler=handler))
        except Exception as exc:
            if upgrade:
                raise
            # Already installed — replace in place so refresh does not eat a slot.
            message = str(exc).lower()
            if "already" in message or "upgrade" in message or "exists" in message:
                handler = _handler(progress, "Replacing existing install")
                await maybe_await(svc.install_from_local(path, cmd="Upgrade", handler=handler))
                return
            raise
        finally:
            await _exit_service(svc, entered)

    try:
        await with_lockdown(udid, work)
    except InstallError:
        raise
    except Exception as exc:
        raise InstallError(_friendly_install_error(exc)) from exc


def _friendly_install_error(exc: BaseException) -> str:
    text = str(exc)
    lower = text.lower()
    if "applicationverificationfailed" in lower or "verify" in lower:
        return (
            "iOS rejected the signature. Trust the developer on the iPhone under "
            "Settings → General → VPN & Device Management, turn on Developer Mode, "
            "and try again."
        )
    if "developer mode" in lower:
        return "Turn on Settings → Privacy & Security → Developer Mode, reboot, then retry."
    if "max" in lower and "app" in lower:
        return (
            "This iPhone already has three free-sideloaded apps. Uninstall one, "
            "or use a paid Apple Developer account."
        )
    return text or type(exc).__name__


def install_ipa(
    udid: str,
    ipa_path: str | Path,
    progress: ProgressCb | None = None,
    *,
    upgrade: bool = False,
) -> None:
    run_async(_install(udid, Path(ipa_path), progress, upgrade))


async def _uninstall(udid: str, bundle_id: str) -> None:
    async def work(lockdown: Any) -> None:
        svc, entered = await _service(lockdown)
        try:
            await maybe_await(svc.uninstall(bundle_id))
        finally:
            await _exit_service(svc, entered)

    try:
        await with_lockdown(udid, work)
    except Exception as exc:
        raise InstallError(f"Could not uninstall {bundle_id}: {exc}") from exc


def uninstall_app(udid: str, bundle_id: str) -> None:
    run_async(_uninstall(udid, bundle_id))


async def _list_user_apps(udid: str) -> list[dict[str, str]]:
    async def work(lockdown: Any) -> list[dict[str, str]]:
        svc, entered = await _service(lockdown)
        try:
            try:
                apps = await maybe_await(svc.get_apps(application_type="User"))
            except Exception:
                apps = await maybe_await(svc.get_apps())
            if not apps:
                try:
                    all_apps = await maybe_await(svc.get_apps(application_type="Any"))
                    apps = {
                        key: val
                        for key, val in (all_apps or {}).items()
                        if str(val.get("ApplicationType") or "User") == "User"
                    }
                except Exception:
                    pass
        finally:
            await _exit_service(svc, entered)
        rows: list[dict[str, str]] = []
        for bundle_id, info in (apps or {}).items():
            rows.append(
                {
                    "bundle_id": bundle_id,
                    "name": str(
                        info.get("CFBundleDisplayName")
                        or info.get("CFBundleName")
                        or bundle_id
                    ),
                    "version": str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or ""),
                    "signer": str(info.get("SignerIdentity") or ""),
                }
            )
        rows.sort(key=lambda r: r["name"].lower())
        return rows

    try:
        return await with_lockdown(udid, work)
    except Exception as exc:
        raise InstallError(f"Could not list apps: {exc}") from exc


def list_user_apps(udid: str) -> list[dict[str, str]]:
    return run_async(_list_user_apps(udid))
