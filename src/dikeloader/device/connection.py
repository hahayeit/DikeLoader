# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from dikeloader.exceptions import DeviceError

T = TypeVar("T")


def run_async(coro: Awaitable[T]) -> T:
    """Run an async function from a worker thread or CLI (no running loop)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise DeviceError("Device calls must run off the UI thread.")


async def maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


@dataclass
class ConnectedDevice:
    udid: str
    name: str
    ios_version: str
    product_type: str
    connection_type: str
    paired: bool
    developer_mode: bool | None
    serial: str = ""

    @property
    def summary(self) -> str:
        mode = "unknown"
        if self.developer_mode is True:
            mode = "on"
        elif self.developer_mode is False:
            mode = "off"
        return (
            f"{self.name}  ·  iOS {self.ios_version}  ·  {self.connection_type}  ·  "
            f"Developer Mode {mode}"
        )


def _connection_type(dev: Any) -> str:
    raw = getattr(dev, "connection_type", None) or getattr(dev, "type", None) or "USB"
    if hasattr(raw, "value"):
        raw = raw.value
    text = str(raw).upper()
    if "NET" in text or "WIFI" in text:
        return "Wi-Fi"
    return "USB"


async def _usbmux_devices() -> list[Any]:
    from pymobiledevice3 import usbmux

    for name in ("list_devices", "list"):
        lister = getattr(usbmux, name, None)
        if lister is None:
            continue
        devices = await maybe_await(lister())
        return list(devices or [])
    raise DeviceError("pymobiledevice3.usbmux.list_devices is missing.")


async def _open_lockdown(udid: str | None, autopair: bool, connection_type: str = "USB"):
    from pymobiledevice3.lockdown import create_using_usbmux

    mux_type = "Network" if connection_type == "Wi-Fi" else "USB"
    kwargs: dict[str, Any] = {
        "label": "DikeLoader",
        "autopair": autopair,
        "connection_type": mux_type,
    }
    if udid:
        kwargs["serial"] = udid
    try:
        return await create_using_usbmux(**kwargs)
    except Exception:
        if mux_type != "USB":
            kwargs["connection_type"] = "USB"
            return await create_using_usbmux(**kwargs)
        raise


async def _close_lockdown(client: Any) -> None:
    for name in ("aclose", "close"):
        meth = getattr(client, name, None)
        if meth is None:
            continue
        try:
            await maybe_await(meth())
        except Exception:
            pass
        return


async def _read_device(mux_dev: Any) -> ConnectedDevice:
    serial = str(getattr(mux_dev, "serial", "") or "")
    conn = _connection_type(mux_dev)

    paired = False
    name = "iPhone"
    ios = "?"
    product = ""
    serial_no = serial
    developer_mode: bool | None = None
    client = None
    try:
        client = await _open_lockdown(serial or None, autopair=False, connection_type=conn)
        paired = bool(getattr(client, "paired", False))
        values = {}
        all_values = getattr(client, "all_values", None)
        if callable(all_values):
            values = await maybe_await(all_values()) or {}
        elif isinstance(all_values, dict):
            values = all_values
        short = getattr(client, "short_info", None)
        if not values and isinstance(short, dict):
            values = short
        name = (
            str(values.get("DeviceName") or getattr(client, "display_name", None) or "iPhone")
        )
        ios = str(
            values.get("ProductVersion")
            or getattr(client, "product_version", None)
            or "?"
        )
        product = str(values.get("ProductType") or "")
        serial_no = str(values.get("SerialNumber") or serial)
        udid = str(
            values.get("UniqueDeviceID")
            or getattr(client, "udid", None)
            or serial
        )
        if "DeveloperModeStatus" in values:
            developer_mode = bool(values["DeveloperModeStatus"])
        serial = udid or serial
    except Exception:
        paired = False
    finally:
        if client is not None:
            await _close_lockdown(client)

    return ConnectedDevice(
        udid=serial,
        name=name,
        ios_version=ios,
        product_type=product,
        connection_type=conn,
        paired=paired,
        developer_mode=developer_mode,
        serial=serial_no,
    )


async def _list_usb_devices() -> list[ConnectedDevice]:
    try:
        mux_devices = await _usbmux_devices()
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc).strip() or name
        lower = message.lower()
        if "no device" in lower or "not found" in lower:
            return []
        raise DeviceError(
            "Could not talk to usbmux. Install Apple Devices (Microsoft Store) or iTunes, "
            f"then reconnect the cable. ({name})"
        ) from exc

    result: list[ConnectedDevice] = []
    for dev in mux_devices:
        try:
            result.append(await _read_device(dev))
        except Exception:
            serial = str(getattr(dev, "serial", "") or "")
            result.append(
                ConnectedDevice(
                    udid=serial,
                    name="iPhone",
                    ios_version="?",
                    product_type="",
                    connection_type="USB",
                    paired=False,
                    developer_mode=None,
                    serial=serial,
                )
            )
    return result


def list_usb_devices() -> list[ConnectedDevice]:
    return run_async(_list_usb_devices())


async def _get_device(udid: str | None) -> ConnectedDevice:
    devices = await _list_usb_devices()
    if not devices:
        raise DeviceError(
            "No iPhone on USB or Wi-Fi. Plug in a data cable or enable Wi-Fi sync, unlock, and tap Trust."
        )
    if udid:
        for device in devices:
            if device.udid == udid:
                return device
        raise DeviceError(f"Device {udid} is not connected over USB or Wi-Fi.")
    if len(devices) == 1:
        return devices[0]
    raise DeviceError("Multiple iPhones are connected. Unplug the extras or pick one in the UI.")


def get_device(udid: str | None = None) -> ConnectedDevice:
    return run_async(_get_device(udid))


async def with_lockdown(udid: str, fn: Callable[[Any], Awaitable[T]], *, autopair: bool = True) -> T:
    client = None
    try:
        try:
            client = await _open_lockdown(udid, autopair=autopair, connection_type="USB")
        except Exception:
            client = await _open_lockdown(udid, autopair=autopair, connection_type="Wi-Fi")
        return await fn(client)
    except Exception as exc:
        name = type(exc).__name__
        text = str(exc)
        if "Pairing" in name or "UserDenied" in name:
            raise DeviceError("Unlock the iPhone and tap Trust This Computer.") from exc
        if "PasswordRequired" in name:
            raise DeviceError("Unlock the iPhone, then try again.") from exc
        if "NoDevice" in name or "not found" in text.lower():
            raise DeviceError("The iPhone disconnected. Replug the USB cable.") from exc
        raise DeviceError(text or name) from exc
    finally:
        if client is not None:
            await _close_lockdown(client)
