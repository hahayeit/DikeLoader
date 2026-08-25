# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import threading
import time

from dikeloader.exceptions import JailbreakError

_lock = threading.Lock()
_thread: threading.Thread | None = None
_udid: str | None = None
_port: int | None = None


def ensure_usb_ssh_tunnel(udid: str, local_port: int = 2222, remote_port: int = 22) -> int:
    """Forward localhost:local_port to OpenSSH on the phone over USB."""
    global _thread, _udid, _port
    with _lock:
        if _thread is not None and _thread.is_alive() and _udid == udid and _port == local_port:
            return local_port

        def run() -> None:
            async def main() -> None:
                from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder

                listening = asyncio.Event()
                fwd = UsbmuxTcpForwarder(
                    udid,
                    remote_port,
                    local_port,
                    listening_event=listening,
                    usbmux_connection_type="USB",
                )
                task = asyncio.create_task(fwd.start("127.0.0.1"))
                await asyncio.wait_for(listening.wait(), timeout=8)
                await task

            try:
                asyncio.run(main())
            except Exception:
                pass

        _thread = threading.Thread(target=run, name="dikeloader-iproxy", daemon=True)
        _udid = udid
        _port = local_port
        _thread.start()

    deadline = time.time() + 8
    while time.time() < deadline:
        if _thread is not None and not _thread.is_alive():
            break
        try:
            import socket

            sock = socket.create_connection(("127.0.0.1", local_port), timeout=0.4)
            sock.close()
            return local_port
        except OSError:
            time.sleep(0.15)
    raise JailbreakError(
        "Could not open USB SSH. Install OpenSSH from Sileo on the iPhone, "
        "or enter the Wi-Fi IP and disable USB SSH."
    )
