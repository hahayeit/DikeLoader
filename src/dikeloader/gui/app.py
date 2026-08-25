# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import queue
import re
import threading

import customtkinter as ctk
from PIL import Image

from dikeloader import __version__
from dikeloader.device.connection import ConnectedDevice, list_usb_devices
from dikeloader.device.installer import list_user_apps, uninstall_app
from dikeloader.doctor import format_doctor, run_doctor
from dikeloader.exceptions import EncryptedIpaError, PackageError
from dikeloader.ipa.inspect import PackageInfo, inspect_package
from dikeloader.pipeline import install_deb_package, refresh_install, sideload
from dikeloader.service.refresh import install_refresh_task, task_installed, uninstall_refresh_task
from dikeloader.store.accounts import active_email, list_saved_emails
from dikeloader.store.installs import forget_install, list_installs
from dikeloader.store.secrets import get_apple_password, get_ssh_password, set_ssh_password
from dikeloader.store.settings import Settings, load_settings, save_settings

ACCENT = "#3D8BFF"
BG = "#101218"
CARD = "#181B24"
MUTED = "#9AA0AE"
OK = "#3DD68C"
WARN = "#F5C542"
ERR = "#FF6B6B"

METHODS = {
    "trollstore": "TrollStore (CoreTrust, permanent)",
    "livecontainer": "LiveContainer",
    "appsync": "AppSync / lockdown",
    "apple": "Apple ID (7-day cert)",
}


try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    class _Root(ctk.CTk, TkinterDnD.DnDWrapper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)

    HAS_DND = True
except Exception:
    _Root = ctk.CTk  # type: ignore[misc, assignment]
    DND_FILES = None
    HAS_DND = False


class LoginDialog(ctk.CTkToplevel):
    def __init__(self, master, email: str = "") -> None:
        super().__init__(master)
        self.title("Apple ID")
        self.geometry("420x280")
        self.resizable(False, False)
        self.result: tuple[str, str] | None = None
        self.transient(master)
        self.grab_set()

        ctk.CTkLabel(self, text="Sign in with your Apple ID", font=ctk.CTkFont(size=18, weight="bold")).pack(
            pady=(20, 6)
        )
        ctk.CTkLabel(
            self,
            text="Only needed for the 7-day Apple ID path. Stored in Windows Credential Manager.",
            text_color=MUTED,
            wraplength=360,
        ).pack(pady=(0, 12))

        self.email = ctk.CTkEntry(self, placeholder_text="Apple ID email", width=320)
        self.email.pack(pady=6)
        if email:
            self.email.insert(0, email)
        self.password = ctk.CTkEntry(self, placeholder_text="Password", width=320, show="•")
        self.password.pack(pady=6)
        self.password.bind("<Return>", lambda _e: self._ok())

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=16)
        ctk.CTkButton(row, text="Cancel", fg_color="#2A2E3A", hover_color="#343949", width=120, command=self.destroy).pack(
            side="left", padx=8
        )
        ctk.CTkButton(row, text="Sign in", fg_color=ACCENT, hover_color="#2F73D9", width=120, command=self._ok).pack(
            side="left", padx=8
        )
        self.after(50, self.email.focus)

    def _ok(self) -> None:
        email = self.email.get().strip()
        password = self.password.get()
        if not email or not password:
            return
        self.result = (email, password)
        self.destroy()


class DikeApp(_Root):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"DikeLoader  {__version__}")
        self.geometry("1080x900")
        self.minsize(920, 740)
        self.configure(fg_color=BG)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.device: ConnectedDevice | None = None
        self.package: PackageInfo | None = None
        self.settings: Settings = load_settings()
        self.email = active_email() or (list_saved_emails()[0] if list_saved_emails() else "")
        self._busy = False
        self._icon_image = None
        self._events: queue.Queue = queue.Queue()
        self._dylibs: list[str] = list(self.settings.inject_dylibs)

        self._build()
        self.after(200, self.refresh_device)
        self.after(250, self._pump)
        self.after(5000, self._poll_device)

        if HAS_DND and DND_FILES is not None:
            try:
                self.drop_target_register(DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(18, 8))
        ctk.CTkLabel(header, text="DikeLoader", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text="iPhone 14 · iOS 16.1 · Dopamine", text_color=MUTED).pack(side="left", padx=12)
        ctk.CTkButton(header, text="Doctor", width=90, fg_color="#2A2E3A", command=self.show_doctor).pack(side="right")

        self.device_bar = ctk.CTkFrame(self, fg_color=CARD, corner_radius=12)
        self.device_bar.pack(fill="x", padx=22, pady=8)
        self.device_label = ctk.CTkLabel(
            self.device_bar,
            text="No iPhone on USB / Wi-Fi",
            anchor="w",
            font=ctk.CTkFont(size=14),
        )
        self.device_label.pack(fill="x", padx=16, pady=(12, 2))
        self.udid_label = ctk.CTkLabel(self.device_bar, text="", anchor="w", text_color=MUTED)
        self.udid_label.pack(fill="x", padx=16, pady=(0, 4))
        self.jb_label = ctk.CTkLabel(self.device_bar, text="", anchor="w", text_color=MUTED)
        self.jb_label.pack(fill="x", padx=16, pady=(0, 12))

        ssh = ctk.CTkFrame(self, fg_color=CARD, corner_radius=12)
        ssh.pack(fill="x", padx=22, pady=8)
        ctk.CTkLabel(ssh, text="SSH (OpenSSH on Dopamine)", anchor="w").pack(fill="x", padx=16, pady=(12, 4))
        row = ctk.CTkFrame(ssh, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 8))
        self.usb_ssh = ctk.BooleanVar(value=self.settings.use_usb_ssh)
        ctk.CTkCheckBox(row, text="USB SSH (iproxy :2222 → 22)", variable=self.usb_ssh, command=self._persist).pack(
            side="left"
        )
        self.wifi_var = ctk.BooleanVar(value=self.settings.prefer_wifi)
        ctk.CTkCheckBox(row, text="Prefer Wi-Fi IP", variable=self.wifi_var, command=self._persist).pack(
            side="left", padx=16
        )
        row2 = ctk.CTkFrame(ssh, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 12))
        self.wifi_ip = ctk.CTkEntry(row2, placeholder_text="Wi-Fi IP (optional)", width=180)
        self.wifi_ip.pack(side="left")
        if self.settings.wifi_ssh_host:
            self.wifi_ip.insert(0, self.settings.wifi_ssh_host)
        self.wifi_ip.bind("<FocusOut>", lambda _e: self._persist())
        self.ssh_pass = ctk.CTkEntry(row2, placeholder_text="SSH password (default alpine)", width=220, show="•")
        self.ssh_pass.pack(side="left", padx=10)
        saved = get_ssh_password(self.settings.ssh_user)
        if saved:
            self.ssh_pass.insert(0, saved)

        account = ctk.CTkFrame(self, fg_color=CARD, corner_radius=12)
        account.pack(fill="x", padx=22, pady=8)
        self.account_label = ctk.CTkLabel(account, text=self._account_text(), anchor="w")
        self.account_label.pack(side="left", padx=16, pady=12)
        ctk.CTkButton(account, text="Apple ID", width=110, fg_color="#2A2E3A", command=self.sign_in).pack(
            side="right", padx=16, pady=12
        )

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=8)

        left = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.drop = ctk.CTkFrame(left, fg_color="#12141C", corner_radius=10, height=120)
        self.drop.pack(fill="x", padx=16, pady=16)
        self.drop_label = ctk.CTkLabel(
            self.drop,
            text="Drop an .ipa / .tipa / .deb here\n(or browse)",
            text_color=MUTED,
            font=ctk.CTkFont(size=16),
        )
        self.drop_label.pack(expand=True, pady=20)
        brow = ctk.CTkFrame(left, fg_color="transparent")
        brow.pack(fill="x", padx=16)
        ctk.CTkButton(brow, text="Browse IPA…", width=140, fg_color="#2A2E3A", command=self.browse).pack(side="left")
        ctk.CTkButton(brow, text="Install .deb…", width=140, fg_color="#2A2E3A", command=self.browse_deb).pack(
            side="left", padx=8
        )

        meta = ctk.CTkFrame(left, fg_color="transparent")
        meta.pack(fill="x", padx=16, pady=8)
        self.icon_label = ctk.CTkLabel(meta, text="", width=56, height=56)
        self.icon_label.pack(side="left", padx=(0, 12))
        self.pkg_label = ctk.CTkLabel(meta, text="No package selected", anchor="w", justify="left")
        self.pkg_label.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(left, text="Install method", anchor="w", text_color=MUTED).pack(fill="x", padx=16)
        self.method = ctk.CTkSegmentedButton(
            left,
            values=["trollstore", "livecontainer", "appsync", "apple"],
            command=lambda _v: self._persist(),
        )
        self.method.pack(fill="x", padx=16, pady=(4, 4))
        self.method.set(self.settings.install_method if self.settings.install_method in METHODS else "trollstore")
        self.method_hint = ctk.CTkLabel(left, text=METHODS["trollstore"], text_color=MUTED, anchor="w")
        self.method_hint.pack(fill="x", padx=16, pady=(0, 8))

        dyl = ctk.CTkFrame(left, fg_color="transparent")
        dyl.pack(fill="x", padx=16, pady=4)
        ctk.CTkButton(dyl, text="Add dylib…", width=120, fg_color="#2A2E3A", command=self.add_dylib).pack(side="left")
        ctk.CTkButton(dyl, text="Clear dylibs", width=110, fg_color="#2A2E3A", command=self.clear_dylibs).pack(
            side="left", padx=8
        )
        self.dylib_label = ctk.CTkLabel(left, text="No dylibs", text_color=MUTED, anchor="w", wraplength=520)
        self.dylib_label.pack(fill="x", padx=16, pady=(0, 6))
        self._refresh_dylib_label()

        self.strip_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            left,
            text="Strip app extensions (Apple ID path only)",
            variable=self.strip_var,
            text_color=MUTED,
        ).pack(anchor="w", padx=16, pady=4)

        self.sideload_btn = ctk.CTkButton(
            left, text="Install", height=40, fg_color=ACCENT, hover_color="#2F73D9", command=self.start_sideload
        )
        self.sideload_btn.pack(fill="x", padx=16, pady=(8, 6))
        self.progress = ctk.CTkProgressBar(left, progress_color=ACCENT)
        self.progress.pack(fill="x", padx=16, pady=(4, 4))
        self.progress.set(0)
        self.status = ctk.CTkLabel(
            left,
            text="Ready — TrollStore install does not use a 7-day cert.",
            text_color=MUTED,
            anchor="w",
            justify="left",
            wraplength=520,
        )
        self.status.pack(fill="x", padx=16, pady=(0, 6))

        svc = ctk.CTkFrame(left, fg_color="transparent")
        svc.pack(fill="x", padx=16, pady=(0, 12))
        ctk.CTkButton(svc, text="Install auto-refresh task", width=200, fg_color="#2A2E3A", command=self.install_service).pack(
            side="left"
        )
        ctk.CTkButton(svc, text="Remove task", width=120, fg_color="#2A2E3A", command=self.remove_service).pack(
            side="left", padx=8
        )

        right = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12, width=340)
        right.pack(side="right", fill="both", padx=(8, 0))
        right.pack_propagate(False)
        head = ctk.CTkFrame(right, fg_color="transparent")
        head.pack(fill="x", padx=12, pady=(12, 4))
        ctk.CTkLabel(head, text="Installed apps", font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        ctk.CTkButton(head, text="Refresh list", width=90, fg_color="#2A2E3A", command=self.reload_apps).pack(side="right")
        self.apps_frame = ctk.CTkScrollableFrame(right, fg_color="transparent")
        self.apps_frame.pack(fill="both", expand=True, padx=8, pady=8)

        foot = ctk.CTkLabel(
            self,
            text="Dopamine is semi-untethered: after a reboot, open Dopamine to re-jailbreak before SSH/TrollStore. TrollStore apps survive reboots.",
            text_color=MUTED,
            wraplength=980,
        )
        foot.pack(fill="x", padx=22, pady=(0, 12))
        self._sync_method_hint()

    def _persist(self) -> None:
        self.settings.install_method = self.method.get() or "trollstore"
        self.settings.use_usb_ssh = bool(self.usb_ssh.get())
        self.settings.prefer_wifi = bool(self.wifi_var.get())
        self.settings.wifi_ssh_host = self.wifi_ip.get().strip()
        self.settings.inject_dylibs = list(self._dylibs)
        save_settings(self.settings)
        pw = self.ssh_pass.get()
        if pw:
            set_ssh_password(self.settings.ssh_user, pw)
        self._sync_method_hint()

    def _sync_method_hint(self) -> None:
        key = self.method.get() if hasattr(self, "method") else "trollstore"
        self.method_hint.configure(text=METHODS.get(key, ""))

    def _account_text(self) -> str:
        if self.email:
            return f"Apple ID  ·  {self.email}  (only for 7-day path)"
        return "Apple ID  ·  not signed in (not needed for TrollStore)"

    def _set_status(self, text: str, *, error: bool = False, pct: int | None = None) -> None:
        self.status.configure(text=text, text_color=ERR if error else MUTED)
        if pct is not None:
            self.progress.set(max(0, min(100, pct)) / 100)

    def _pump(self) -> None:
        try:
            while True:
                fn = self._events.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.after(80, self._pump)

    def ui(self, fn) -> None:
        self._events.put(fn)

    def _poll_device(self) -> None:
        if not self._busy:
            threading.Thread(target=self._refresh_device_bg, daemon=True).start()
        self.after(8000, self._poll_device)

    def refresh_device(self) -> None:
        threading.Thread(target=self._refresh_device_bg, daemon=True).start()

    def _refresh_device_bg(self) -> None:
        try:
            devices = list_usb_devices()
        except Exception as exc:
            self.ui(lambda: self._show_device(None, str(exc), None))
            return
        device = devices[0] if devices else None
        jb_text = ""
        if device and device.paired:
            try:
                from dikeloader.jailbreak.detect import probe_jailbreak
                from dikeloader.jailbreak.ssh import connect_ssh

                self._persist()
                ssh = connect_ssh(self.settings, udid=device.udid, password=self.ssh_pass.get() or None)
                try:
                    info = probe_jailbreak(ssh, device.udid)
                    jb_text = info.summary
                finally:
                    ssh.close()
            except Exception as exc:
                jb_text = f"SSH: {exc}"
        self.ui(lambda: self._show_device(device, None, jb_text))

    def _show_device(self, device: ConnectedDevice | None, error: str | None, jb: str | None) -> None:
        self.device = device
        if error:
            self.device_label.configure(text=f"Device error: {error}", text_color=ERR)
            self.udid_label.configure(text="")
            self.jb_label.configure(text="")
            return
        if device is None:
            self.device_label.configure(text="No iPhone on USB / Wi-Fi", text_color=WARN)
            self.udid_label.configure(text="Plug in a data cable (or Wi-Fi sync), unlock, and tap Trust.")
            self.jb_label.configure(text="")
            return
        color = OK if device.paired else WARN
        self.device_label.configure(text=device.summary, text_color=color)
        extra = f"UDID  {device.udid}"
        if not device.paired:
            extra += "  ·  tap Trust This Computer"
        self.udid_label.configure(text=extra)
        self.jb_label.configure(text=jb or "Jailbreak status unknown until SSH works.", text_color=OK if jb and "Dopamine" in jb else MUTED)

    def sign_in(self) -> None:
        dlg = LoginDialog(self, self.email)
        self.wait_window(dlg)
        if not dlg.result:
            return
        email, password = dlg.result
        self.email = email
        from dikeloader.store.accounts import remember_account
        from dikeloader.store.secrets import set_apple_password

        try:
            set_apple_password(email, password)
            remember_account(email)
        except Exception:
            pass
        self.account_label.configure(text=self._account_text())
        self._set_status("Apple ID saved for the 7-day path.")

    def browse(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Choose IPA or TIPA",
            filetypes=[("iOS apps", "*.ipa *.tipa"), ("All files", "*.*")],
        )
        if path:
            self._load_package(path)

    def browse_deb(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(title="Choose .deb", filetypes=[("Debian packages", "*.deb")])
        if path:
            self.start_deb(path)

    def add_dylib(self) -> None:
        from tkinter import filedialog

        paths = filedialog.askopenfilenames(title="Choose dylibs", filetypes=[("Dylibs", "*.dylib"), ("All files", "*.*")])
        for path in paths:
            if path not in self._dylibs:
                self._dylibs.append(path)
        self._refresh_dylib_label()
        self._persist()

    def clear_dylibs(self) -> None:
        self._dylibs = []
        self._refresh_dylib_label()
        self._persist()

    def _refresh_dylib_label(self) -> None:
        if not self._dylibs:
            self.dylib_label.configure(text="No dylibs — optional inject into the IPA before install")
            return
        names = ", ".join(Path(p).name for p in self._dylibs)
        self.dylib_label.configure(text=f"Inject: {names}")

    def _on_drop(self, event) -> None:  # type: ignore[no-untyped-def]
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"):
            raw = raw[1:-1]
        path = raw.split("} {")[0].strip().strip("{}")
        if path.lower().endswith(".deb"):
            self.start_deb(path)
        elif path:
            self._load_package(path)

    def _load_package(self, path: str) -> None:
        try:
            info = inspect_package(path)
        except EncryptedIpaError as exc:
            self.package = None
            self.pkg_label.configure(text=str(exc))
            self._set_status(str(exc), error=True)
            return
        except PackageError as exc:
            self.package = None
            self.pkg_label.configure(text=str(exc))
            self._set_status(str(exc), error=True)
            return
        self.package = info
        extra = f"{info.display_name}\n{info.bundle_id}  ·  {info.version or 'unknown version'}"
        if info.suffix == ".tipa":
            extra += "\n.tipa treated as IPA — TrollStore will CoreTrust-sign it on iOS 16.1"
        self.pkg_label.configure(text=extra)
        self._set_icon(info.icon_png)
        self._set_status(f"Loaded {info.display_name}")

    def _set_icon(self, png: bytes | None) -> None:
        if not png:
            self.icon_label.configure(image=None, text="")
            self._icon_image = None
            return
        try:
            img = Image.open(BytesIO(png)).convert("RGBA").resize((56, 56))
            ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(56, 56))
            self._icon_image = ctk_img
            self.icon_label.configure(image=ctk_img, text="")
        except Exception:
            self.icon_label.configure(image=None, text="")
            self._icon_image = None

    def _two_factor(self, prompt: str) -> str:
        box: queue.Queue[str] = queue.Queue()

        def ask() -> None:
            dialog = ctk.CTkInputDialog(text=prompt, title="Apple ID verification")
            raw = dialog.get_input() or ""
            box.put(re.sub(r"\D", "", raw))

        self.ui(ask)
        try:
            return box.get(timeout=300)
        except queue.Empty:
            return ""

    def _credentials(self) -> tuple[str, str] | None:
        email = self.email
        password = get_apple_password(email) if email else None
        if email and password:
            return email, password
        dlg = LoginDialog(self, email)
        self.wait_window(dlg)
        if not dlg.result:
            return None
        self.email = dlg.result[0]
        self.account_label.configure(text=self._account_text())
        return dlg.result

    def start_sideload(self) -> None:
        if self._busy:
            return
        if self.package is None:
            self._set_status("Choose an .ipa or .tipa first.", error=True)
            return
        self._persist()
        method = self.method.get() or "trollstore"
        email, password = "", ""
        if method == "apple":
            creds = self._credentials()
            if not creds:
                return
            email, password = creds
        path = str(self.package.path)
        udid = self.device.udid if self.device else None
        strip = bool(self.strip_var.get())
        ssh_pw = self.ssh_pass.get() or None
        dylibs = list(self._dylibs)
        self._busy = True
        self.sideload_btn.configure(state="disabled")
        self._set_status("Starting…", pct=1)

        def work() -> None:
            try:
                record = sideload(
                    path,
                    email,
                    password,
                    udid=udid,
                    strip_extensions=strip,
                    two_factor=self._two_factor,
                    progress=lambda msg, pct: self.ui(lambda m=msg, p=pct: self._set_status(m, pct=p)),
                    method=method,
                    settings=self.settings,
                    dylibs=dylibs,
                    ssh_password=ssh_pw,
                )
            except Exception as exc:
                message = str(exc) or type(exc).__name__
                self.ui(lambda: self._sideload_done(error=message))
                return
            self.ui(lambda: self._sideload_done(record=record))

        threading.Thread(target=work, daemon=True).start()

    def start_deb(self, path: str) -> None:
        if self._busy:
            return
        self._persist()
        udid = self.device.udid if self.device else None
        ssh_pw = self.ssh_pass.get() or None
        self._busy = True
        self.sideload_btn.configure(state="disabled")
        self._set_status(f"Installing {Path(path).name}…", pct=5)

        def work() -> None:
            try:
                msg = install_deb_package(
                    path,
                    udid=udid,
                    settings=self.settings,
                    ssh_password=ssh_pw,
                    progress=lambda m, p: self.ui(lambda t=m, n=p: self._set_status(t, pct=n)),
                )
            except Exception as exc:
                self.ui(lambda: self._sideload_done(error=str(exc)))
                return
            self.ui(lambda: self._sideload_done(error=None, extra=msg[:240]))

        threading.Thread(target=work, daemon=True).start()

    def _sideload_done(self, record=None, error: str | None = None, extra: str | None = None) -> None:
        self._busy = False
        self.sideload_btn.configure(state="normal")
        if error:
            self._set_status(error, error=True)
            return
        if extra:
            self._set_status(extra, pct=100)
            return
        name = record.name if record else "App"
        method = getattr(record, "method", "") if record else ""
        if method in {"trollstore", "appsync"}:
            msg = f"{name} installed permanently (CoreTrust / jailbreak). No developer trust prompt."
        elif method == "livecontainer":
            msg = f"{name} copied into LiveContainer. Open LiveContainer to launch it."
        else:
            msg = f"{name} installed. Trust this Apple ID under Settings → General → VPN & Device Management."
        self._set_status(msg, pct=100)
        self.reload_apps()

    def reload_apps(self) -> None:
        threading.Thread(target=self._reload_apps_bg, daemon=True).start()

    def _reload_apps_bg(self) -> None:
        udid = self.device.udid if self.device else None
        device_apps = []
        if udid:
            try:
                device_apps = list_user_apps(udid)
            except Exception:
                device_apps = []
        local = list_installs()
        self.ui(lambda: self._render_apps(device_apps, local, udid))

    def _render_apps(self, device_apps: list[dict], local, udid: str | None) -> None:
        for child in self.apps_frame.winfo_children():
            child.destroy()
        by_id = {r.bundle_id: r for r in local if (not udid or r.udid == udid)}
        seen = set()
        rows = []
        for app in device_apps:
            bid = app["bundle_id"]
            seen.add(bid)
            rec = by_id.get(bid)
            days = rec.days_left() if rec else None
            method = rec.method if rec else ""
            rows.append((app["name"], bid, days, True, method))
        for rec in local:
            if rec.bundle_id in seen:
                continue
            if udid and rec.udid != udid:
                continue
            rows.append((rec.name, rec.bundle_id, rec.days_left(), False, rec.method))
        if not rows:
            ctk.CTkLabel(self.apps_frame, text="Nothing installed yet.", text_color=MUTED).pack(anchor="w")
            return
        for name, bid, days, on_device, method in rows:
            card = ctk.CTkFrame(self.apps_frame, fg_color="#12141C", corner_radius=8)
            card.pack(fill="x", pady=6)
            if method in {"trollstore", "livecontainer", "appsync"}:
                expiry = method + " · no expiry"
            elif days is None:
                expiry = "free cert · refresh weekly"
            elif days < 0:
                expiry = "expired — refresh"
            elif days == 0:
                expiry = "expires today"
            else:
                expiry = f"{days} day{'s' if days != 1 else ''} left"
            if not on_device:
                expiry += " · not on this iPhone"
            ctk.CTkLabel(card, text=name, anchor="w", font=ctk.CTkFont(weight="bold")).pack(fill="x", padx=10, pady=(8, 0))
            ctk.CTkLabel(card, text=f"{bid}\n{expiry}", anchor="w", text_color=MUTED, justify="left").pack(
                fill="x", padx=10
            )
            btns = ctk.CTkFrame(card, fg_color="transparent")
            btns.pack(fill="x", padx=8, pady=(4, 8))
            if method == "apple" or not method:
                ctk.CTkButton(
                    btns, text="Refresh", width=80, fg_color="#2A2E3A", command=lambda b=bid: self.start_refresh(b)
                ).pack(side="left", padx=4)
            ctk.CTkButton(
                btns, text="Uninstall", width=80, fg_color="#3A1F2A", hover_color="#5A2A38", command=lambda b=bid: self.start_uninstall(b)
            ).pack(side="left", padx=4)

    def start_refresh(self, bundle_id: str) -> None:
        if self._busy:
            return
        creds = self._credentials()
        if not creds:
            return
        email, password = creds
        udid = self.device.udid if self.device else None
        strip = bool(self.strip_var.get())
        self._busy = True
        self.sideload_btn.configure(state="disabled")

        def work() -> None:
            try:
                record = refresh_install(
                    bundle_id,
                    email,
                    password,
                    udid=udid,
                    strip_extensions=strip,
                    two_factor=self._two_factor,
                    progress=lambda msg, pct: self.ui(lambda m=msg, p=pct: self._set_status(m, pct=p)),
                )
            except Exception as exc:
                self.ui(lambda: self._sideload_done(error=str(exc)))
                return
            self.ui(lambda: self._sideload_done(record=record))

        threading.Thread(target=work, daemon=True).start()

    def start_uninstall(self, bundle_id: str) -> None:
        if not self.device:
            self._set_status("Connect an iPhone first.", error=True)
            return

        def work() -> None:
            try:
                uninstall_app(self.device.udid, bundle_id)  # type: ignore[union-attr]
                forget_install(bundle_id, self.device.udid)  # type: ignore[union-attr]
            except Exception as exc:
                self.ui(lambda: self._set_status(str(exc), error=True))
                return
            self.ui(lambda: (self._set_status(f"Uninstalled {bundle_id}"), self.reload_apps()))

        threading.Thread(target=work, daemon=True).start()

    def install_service(self) -> None:
        try:
            msg = install_refresh_task(12)
        except Exception as exc:
            self._set_status(str(exc), error=True)
            return
        self._set_status(msg)

    def remove_service(self) -> None:
        self._set_status(uninstall_refresh_task())

    def show_doctor(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Doctor")
        win.geometry("680x520")
        box = ctk.CTkTextbox(win, wrap="word")
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", "Running checks…")

        def work() -> None:
            text = format_doctor(run_doctor())
            extra = (
                "\nAuto-refresh task: "
                + ("installed" if task_installed() else "not installed")
            )
            self.ui(lambda: (box.delete("1.0", "end"), box.insert("1.0", text + extra)))

        threading.Thread(target=work, daemon=True).start()


def run_app() -> None:
    app = DikeApp()
    app.mainloop()
