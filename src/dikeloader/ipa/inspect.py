# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
import plistlib
import struct
import zipfile

from dikeloader.exceptions import EncryptedIpaError, PackageError

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C


@dataclass
class PackageInfo:
    path: Path
    display_name: str
    bundle_id: str
    version: str
    executable: str
    min_os: str
    encrypted: bool
    has_extensions: bool
    icon_png: bytes | None = None
    app_plist: dict = field(default_factory=dict)

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


def inspect_package(path: str | Path) -> PackageInfo:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix not in {".ipa", ".tipa"}:
        raise PackageError("Choose an .ipa or .tipa file.")
    if not file_path.is_file():
        raise PackageError(f"File not found: {file_path}")

    try:
        with zipfile.ZipFile(file_path) as zf:
            app_root = _payload_app(zf)
            plist_name = f"{app_root}Info.plist"
            try:
                plist_bytes = zf.read(plist_name)
            except KeyError as exc:
                raise PackageError("This package has no Info.plist inside Payload/*.app.") from exc
            try:
                info = plistlib.loads(plist_bytes)
            except Exception as exc:
                raise PackageError("Info.plist is not a valid Apple property list.") from exc

            bundle_id = str(info.get("CFBundleIdentifier") or "")
            if not bundle_id:
                raise PackageError("Info.plist is missing CFBundleIdentifier.")
            display = str(
                info.get("CFBundleDisplayName") or info.get("CFBundleName") or file_path.stem
            )
            version = str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "")
            executable = str(info.get("CFBundleExecutable") or "")
            min_os = str(info.get("MinimumOSVersion") or "")
            encrypted = _is_encrypted(zf, app_root, executable)
            has_extensions = any(
                name.startswith(f"{app_root}PlugIns/") or name.startswith(f"{app_root}Extensions/")
                for name in zf.namelist()
            )
            icon = _read_icon(zf, app_root, info)
    except zipfile.BadZipFile as exc:
        raise PackageError("That file is not a valid zip-based .ipa / .tipa.") from exc

    if encrypted:
        raise EncryptedIpaError(
            "This looks like an App Store IPA (FairPlay encryption). "
            "DikeLoader can only sign apps you are allowed to run that are not encrypted — "
            "for example builds from the developer, GitHub, or your own Xcode archive."
        )

    return PackageInfo(
        path=file_path,
        display_name=display,
        bundle_id=bundle_id,
        version=version,
        executable=executable,
        min_os=min_os,
        encrypted=False,
        has_extensions=has_extensions,
        icon_png=icon,
        app_plist=info,
    )


def _payload_app(zf: zipfile.ZipFile) -> str:
    apps = []
    for name in zf.namelist():
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            prefix = f"Payload/{parts[1]}/"
            if prefix not in apps:
                apps.append(prefix)
    if not apps:
        raise PackageError("No Payload/*.app folder inside this package.")
    return apps[0]


def _is_encrypted(zf: zipfile.ZipFile, app_root: str, executable: str) -> bool:
    names = set(zf.namelist())
    if f"{app_root}SC_Info/" in names or any(n.startswith(f"{app_root}SC_Info/") for n in names):
        # Dumped IPAs keep SC_Info even after decrypt; still check the Mach-O cryptid.
        pass
    candidates = []
    if executable:
        candidates.append(f"{app_root}{executable}")
    for name in zf.namelist():
        if name.startswith(app_root) and "/." not in name:
            rel = name[len(app_root) :]
            if "/" not in rel and rel and not rel.endswith("/"):
                candidates.append(name)
    seen: set[str] = set()
    for name in candidates:
        if name in seen or name not in names:
            continue
        seen.add(name)
        try:
            data = zf.read(name)
        except KeyError:
            continue
        cryptid = _macho_cryptid(data)
        if cryptid is None:
            continue
        if cryptid != 0:
            return True
        return False
    return False


def _macho_cryptid(data: bytes) -> int | None:
    if len(data) < 8:
        return None
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic == FAT_MAGIC else "<"
        nfat = struct.unpack(endian + "I", data[4:8])[0]
        if nfat <= 0 or nfat > 16:
            return None
        for i in range(nfat):
            off = 8 + i * 20
            if off + 20 > len(data):
                break
            _cpu, _sub, offset, size, _align = struct.unpack(endian + "IIIII", data[off : off + 20])
            slice_data = data[offset : offset + size]
            cryptid = _thin_cryptid(slice_data)
            if cryptid:
                return cryptid
        return 0 if nfat else None
    return _thin_cryptid(data)


def _thin_cryptid(data: bytes) -> int | None:
    if len(data) < 32:
        return None
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (MH_MAGIC, MH_MAGIC_64):
        endian = "<"
    elif magic in (MH_CIGAM, MH_CIGAM_64):
        endian = ">"
        magic = struct.unpack(">I", data[:4])[0]
    else:
        return None
    is64 = magic in (MH_MAGIC_64,)
    header_size = 32 if is64 else 28
    if len(data) < header_size:
        return None
    if is64:
        _magic, _cputype, _cpusub, _ftype, ncmds, sizeofcmds, _flags, _reserved = struct.unpack(
            endian + "IIIIIIII", data[:32]
        )
    else:
        _magic, _cputype, _cpusub, _ftype, ncmds, sizeofcmds, _flags = struct.unpack(
            endian + "IIIIIII", data[:28]
        )
    off = header_size
    end = min(len(data), header_size + sizeofcmds)
    for _ in range(min(ncmds, 256)):
        if off + 8 > end:
            break
        cmd, cmdsize = struct.unpack(endian + "II", data[off : off + 8])
        if cmdsize < 8:
            break
        cmd_id = cmd & 0xFFFFFFFF
        if cmd_id in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cryptoff, cryptsize, cryptid [, pad]
            if off + 16 > len(data):
                return None
            _coff, _csize, cryptid = struct.unpack(endian + "III", data[off + 8 : off + 20])
            return int(cryptid)
        off += cmdsize
    return 0


def _read_icon(zf: zipfile.ZipFile, app_root: str, info: dict) -> bytes | None:
    names = []
    icons = info.get("CFBundleIcons") or {}
    primary = icons.get("CFBundlePrimaryIcon") or {}
    files = primary.get("CFBundleIconFiles") or info.get("CFBundleIconFiles") or []
    if isinstance(files, str):
        files = [files]
    icon_name = info.get("CFBundleIconFile")
    if icon_name:
        files = list(files) + [icon_name]
    for base in files:
        base = str(base)
        for extra in ("", "@2x", "@3x"):
            for ext in ("", ".png"):
                names.append(f"{app_root}{base}{extra}{ext}")
    names.extend(
        n
        for n in zf.namelist()
        if n.startswith(app_root)
        and n.lower().endswith(".png")
        and "appicon" in n.lower().rsplit("/", 1)[-1]
    )
    seen: set[str] = set()
    best: bytes | None = None
    for name in names:
        if name in seen or name not in zf.namelist():
            continue
        seen.add(name)
        try:
            raw = zf.read(name)
        except KeyError:
            continue
        png = _maybe_png(raw)
        if png and (best is None or len(png) > len(best)):
            best = png
    return best


def _maybe_png(raw: bytes) -> bytes | None:
    if not raw.startswith(b"\x89PNG"):
        return None
    try:
        from PIL import Image

        Image.open(BytesIO(raw)).verify()
        return raw
    except Exception:
        # iOS CgBI icons often fail in Pillow; still return bytes for a later decoder.
        return raw
