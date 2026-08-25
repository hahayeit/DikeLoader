# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from base64 import b64decode
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import plistlib
import re
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from dikeloader.apple.developer import DeveloperClient
from dikeloader.apple.gsa import AppleSession
from dikeloader.device.connection import ConnectedDevice
from dikeloader.exceptions import ProvisioningError
from dikeloader.ipa.inspect import PackageInfo
from dikeloader.paths import certs_dir
from dikeloader.store.secrets import get_p12_password, set_p12_password


@dataclass
class SigningArtifacts:
    p12_path: Path
    p12_password: str
    profile_path: Path
    team_id: str
    team_name: str
    free_team: bool
    expiry: datetime | None
    bundle_id: str


def _machine_id(email: str) -> str:
    path = certs_dir(email) / "machine_id.txt"
    if path.is_file():
        return path.read_text(encoding="utf-8").strip() or str(uuid4()).upper()
    value = str(uuid4()).upper()
    path.write_text(value, encoding="utf-8")
    return value


def _safe_profile_name(display: str, bundle_id: str) -> str:
    base = re.sub(r"[^A-Za-z0-9 \-]", "", display).strip() or bundle_id.split(".")[-1]
    return f"Kike {base}"[:50]


def _load_cert_from_der(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der)


def _cert_serial(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "X")


def _parse_profile_expiry(blob: bytes) -> datetime | None:
    start = blob.find(b"<?xml")
    end = blob.find(b"</plist>")
    if start < 0 or end < 0:
        return None
    try:
        data = plistlib.loads(blob[start : end + len(b"</plist>")])
    except Exception:
        return None
    expiry = data.get("ExpirationDate")
    if isinstance(expiry, datetime):
        if expiry.tzinfo is None:
            return expiry.replace(tzinfo=timezone.utc)
        return expiry
    return None


def _ensure_device(client: DeveloperClient, team_id: str, device: ConnectedDevice) -> None:
    devices = client.list_devices(team_id)
    udids = {str(d.get("deviceNumber") or d.get("udid") or "").lower() for d in devices}
    if device.udid.lower() in udids:
        return
    client.add_device(team_id, device.udid, device.name or "iPhone")


def _ensure_app_id(client: DeveloperClient, team_id: str, info: PackageInfo) -> str:
    existing = client.list_app_ids(team_id)
    for app in existing:
        if str(app.get("identifier") or "") == info.bundle_id:
            return str(app.get("appIdId") or app.get("appId") or "")
    try:
        created = client.add_app_id(team_id, info.bundle_id, _safe_profile_name(info.display_name, info.bundle_id))
    except ProvisioningError as exc:
        # Race: created elsewhere. Re-list.
        existing = client.list_app_ids(team_id)
        for app in existing:
            if str(app.get("identifier") or "") == info.bundle_id:
                return str(app.get("appIdId") or app.get("appId") or "")
        raise ProvisioningError(str(exc)) from exc
    app = created.get("appId") if isinstance(created.get("appId"), dict) else created
    app_id = str(app.get("appIdId") or app.get("appId") or created.get("appIdId") or "")
    if not app_id:
        existing = client.list_app_ids(team_id)
        for item in existing:
            if str(item.get("identifier") or "") == info.bundle_id:
                return str(item.get("appIdId") or "")
        raise ProvisioningError("Apple created an App ID but did not return its id.")
    return app_id


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csr_pem(key: rsa.RSAPrivateKey, email: str) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "DikeLoader"),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _write_p12(path: Path, key: rsa.RSAPrivateKey, cert: x509.Certificate, password: str) -> None:
    blob = pkcs12.serialize_key_and_certificates(
        name=b"DikeLoader",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    path.write_bytes(blob)


def _load_local_identity(email: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate] | None:
    folder = certs_dir(email)
    key_path = folder / "key.pem"
    cert_path = folder / "cert.der"
    if not key_path.is_file() or not cert_path.is_file():
        return None
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_der_x509_certificate(cert_path.read_bytes())
    except Exception:
        return None
    if not isinstance(key, rsa.RSAPrivateKey):
        return None
    expiry = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry < datetime.now(timezone.utc):
        return None
    return key, cert


def _save_local_identity(email: str, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
    folder = certs_dir(email)
    folder.mkdir(parents=True, exist_ok=True)
    folder.joinpath("key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    folder.joinpath("cert.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))


def _ensure_certificate(client: DeveloperClient, session: AppleSession, team_id: str) -> tuple[Path, str]:
    email = session.email
    folder = certs_dir(email)
    p12_path = folder / "dev.p12"
    password = get_p12_password(email) or secrets.token_urlsafe(16)
    machine = _machine_id(email)

    local = _load_local_identity(email)
    server_certs = client.list_certs(team_id)
    if local:
        key, cert = local
        serial = _cert_serial(cert).upper()
        for item in server_certs:
            remote_serial = str(item.get("serialNumber") or "").replace(":", "").upper()
            if remote_serial.endswith(serial) or serial.endswith(remote_serial):
                if not p12_path.is_file():
                    _write_p12(p12_path, key, cert, password)
                    set_p12_password(email, password)
                return p12_path, password

    key = _generate_key()
    csr = _csr_pem(key, email)
    try:
        result = client.submit_csr(team_id, csr, machine)
    except ProvisioningError:
        ours = [
            c
            for c in server_certs
            if str(c.get("machineName") or "") == "DikeLoader"
            or str(c.get("machineId") or "").upper() == machine.upper()
        ]
        if ours:
            serial = str(ours[0].get("serialNumber") or "")
            if serial:
                try:
                    client.revoke_cert(team_id, serial)
                except ProvisioningError:
                    pass
            result = client.submit_csr(team_id, csr, machine)
        else:
            raise
    cert_node = result.get("certRequest") if isinstance(result.get("certRequest"), dict) else result
    der = cert_node.get("certContent") or cert_node.get("certificate") or result.get("certContent")
    if isinstance(der, str):
        der = b64decode(der)
    if not isinstance(der, (bytes, bytearray)):
        for item in client.list_certs(team_id):
            if str(item.get("machineId") or "").upper() == machine.upper():
                der = item.get("certContent")
                break
    if isinstance(der, str):
        der = b64decode(der)
    if not isinstance(der, (bytes, bytearray)):
        raise ProvisioningError("Apple did not return a development certificate.")
    cert = _load_cert_from_der(bytes(der))
    _save_local_identity(email, key, cert)
    set_p12_password(email, password)
    _write_p12(p12_path, key, cert, password)
    return p12_path, password


def provision_for_app(
    session: AppleSession,
    device: ConnectedDevice,
    info: PackageInfo,
    progress: Callable[[str], None] | None = None,
) -> SigningArtifacts:
    def note(msg: str) -> None:
        if progress:
            progress(msg)

    with DeveloperClient(session) as client:
        note("Fetching developer team")
        team = client.pick_team()
        team_id = str(team.get("teamId") or team.get("teamID") or "")
        team_name = str(team.get("name") or "Apple Developer")
        free_team = bool(team.get("xcodeFreeOnly"))
        if not team_id:
            raise ProvisioningError("Apple did not return a team id.")

        note("Registering this iPhone")
        _ensure_device(client, team_id, device)

        note("Creating App ID")
        app_id_id = _ensure_app_id(client, team_id, info)

        note("Issuing development certificate")
        p12_path, password = _ensure_certificate(client, session, team_id)

        note("Downloading provisioning profile")
        profile = client.download_profile(team_id, app_id_id)
        profile_path = certs_dir(session.email) / f"{re.sub(r'[^A-Za-z0-9._-]', '_', info.bundle_id)}.mobileprovision"
        profile_path.write_bytes(profile)
        expiry = _parse_profile_expiry(profile)

    return SigningArtifacts(
        p12_path=p12_path,
        p12_password=password,
        profile_path=profile_path,
        team_id=team_id,
        team_name=team_name,
        free_team=free_team,
        expiry=expiry,
        bundle_id=info.bundle_id,
    )
