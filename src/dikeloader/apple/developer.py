# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Any
from uuid import uuid4
from base64 import b64decode
import plistlib

from dikeloader.apple.anisette import get_anisette_headers
from dikeloader.apple.gsa import AppleSession
from dikeloader.apple.headers import XCODE_VERSION
from dikeloader.apple.tls import apple_httpx_client, assert_apple_url, ssl_error_message
from dikeloader.exceptions import ProvisioningError

CLIENT_ID = "XABBG36SBA"
PROTOCOL = "QH65B2"
BASE = "https://developerservices2.apple.com/services/QH65B2"
XCODE_APP_INFO = "com.apple.gs.xcode.auth"


def _friendly(code: Any, user: str, raw: str) -> str:
    text = (user or raw or "").strip()
    blob = f"{code} {text}".lower()
    if "app id" in blob and ("limit" in blob or "maximum" in blob or "9412" in blob):
        return (
            "This Apple ID has used its free App ID quota for the week "
            "(about 10). Wait, delete an App ID, or use another Apple ID."
        )
    if "device" in blob and ("limit" in blob or "maximum" in blob):
        return "This Apple ID cannot register another device. Remove one at developer.apple.com."
    if "cert" in blob and ("limit" in blob or "maximum" in blob or "already" in blob):
        return (
            "This Apple ID already has the maximum number of development certificates. "
            "DikeLoader will try to reuse its own certificate."
        )
    if "agreement" in blob or "terms" in blob:
        return "Open developer.apple.com in a browser and accept Apple's latest developer agreement."
    if "invalid" in blob and "login" in blob:
        return "Apple rejected this developer session. Sign in again."
    if "session has expired" in blob or "please log in" in blob:
        return (
            "Apple signed you out of developer services. "
            "Click Sideload again and enter the newest 6-digit code if asked."
        )
    if text:
        return text
    return f"Apple developer services error {code}."


def _envelope(team_id: str | None = None, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "clientId": CLIENT_ID,
        "protocolVersion": PROTOCOL,
        "requestId": str(uuid4()).upper(),
        "userLocale": ["en_US"],
    }
    if team_id:
        body["teamId"] = team_id
    body.update(extra)
    return body


class DeveloperClient:
    def __init__(self, session: AppleSession) -> None:
        self.session = session
        self._http = apple_httpx_client(timeout=60.0)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "DeveloperClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        anisette = get_anisette_headers()
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "X-Xcode-Version": XCODE_VERSION,
            "X-Apple-App-Info": XCODE_APP_INFO,
            "X-Apple-I-Identity-Id": self.session.adsid,
            "X-Apple-GS-Token": self.session.gs_token,
        }
        headers.update(anisette)
        return headers

    def post(self, action: str, team_id: str | None = None, **extra: Any) -> dict[str, Any]:
        path = action if action.startswith("ios/") or action.startswith("list") else action
        url = f"{BASE}/{path}?clientId={CLIENT_ID}"
        assert_apple_url(url)
        payload = _envelope(team_id, **extra)
        try:
            response = self._http.post(
                url,
                content=plistlib.dumps(payload, fmt=plistlib.FMT_XML),
                headers=self._headers(),
            )
        except Exception as exc:
            raise ProvisioningError(ssl_error_message(exc)) from exc
        parsed = {}
        if response.content:
            try:
                loaded = plistlib.loads(response.content)
                parsed = loaded if isinstance(loaded, dict) else {}
            except Exception:
                parsed = {}
        if response.status_code >= 400:
            raise ProvisioningError(
                _friendly(
                    response.status_code,
                    parsed.get("userString") or parsed.get("resultString") or "",
                    response.text[:300],
                )
            )
        code = parsed.get("resultCode", 0)
        if code not in (0, "0", None):
            raise ProvisioningError(
                _friendly(code, str(parsed.get("userString") or parsed.get("resultString") or ""), "")
            )
        return parsed

    def list_teams(self) -> list[dict[str, Any]]:
        data = self.post("listTeams.action")
        teams = data.get("teams") or []
        if not teams:
            raise ProvisioningError(
                "This Apple ID has no developer team. Open developer.apple.com once in a browser, "
                "then try again. A free Apple ID is enough."
            )
        return teams

    def pick_team(self) -> dict[str, Any]:
        teams = self.list_teams()
        paid = [t for t in teams if not t.get("xcodeFreeOnly")]
        return paid[0] if paid else teams[0]

    def list_devices(self, team_id: str) -> list[dict[str, Any]]:
        return list(self.post("ios/listDevices.action", team_id).get("devices") or [])

    def add_device(self, team_id: str, udid: str, name: str) -> None:
        try:
            self.post("ios/addDevice.action", team_id, deviceNumber=udid, name=name[:50] or "iPhone")
        except ProvisioningError as exc:
            if "already" in str(exc).lower() or "exists" in str(exc).lower():
                return
            raise

    def list_app_ids(self, team_id: str) -> list[dict[str, Any]]:
        return list(self.post("ios/listAppIds.action", team_id).get("appIds") or [])

    def add_app_id(self, team_id: str, identifier: str, name: str) -> dict[str, Any]:
        return self.post(
            "ios/addAppId.action",
            team_id,
            identifier=identifier,
            name=name[:50],
        )

    def list_certs(self, team_id: str) -> list[dict[str, Any]]:
        data = self.post("ios/listAllDevelopmentCerts.action", team_id)
        return list(data.get("certificates") or data.get("developmentCertificates") or [])

    def submit_csr(self, team_id: str, csr_pem: str, machine_id: str, machine_name: str = "DikeLoader") -> dict[str, Any]:
        return self.post(
            "ios/submitDevelopmentCSR.action",
            team_id,
            csrContent=csr_pem,
            machineId=machine_id,
            machineName=machine_name,
        )

    def revoke_cert(self, team_id: str, serial: str) -> None:
        self.post("ios/revokeDevelopmentCert.action", team_id, serialNumber=serial)

    def download_profile(self, team_id: str, app_id_id: str) -> bytes:
        data = self.post("ios/downloadTeamProvisioningProfile.action", team_id, appIdId=app_id_id)
        profile = data.get("provisioningProfile") or data
        encoded = None
        if isinstance(profile, dict):
            encoded = profile.get("encodedProfile") or profile.get("profileContent")
        elif isinstance(profile, (bytes, bytearray)):
            encoded = profile
        if isinstance(encoded, str):
            encoded = b64decode(encoded)
        if not isinstance(encoded, (bytes, bytearray)):
            raise ProvisioningError("Apple did not return a provisioning profile.")
        return bytes(encoded)
