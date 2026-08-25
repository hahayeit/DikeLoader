# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from base64 import b64encode
import hashlib
import hmac
import json
import plistlib
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from dikeloader.apple.anisette import get_anisette_headers
from dikeloader.apple.headers import GSA_USER_AGENT, XCODE_CLIENT_INFO, XCODE_VERSION, utc_client_time
from dikeloader.apple.tls import apple_httpx_client, assert_apple_url, ssl_error_message
from dikeloader.exceptions import AppleAuthError, TwoFactorRequired

GSA_URL = "https://gsa.apple.com/grandslam/GsService2"
XCODE_APP = "com.apple.gs.xcode.auth"

TwoFactorFn = Callable[[str], str]


def _srp_mod():
    try:
        import srp._pysrp as srp_impl
    except ImportError:
        import srp as srp_impl  # type: ignore

    if hasattr(srp_impl, "rfc5054_enable"):
        srp_impl.rfc5054_enable()
    if hasattr(srp_impl, "no_username_in_x"):
        srp_impl.no_username_in_x()
    return srp_impl


def _encrypt_password(password: str, salt: bytes, iterations: int, protocol: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        digest = digest.hex().encode("ascii")
    if iterations < 1:
        iterations = 1
    return hashlib.pbkdf2_hmac("sha256", digest, salt, int(iterations), dklen=32)


def _session_key(usr, name: str) -> bytes:
    key = usr.get_session_key()
    if not key:
        raise AppleAuthError("Apple login did not produce a session key.")
    return hmac.new(key, name.encode(), hashlib.sha256).digest()


def _decrypt_cbc(usr, blob: bytes) -> bytes:
    extra_key = _session_key(usr, "extra data key:")
    extra_iv = _session_key(usr, "extra data iv:")[:16]
    decryptor = Cipher(algorithms.AES(extra_key), modes.CBC(extra_iv)).decryptor()
    padded = decryptor.update(blob) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _decrypt_gcm_xyz(sk: bytes, blob: bytes) -> bytes:
    """Decrypt GSA `et` (XYZ magic + 16-byte IV + ciphertext + 16-byte tag)."""
    if len(blob) < 35 or blob[:3] != b"XYZ":
        raise AppleAuthError("Apple returned a token blob this app cannot read.")
    nonce = blob[3:19]
    tag = blob[-16:]
    ciphertext = blob[19:-16]
    try:
        return AESGCM(sk).decrypt(nonce, ciphertext + tag, b"XYZ")
    except Exception as exc:
        raise AppleAuthError("Could not decrypt Apple's developer token.") from exc


def _loads_plist(raw: bytes) -> dict:
    if not raw:
        return {}
    try:
        data = plistlib.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        header = (
            b"<?xml version='1.0' encoding='UTF-8'?>\n"
            b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        )
        data = plistlib.loads(header + raw)
        return data if isinstance(data, dict) else {}


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _as_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _status_error(response: dict) -> str | None:
    status = response.get("Status") if isinstance(response.get("Status"), dict) else response
    if not isinstance(status, dict):
        return None
    code = status.get("ec", 0)
    if code in (0, "0", None):
        return None
    return str(status.get("em") or f"Apple login error {code}")


def _clean_code(code: str) -> str:
    return re.sub(r"\D", "", code or "")


@dataclass
class AppleSession:
    email: str
    adsid: str
    gs_token: str
    idms_token: str = ""
    pet: str = ""
    cookie: str = ""
    raw: dict = field(default_factory=dict)


def _gsa_headers(anisette: dict[str, str]) -> dict[str, str]:
    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": GSA_USER_AGENT,
        "X-MMe-Client-Info": anisette.get("X-MMe-Client-Info") or XCODE_CLIENT_INFO,
    }
    headers.update(anisette)
    return headers


def _cpd(anisette: dict[str, str]) -> dict[str, Any]:
    cpd: dict[str, Any] = {
        "bootstrap": True,
        "icscrec": True,
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",
    }
    cpd.update(anisette)
    rinfo = cpd.get("X-Apple-I-MD-RINFO")
    if rinfo is not None:
        try:
            cpd["X-Apple-I-MD-RINFO"] = int(rinfo)
        except (TypeError, ValueError):
            pass
    return cpd


def _gsa_request(client, parameters: dict[str, Any], anisette: dict[str, str]) -> dict:
    assert_apple_url(GSA_URL)
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"cpd": _cpd(anisette)},
    }
    body["Request"].update(parameters)
    try:
        response = client.post(
            GSA_URL,
            content=plistlib.dumps(body, fmt=plistlib.FMT_XML),
            headers=_gsa_headers(anisette),
        )
    except Exception as exc:
        raise AppleAuthError(ssl_error_message(exc)) from exc
    if response.status_code >= 400:
        raise AppleAuthError(f"Apple login HTTP {response.status_code}.")
    parsed = _loads_plist(response.content)
    inner = parsed.get("Response", parsed)
    if not isinstance(inner, dict):
        raise AppleAuthError("Unexpected response from Apple login.")
    if _auth_kind(inner):
        return inner
    err = _status_error(inner)
    if err:
        raise AppleAuthError(err)
    return inner


def _srp_login(client, email: str, password: str, anisette: dict[str, str]):
    srp_impl = _srp_mod()
    usr = srp_impl.User(email, bytes(), hash_alg=srp_impl.SHA256, ng_type=srp_impl.NG_2048)
    _uname, A = usr.start_authentication()
    init = _gsa_request(
        client,
        {"A2k": A, "ps": ["s2k", "s2k_fo"], "u": email, "o": "init"},
        anisette,
    )
    protocol = str(init.get("sp") or "s2k")
    salt = init.get("s")
    B = init.get("B")
    iterations = int(init.get("i") or 0)
    if not isinstance(salt, (bytes, bytearray)) or not isinstance(B, (bytes, bytearray)):
        raise AppleAuthError("Apple login challenge was malformed.")
    hashed = _encrypt_password(password, bytes(salt), iterations, protocol)
    if hasattr(usr, "p"):
        usr.p = hashed
    elif hasattr(usr, "_password"):
        usr._password = hashed
    else:
        usr = srp_impl.User(email, hashed, hash_alg=srp_impl.SHA256, ng_type=srp_impl.NG_2048)
        _uname, A = usr.start_authentication()
        init = _gsa_request(
            client,
            {"A2k": A, "ps": ["s2k", "s2k_fo"], "u": email, "o": "init"},
            anisette,
        )
        salt = init.get("s")
        B = init.get("B")
        if not isinstance(salt, (bytes, bytearray)) or not isinstance(B, (bytes, bytearray)):
            raise AppleAuthError("Apple login challenge was malformed.")
    M = usr.process_challenge(bytes(salt), bytes(B))
    if M is None:
        raise AppleAuthError("Wrong Apple ID or password.")
    complete = _gsa_request(
        client,
        {"c": init.get("c"), "M1": M, "u": email, "o": "complete"},
        anisette,
    )
    m2 = complete.get("M2")
    if isinstance(m2, (bytes, bytearray)):
        usr.verify_session(bytes(m2))
        if not usr.authenticated():
            raise AppleAuthError("Could not verify Apple's login session.")
    spd_blob = complete.get("spd")
    if not isinstance(spd_blob, (bytes, bytearray)):
        raise AppleAuthError("Apple login did not return session data.")
    spd = _loads_plist(_decrypt_cbc(usr, bytes(spd_blob)))
    return usr, complete, spd


def _auth_kind(complete: dict) -> str | None:
    status = complete.get("Status") if isinstance(complete.get("Status"), dict) else {}
    au = status.get("au") if isinstance(status, dict) else None
    if au in {"trustedDeviceSecondaryAuth", "extraAction"}:
        return "trusted"
    if au in {"secondaryAuth", "phoneSecondaryAuth"}:
        return "sms"
    return None


def _identity_token(adsid: str, idms: str) -> str:
    return b64encode(f"{adsid}:{idms}".encode()).decode()


def _identity_headers(adsid: str, idms: str, anisette: dict[str, str]) -> dict[str, str]:
    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": _identity_token(adsid, idms),
        "X-Apple-App-Info": XCODE_APP,
        "X-Xcode-Version": XCODE_VERSION,
    }
    headers.update(anisette)
    return headers


def _complete_trusted_2fa(client, adsid: str, idms: str, anisette: dict[str, str], code: str) -> None:
    headers = _identity_headers(adsid, idms, anisette)
    headers["security-code"] = code
    url = "https://gsa.apple.com/grandslam/GsService2/validate"
    assert_apple_url(url)
    response = client.get(url, headers=headers)
    try:
        parsed = _loads_plist(response.content) if response.content else {}
    except Exception:
        parsed = {}
    err = _status_error(parsed) if parsed else None
    if not parsed or response.status_code >= 400 or err:
        raise AppleAuthError(err or "That two-factor code was not accepted.")


def _trigger_trusted_2fa(client, adsid: str, idms: str, anisette: dict[str, str]) -> None:
    url = "https://gsa.apple.com/auth/verify/trusteddevice"
    assert_apple_url(url)
    client.get(url, headers=_identity_headers(adsid, idms, anisette))


def _sms_phone_id(client, headers: dict[str, str]) -> int:
    url = "https://gsa.apple.com/auth/verify/phone"
    assert_apple_url(url)
    try:
        response = client.get(url, headers=headers)
        data = response.json() if response.content else {}
    except Exception:
        return 1
    numbers = []
    if isinstance(data, dict):
        numbers = data.get("trustedPhoneNumbers") or data.get("phones") or []
    if isinstance(numbers, list) and numbers:
        first = numbers[0]
        if isinstance(first, dict):
            ident = first.get("id")
            if ident is not None:
                try:
                    return int(ident)
                except (TypeError, ValueError):
                    pass
    return 1


def _complete_sms_2fa(client, adsid: str, idms: str, anisette: dict[str, str], code: str) -> None:
    headers = _identity_headers(adsid, idms, anisette)
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    phone_id = _sms_phone_id(client, headers)
    put = "https://gsa.apple.com/auth/verify/phone/"
    post = "https://gsa.apple.com/auth/verify/phone/securitycode"
    assert_apple_url(put)
    assert_apple_url(post)
    client.put(put, json={"phoneNumber": {"id": phone_id}, "mode": "sms"}, headers=headers)
    response = client.post(
        post,
        json={"phoneNumber": {"id": phone_id}, "mode": "sms", "securityCode": {"code": code}},
        headers=headers,
    )
    ok = response.is_success
    try:
        parsed = response.json() if response.content else {}
        if isinstance(parsed, dict) and parsed.get("ec") not in (None, 0, "0"):
            ok = False
    except json.JSONDecodeError:
        pass
    if not ok:
        raise AppleAuthError("That SMS code was not accepted.")


def _extract_pet(spd: dict) -> str:
    tokens = spd.get("t")
    if isinstance(tokens, dict):
        for key, value in tokens.items():
            token = value.get("token") if isinstance(value, dict) else value
            if _as_str(key).endswith("idms.pet") and token:
                return _as_str(token)
    return ""


def _app_tokens_checksum(sk: bytes, adsid: str, apps: list[str]) -> bytes:
    msg = b"apptokens" + adsid.encode("utf-8") + b"".join(app.encode("utf-8") for app in apps)
    return hmac.new(sk, msg, hashlib.sha256).digest()


def _fetch_xcode_token(client, spd: dict, anisette: dict[str, str]) -> str:
    adsid = _as_str(spd.get("adsid") or spd.get("GsIdmsDsId"))
    idms = _as_str(spd.get("GsIdmsToken"))
    sk = _as_bytes(spd.get("sk"))
    challenge = spd.get("c")
    if not adsid or not idms or not sk or challenge is None:
        raise AppleAuthError("Apple login did not return developer token keys.")
    apps = [XCODE_APP]
    app = _gsa_request(
        client,
        {
            "app": apps,
            "c": challenge,
            "t": idms,
            "u": adsid,
            "checksum": _app_tokens_checksum(sk, adsid, apps),
            "o": "apptokens",
        },
        anisette,
    )
    et = app.get("et")
    if not isinstance(et, (bytes, bytearray)):
        raise AppleAuthError("Apple did not issue an Xcode developer token.")
    decrypted = _loads_plist(_decrypt_gcm_xyz(sk, bytes(et)))
    tokens = decrypted.get("t") if isinstance(decrypted.get("t"), dict) else decrypted
    if isinstance(tokens, dict):
        node = tokens.get(XCODE_APP) or tokens
        token = node.get("token") if isinstance(node, dict) else node
        if token:
            return _as_str(token)
    raise AppleAuthError("Apple did not issue an Xcode developer token.")


def _ask_code(two_factor: TwoFactorFn, kind: str) -> str:
    prompt = (
        "Enter the 6-digit code shown on your Apple devices (no dashes)."
        if kind == "trusted"
        else "Enter the 6-digit SMS code Apple sent (no dashes)."
    )
    code = _clean_code(two_factor(prompt))
    if len(code) < 4:
        raise AppleAuthError("Two-factor authentication was cancelled.")
    return code


def login_apple_id(email: str, password: str, two_factor: TwoFactorFn | None = None) -> AppleSession:
    email = email.strip()
    if not email or not password:
        raise AppleAuthError("Enter your Apple ID and password.")
    with apple_httpx_client() as client:
        anisette = get_anisette_headers()
        usr, complete, spd = _srp_login(client, email, password, anisette)
        kind = _auth_kind(complete)
        if kind:
            adsid = _as_str(spd.get("adsid"))
            idms = _as_str(spd.get("GsIdmsToken"))
            if not adsid or not idms:
                raise AppleAuthError("Apple asked for two-factor authentication but did not return account tokens.")
            two_fa_headers = get_anisette_headers()
            if kind == "trusted":
                _trigger_trusted_2fa(client, adsid, idms, two_fa_headers)
            if two_factor is None:
                raise TwoFactorRequired(kind)
            code = _ask_code(two_factor, kind)
            two_fa_headers = dict(two_fa_headers)
            two_fa_headers["X-Apple-I-Client-Time"] = utc_client_time()
            if kind == "sms":
                _complete_sms_2fa(client, adsid, idms, two_fa_headers, code)
            else:
                _complete_trusted_2fa(client, adsid, idms, two_fa_headers, code)
            anisette = get_anisette_headers()
            usr, complete, spd = _srp_login(client, email, password, anisette)
            if _auth_kind(complete):
                raise AppleAuthError(
                    "Apple still wants two-factor authentication. "
                    "Use the newest 6-digit code from your iPhone (not an old one) and try Sideload again."
                )
        adsid = _as_str(spd.get("adsid") or spd.get("GsIdmsDsId"))
        idms = _as_str(spd.get("GsIdmsToken"))
        token = _fetch_xcode_token(client, spd, anisette)
        if not adsid:
            raise AppleAuthError("Apple login did not return an account id.")
        return AppleSession(
            email=email,
            adsid=adsid,
            gs_token=token,
            idms_token=idms,
            pet=_extract_pet(spd),
            cookie=_as_str(complete.get("c") or spd.get("c") or ""),
            raw=spd,
        )
