# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import ssl

import certifi
import httpx

APPLE_HOSTS = (
    "gsa.apple.com",
    "idmsa.apple.com",
    "developerservices2.apple.com",
    "developer.apple.com",
)

# Public Apple PKI roots: https://www.apple.com/certificateauthority/
_APPLE_ROOT_PEMS = (
    "AppleIncRootCertificate.pem",
    "AppleRootCA-G2.pem",
    "AppleRootCA-G3.pem",
)


def _certs_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "certs"


def apple_ca_bundle() -> bytes:
    """Apple Root CA PEMs (not in Mozilla certifi; often missing from Windows)."""
    root = _certs_dir()
    parts: list[bytes] = []
    for name in _APPLE_ROOT_PEMS:
        path = root / name
        if not path.is_file():
            raise FileNotFoundError(f"Missing bundled Apple CA: {path}")
        parts.append(path.read_bytes().strip())
    return b"\n".join(parts) + b"\n"


def inject_os_trust() -> None:
    """No-op. Apple TLS uses bundled Apple roots; Schannel does not trust them."""
    return


def apple_ssl_context() -> ssl.SSLContext:
    """Verify Apple TLS with certifi + OS store + bundled Apple Root CAs."""
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=certifi.where())
    try:
        ctx.load_default_certs()
    except Exception:
        pass
    # PEM must be str; bytes are parsed as DER and fail.
    ctx.load_verify_locations(cadata=apple_ca_bundle().decode("ascii"))
    return ctx


def apple_httpx_client(**kwargs) -> httpx.Client:
    """TLS-verified client. Apple ID traffic only goes to Apple."""
    timeout = kwargs.pop("timeout", 45.0)
    headers = kwargs.pop("headers", {})
    return httpx.Client(
        timeout=timeout,
        headers=headers,
        verify=apple_ssl_context(),
        follow_redirects=False,
        **kwargs,
    )


def assert_apple_url(url: str) -> None:
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in APPLE_HOSTS):
        raise ValueError(f"Refusing to send Apple ID data to non-Apple host: {host}")


def ssl_error_message(exc: BaseException) -> str:
    text = str(exc).lower()
    if "certificate" in text or "ssl" in text:
        return (
            "Could not make a trusted HTTPS connection to Apple. "
            "If antivirus HTTPS scanning is on, add an exception for "
            "gsa.apple.com and developerservices2.apple.com (or turn scanning "
            "off for python.exe), then try Sideload again. Details: "
            f"{exc}"
        )
    return str(exc) or type(exc).__name__
