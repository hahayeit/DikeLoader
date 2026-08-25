# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import keyring

from dikeloader.exceptions import AppleAuthError

SERVICE = "DikeLoader"


def set_ssh_password(user: str, password: str) -> None:
    keyring.set_password(SERVICE, f"ssh:{user.lower()}", password)


def get_ssh_password(user: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, f"ssh:{user.lower()}")
    except Exception:
        return None


def set_apple_password(email: str, password: str) -> None:
    keyring.set_password(SERVICE, f"apple-id:{email.lower()}", password)


def get_apple_password(email: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, f"apple-id:{email.lower()}")
    except Exception as exc:
        raise AppleAuthError(f"Could not read the saved Apple ID from Windows: {exc}") from exc


def delete_apple_password(email: str) -> None:
    try:
        keyring.delete_password(SERVICE, f"apple-id:{email.lower()}")
    except keyring.errors.PasswordDeleteError:
        pass
    except Exception:
        pass


def set_p12_password(email: str, password: str) -> None:
    keyring.set_password(SERVICE, f"p12:{email.lower()}", password)


def get_p12_password(email: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, f"p12:{email.lower()}")
    except Exception:
        return None
