# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


class KikeError(Exception):
    """User-facing error with a safe message (no secrets)."""


DikeError = KikeError


class JailbreakError(KikeError):
    pass


class DeviceError(KikeError):
    pass


class PackageError(KikeError):
    pass


class EncryptedIpaError(PackageError):
    pass


class AppleAuthError(KikeError):
    pass


class TwoFactorRequired(AppleAuthError):
    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(message or "Two-factor authentication is required.")
        self.kind = kind  # "trusted" or "sms"


class ProvisioningError(KikeError):
    pass


class SignError(KikeError):
    pass


class InstallError(KikeError):
    pass


class DoctorError(KikeError):
    pass
