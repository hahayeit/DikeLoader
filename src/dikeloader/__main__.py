# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dikeloader",
        description="Install .ipa / .tipa / .deb on a Dopamine-jailbroken iPhone (iOS 16.1).",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="gui",
        choices=("gui", "doctor", "fetch-zsign", "refresh-all", "service-install", "service-remove"),
        help="gui (default), doctor, fetch-zsign, refresh-all, service-install, service-remove",
    )
    parser.add_argument("--hours", type=int, default=12, help="Hours between auto-refresh (service-install)")
    args = parser.parse_args(argv)

    from dikeloader.apple.tls import inject_os_trust

    inject_os_trust()

    if args.command == "doctor":
        from dikeloader.doctor import format_doctor, run_doctor

        print(format_doctor())
        return 0 if all(c.ok for c in run_doctor()) else 1

    if args.command == "fetch-zsign":
        from dikeloader.sign.fetch import fetch_zsign

        try:
            path = fetch_zsign()
        except Exception as exc:
            print(f"fetch-zsign failed: {exc}", file=sys.stderr)
            return 1
        print(f"Installed {path}")
        return 0

    if args.command == "refresh-all":
        from dikeloader.pipeline import refresh_all_apple
        from dikeloader.store.accounts import active_email, list_saved_emails
        from dikeloader.store.secrets import get_apple_password

        email = active_email() or (list_saved_emails()[0] if list_saved_emails() else "")
        password = get_apple_password(email) if email else None
        if not email or not password:
            print("No saved Apple ID for 7-day cert refresh.", file=sys.stderr)
            return 0
        rows = refresh_all_apple(email, password)
        print(f"Refreshed {len(rows)} Apple ID app(s).")
        return 0

    if args.command == "service-install":
        from dikeloader.service.refresh import install_refresh_task

        print(install_refresh_task(args.hours))
        return 0

    if args.command == "service-remove":
        from dikeloader.service.refresh import uninstall_refresh_task

        print(uninstall_refresh_task())
        return 0

    from dikeloader.gui.app import run_app

    run_app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
