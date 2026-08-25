# DikeLoader

Windows app that installs `.ipa` / `.tipa` / `.deb` onto **your** Dopamine-jailbroken **iPhone 14 (iOS 16.1)**.

This is the jailbreak-oriented sibling of KikeLoader (iOS 26, no TrollStore). On iOS 16.1, TrollStore’s CoreTrust bug is available, so apps can be permanent. Dopamine is **semi-untethered**: after a reboot, open the Dopamine app before SSH / TrollStore installs.

## What you need

1. Windows 10/11 and Python 3.11+ (3.13 tested)
2. [Apple Devices](https://apps.microsoft.com/detail/9np83lwlpz9k) (or iTunes) for USB
3. iPhone 14 on **iOS 16.1**, already jailbroken with **Dopamine**
4. **OpenSSH** from Sileo (user `root`, password often `alpine` — change it)
5. **TrollStore** (or TrollHelper) for CoreTrust installs
6. Optional: **LiveContainer**, **AppSync Unified** (rootless), **ElleKit**

Visual C++ Build Tools are not required.

## Build

```powershell
cd DikeLoader
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
.\.venv\Scripts\python -m dikeloader
```

`bootstrap.ps1` creates `.venv`, installs deps (including `paramiko` for SSH), fetches `vendor/zsign.exe`, and runs doctor.

### Build by hand

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e . --no-deps
pip install -r requirements.txt
pip install pymobiledevice3 --no-deps
python -m dikeloader fetch-zsign
python -m dikeloader doctor
python -m dikeloader
```

Always install `pymobiledevice3` with `--no-deps` unless you have Visual C++.

## Install methods

| Method | What it does |
|---|---|
| **TrollStore** | Copies the IPA over SSH and runs `trollstorehelper install`. CoreTrust-signed, no 7-day expiry. Default. |
| **LiveContainer** | Drops the app into LiveContainer’s Documents so you can run it without a SpringBoard icon. |
| **AppSync** | Installs via lockdown `installation_proxy` (needs AppSync Unified on the phone). |
| **Apple ID** | Same 7-day free-cert path as KikeLoader. Use only if TrollStore is missing. |

Wi-Fi: enable **Prefer Wi-Fi IP** and type the iPhone’s address, or leave **USB SSH** on (iproxy `2222 → 22`). Lockdown listing also includes Wi-Fi-paired devices.

## Dylibs and .debs

- **Add dylib…** injects each `.dylib` with `zsign -l` (ad-hoc) before TrollStore/AppSync/LiveContainer install.
- **Install .deb…** (or drop a `.deb`) uploads it and runs rootless `dpkg -i` (`PATH` includes `/var/jb/usr/bin`).

## Auto-refresh Windows task

TrollStore apps do not expire. If you still have Apple ID–signed apps:

```powershell
python -m dikeloader service-install
python -m dikeloader service-remove
```

That creates a per-user `schtasks` job (`DikeLoaderAutoRefresh`) every 12 hours calling `python -m dikeloader refresh-all`.

## Commands

| Command | Action |
|---|---|
| `python -m dikeloader` | GUI |
| `python -m dikeloader doctor` | USB, Dopamine SSH, TrollStore, LiveContainer |
| `python -m dikeloader fetch-zsign` | Download `vendor/zsign.exe` |
| `python -m dikeloader refresh-all` | Re-sign cached Apple ID apps |
| `python -m dikeloader service-install` | Hourly Windows refresh task |
| `python -m dikeloader service-remove` | Remove that task |

## Limits

- Encrypted App Store IPAs cannot be re-signed or injected
- After reboot, re-enable Dopamine before SSH
- TrollStore must already be on the device; DikeLoader does not exploit CoreTrust itself — it calls TrollStore’s helper
- Only install software you are allowed to run on **your** phone

## License

[GPL-3.0-or-later](LICENSE) (pymobiledevice3). DikeLoader is not affiliated with Apple, Dopamine, or TrollStore.
