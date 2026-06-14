# Privacy Index Linux v3.4

Small local audit tool for Debian/Ubuntu-like, Kali and Arch-like Linux systems.

It produces three scores out of 20:

- **Privacy Index**: daily privacy against tracking, telemetry, DNS exposure and local exposure.
- **Anonymity Index**: resistance to IP/fingerprint correlation and presence of tools such as Tor Browser, Mullvad Browser or LibreWolf.
- **Hardening Index**: local hardening: disk encryption, firewall, exposed services and updates.

The normal scan does not contact external servers. It does not read browser history, bookmarks, emails or personal documents.

## Run

By default, the application asks for the language in English. Pressing Enter selects English.

```bash
python3 -m privacy_index --verbose
```

Force a language:

```bash
python3 -m privacy_index --lang en --verbose
python3 -m privacy_index --lang fr --verbose
python3 -m privacy_index --lang de --verbose
```

Export:

```bash
python3 -m privacy_index --lang en --verbose --json privacy_report.json --csv privacy_report.csv
```

Optional browser tests:

```bash
python3 -m privacy_index --lang en --browser-tests --test-browser firefox
python3 -m privacy_index --lang en --browser-tests --test-browser mullvad
python3 -m privacy_index --lang en --browser-tests --test-browser chromium
```
AppImage :

chmod +x PrivacyIndex-v3.4-x86_64.AppImage
sudo ./PrivacyIndex-v3.4-x86_64.AppImage --lang en --verbose

## Dependencies

No external Python dependency.

Useful Linux commands if present:

- `lsblk`, `findmnt`, `swapon`, `ip`, `ss`
- `resolvectl`
- `ufw`, `nft`, `iptables`
- `wg`, `flatpak`, `apt`, `pacman`

## What v1 scans

- OS and package manager.
- Approximate update state, including APT packages intentionally held back.
- Home directory permissions, correlated with the presence of other human users.
- Root LUKS/dm-crypt encryption and swap.
- Active VPN/tunnel interfaces.
- Local/known public/Google/router DNS classification.
- Local Tor tools.
- Firewall and exposed services.
- Installed browsers: Tor Browser, Mullvad Browser, LibreWolf, Brave, Firefox, Chromium, Chrome, Edge, Opera, Vivaldi.
- Firefox/LibreWolf/Tor Browser/Mullvad Browser settings: RFP, WebRTC, telemetry, DoH, with caution for default values.
- Partial Chromium-like profile reading.
- Known privacy/risk extensions, best effort.
- Messengers, encryption tools, password managers and sandboxing tools.

## Known limits

- Brave Shields and many Chromium settings cannot be read perfectly from local files.
- Active VPN detection is interface-based; it does not prove absence of leaks.
- DNS is classified locally; external leak tests require explicit consent.
- External WebRTC/DNS/fingerprint sites are not automated: the user reads the result in the browser.
- The score is not proof of anonymity. It is a local indicator.

## Scoring wording

Labels are intentionally informative rather than moralizing:

- **CORRECT** in green: compliant point or good signal.
- **TO KNOW** in orange: point to understand or verify, not necessarily an error.
- **WARNING** in red: problematic or risky point.

French uses **CORRECT**, **À SAVOIR**, **ATTENTION**. German uses **KORREKT**, **HINWEIS**, **ACHTUNG**.
## Changes v3.0 / v3.4

- Residual browser profiles now have a dedicated explanation instead of reusing browser-settings text.
- Residual profile detection covers Chromium-like, Firefox/LibreWolf and Tor/Mullvad profile leftovers more explicitly.

- Hardens browser detection to avoid false positives from stale profiles or old configuration folders.
- Confirms browser installation through multiple sources: PATH commands, package managers (`dpkg`, `pacman`, `rpm`), Flatpak app IDs, valid `.desktop` launchers, or official Tor/Mullvad tarball markers.
- Treats old Chromium-like profiles such as `~/.config/BraveSoftware` as residual `INFO` when the browser is not otherwise confirmed installed.
- Limits Chromium profile and search-engine analysis to confirmed installed browsers, reducing stale evidence in the score.
- Keeps the DNS database, extended `ss` port investigation, sudo support and clean report grid from previous versions.

Focused port investigation remains available:

```bash
python3 -m privacy_index --lang fr --investigate-port 54449
python3 -m privacy_index --lang fr --investigate-port 54449 --investigate-proto udp
```

## Current notes

- **v3.4**: stronger LibreWolf detection and explicit Amnezia/Nym privacy-provider signals; notes on HTML/JS portability limits.


## Portability note

Standalone HTML/JS cannot perform the full local audit because a browser page cannot run `ss`, `dpkg`, `pacman`, `resolvectl`, inspect `/proc`, read arbitrary browser profiles or enumerate system services. A web UI is still useful as a report viewer or browser self-test page, but the real Linux scanner needs a backend such as Python, Bash, Node/Electron, Tauri, or a packaged AppImage.

