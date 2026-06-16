# Privacy Index Linux v3.4

Small local audit tool for Debian/Ubuntu-like Linux systems.

It produces three scores out of 20:

- **Privacy Index**: daily privacy against tracking, telemetry, DNS exposure and local exposure.
- **Anonymity Index**: resistance to IP/fingerprint correlation and presence of tools such as Tor Browser, Mullvad Browser or LibreWolf.
- **Hardening Index**: local hardening: disk encryption, firewall, exposed services and updates.

The normal scan does not contact external servers. It does not read browser history, bookmarks, emails or personal documents.

## Limits

The score is not a certification of security or anonymity. It represents a local, weighted and improvable reading of certain technical signals.
Each user can adapt the criteria, weightings and local databases according to their own threat model.


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
Commands :
```bash

usage: privacy-index [-h] [--json JSON_PATH] [--csv CSV_PATH] [--no-color] [--verbose] [--debug-facts] [--browser-tests] [--test-browser TEST_BROWSER] [--yes] [--lang {fr,en,de}]
                     [--no-lang-prompt] [--no-sudo] [--investigate-port INVESTIGATE_PORT] [--investigate-proto {udp,tcp}]

Local Linux privacy, anonymity and hardening audit.

options:
  -h, --help            show this help message and exit
  --json JSON_PATH      Export the JSON report to this file
  --csv CSV_PATH        Export CSV results to this file
  --no-color            Disable ANSI colors
  --verbose, -v         Show detailed explanations and remediation hints
  --debug-facts         Show raw detected facts to debug false positives
  --browser-tests       Offer optional browser tests. External tests require confirmation.
  --test-browser TEST_BROWSER
                        Browser to use for tests: firefox, librewolf, mullvad, brave, chromium, default, etc.
  --yes                 Answer yes to optional browser-test confirmations.
  --lang {fr,en,de}     Interface language: fr, en or de. If omitted, the app asks in English.
  --no-lang-prompt      Use English without asking for the interface language.
  --no-sudo             Do not ask for sudo. Some root-owned listening processes may remain unknown.
  --investigate-port INVESTIGATE_PORT
                        Run a focused extended ss investigation for one listening port, then exit.
  --investigate-proto {udp,tcp}
                        Protocol for --investigate-port. Default: udp.
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

## Output sample on test computer
```bash
 sudo python3 -m privacy_index --lang en --verbose                                                                                                                                    

Privacy Index Linux v3.4
============================
Detected OS     : Debian GNU/Linux 13 (trixie)
Package manager : apt/dpkg

Privacy Index   : 20/20
Anonymity Index : 15/20
Hardening Index : 15/20
Global index    : 18/20
Scan confidence : high

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ STATUS       ┃ INFORMATION                                                                                                             ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
┃ [apps]       ┃                                                                                                                         ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ ENCRYPTED/PRIVATE MESSENGER DETECTED (P+1 A+1)                                                                          ┃
┃              ┃ evidence : Ricochet Refresh:.desktop, Session:.desktop, Signal:.desktop                                                 ┃
┃              ┃ why : Encrypted messaging limits content exposure, but protection also depends on metadata, backups and contact         ┃
┃              ┃       discovery.                                                                                                        ┃
┃              ┃ solution : Check cloud backups, notifications, contact sync and phone-number identity depending on the application.     ┃
┃              ┃ learn more : https://www.privacyguides.org/en/real-time-communication/                                                  ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ ENCRYPTION TOOLS PRESENT (P+1 H+1)                                                                                      ┃
┃              ┃ evidence : GnuPG:PATH, VeraCrypt:.desktop, VeraCrypt:PATH, ZuluCrypt:.desktop, cryptsetup/LUKS:PATH                     ┃
┃              ┃ why : File and volume encryption tools complement system disk encryption for exchanges, archives and removable drives.  ┃
┃              ┃ solution : Use VeraCrypt for cross-platform volumes, LUKS for Linux system disks, and age/GPG for files depending on    ┃
┃              ┃            the need.                                                                                                    ┃
┃              ┃ learn more : https://www.veracrypt.fr/en/Documentation.html                                                             ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ PASSWORD MANAGER DETECTED (P+1 H+1)                                                                                     ┃
┃              ┃ evidence : KeePassXC:.desktop                                                                                           ┃
┃              ┃ why : A local password manager prevents password reuse and makes strong secrets practical.                              ┃
┃              ┃ solution : KeePassXC/pass are good local choices. Keeping a sensitive app outside PATH is acceptable if the desktop     ┃
┃              ┃            launcher is present and controlled by the user.                                                              ┃
┃              ┃ learn more : https://keepassxc.org/docs/                                                                                ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ SANDBOXING/COMPARTMENTALIZATION TOOLS DETECTED (P+1 H+1)                                                                ┃
┃              ┃ evidence : Bubblewrap:PATH                                                                                              ┃
┃              ┃ why : Compartmentalization reduces damage if an application is compromised or too curious.                              ┃
┃              ┃ solution : Check Flatpak permissions with Flatseal or flatpak permission-show. Firejail/Bubblewrap profiles should be   ┃
┃              ┃            tested case by case.                                                                                         ┃
┃              ┃ learn more : https://wiki.archlinux.org/title/Bubblewrap                                                                ┃
╠══════════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
┃ [browser]    ┃                                                                                                                         ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ PRIVACY-ORIENTED BROWSERS DETECTED (P+3 A+4)                                                                            ┃
┃              ┃ evidence : brave (PATH:brave-browser, desktop:brave-browser.desktop, desktop:com.brave.Browser.desktop); chromium       ┃
┃              ┃            (PATH:chromium, desktop:chromium.desktop, dpkg:chromium); firefox (PATH:firefox, PATH:firefox-esr,           ┃
┃              ┃            desktop:firefox-esr.desktop); mullvad-browser (PATH:mullvad-browser, desktop:mullvad-browser.desktop,        ┃
┃              ┃            dpkg:mullvad-browser); tor-browser (PATH:torbrowser-launcher,                                                ┃
┃              ┃            desktop:org.torproject.torbrowser-launcher.desktop,                                                          ┃
┃              ┃            desktop:org.torproject.torbrowser-launcher.settings.desktop)                                                 ┃
┃              ┃ why : Browser settings strongly affect tracking, fingerprinting, WebRTC, telemetry and cookies.                         ┃
┃              ┃ solution : Check the browser UI and, for Firefox/LibreWolf, about:config: privacy.resistFingerprinting,                 ┃
┃              ┃            media.peerconnection.enabled, telemetry and DNS/DoH.                                                         ┃
┃              ┃ learn more : https://support.mozilla.org/kb/privacy-and-security-settings                                               ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ BRAVE BROWSER DETECTED                                                                                                  ┃
┃              ┃ evidence : PATH:brave-browser; desktop:brave-browser.desktop; desktop:com.brave.Browser.desktop; dpkg:brave-browser     ┃
┃              ┃ why : Brave is privacy-oriented by default, but protection still depends on Shields, WebRTC, third-party cookies, sync, ┃
┃              ┃       extensions and the search engine.                                                                                 ┃
┃              ┃ solution : Check Shields, disable sync if unnecessary, control WebRTC and keep extensions limited.                      ┃
┃              ┃ learn more : https://support.brave.com/hc/en-us/categories/360001053072-Desktop-Browser                                 ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ TO KNOW      ┃ CHROMIUM BROWSER DETECTED                                                                                               ┃
┃              ┃ evidence : PATH:chromium; desktop:chromium.desktop; dpkg:chromium                                                       ┃
┃              ┃ why : Chromium is an open-source base, but its default configuration can remain too permissive for a strict privacy     ┃
┃              ┃       goal.                                                                                                             ┃
┃              ┃ solution : Check Safe Browsing, WebRTC, third-party cookies, sync, extensions, the search engine and any enterprise     ┃
┃              ┃            policies.                                                                                                    ┃
┃              ┃ learn more : https://www.chromium.org/user-experience/user-data-directory/                                              ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ INFO         ┃ FIREFOX BROWSER DETECTED                                                                                                ┃
┃              ┃ evidence : PATH:firefox; PATH:firefox-esr; desktop:firefox-esr.desktop; dpkg:firefox-esr                                ┃
┃              ┃ why : Firefox is a good open-source base, but it is not as hardened as Tor Browser or Mullvad Browser without           ┃
┃              ┃       additional settings.                                                                                              ┃
┃              ┃ solution : Check telemetry, WebRTC, RFP/anti-fingerprinting, cookies, DNS/DoH, extensions and the search engine.        ┃
┃              ┃ learn more : https://support.mozilla.org/kb/privacy-and-security-settings                                               ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ TOR BROWSER DETECTED (P+2 A+5)                                                                                          ┃
┃              ┃ evidence : /usr/lib/python3/dist-packages/torbrowser_launcher,                                                          ┃
┃              ┃            /usr/lib/python3/dist-packages/torbrowser_launcher-0.3.9.egg-info                                            ┃
┃              ┃ why : Tor Browser is the key component for web anonymity thanks to Tor routing and a uniform anti-fingerprinting        ┃
┃              ┃       profile.                                                                                                          ┃
┃              ┃ solution : Do not add extensions, avoid distinctive full-screen behavior, and avoid logging into personal accounts when ┃
┃              ┃            anonymity is the goal.                                                                                       ┃
┃              ┃ learn more : https://tb-manual.torproject.org/                                                                          ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ MULLVAD BROWSER DETECTED (P+3 A+3)                                                                                      ┃
┃              ┃ evidence : /usr/lib/mullvad-browser                                                                                     ┃
┃              ┃ why : Mullvad Browser uses a standardized fingerprint approach without the Tor network by default. It is very good for  ┃
┃              ┃       reducing common web tracking.                                                                                     ┃
┃              ┃ solution : Keep it close to its default configuration. Too many extensions or exotic tweaks can break fingerprint       ┃
┃              ┃            uniformity.                                                                                                  ┃
┃              ┃ learn more : https://mullvad.net/browser                                                                                ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ UNKNOWN      ┃ DEFAULT SEARCH ENGINE COULD NOT BE DETERMINED LOCALLY                                                                   ┃
┃              ┃ evidence : Brave/default: unknown; Chromium/default: unknown; Firefox/default: unknown; Mullvad Browser/default:        ┃
┃              ┃            unknown; Tor Browser/default: unknown                                                                        ┃
┃              ┃ why : The scanner could not determine the default engine locally. This is common: some browsers store it in a locked    ┃
┃              ┃       database or compressed profile format.                                                                            ┃
┃              ┃ solution : Check the browser settings manually. No network test is launched for this check.                             ┃
╠══════════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
┃ [disk]       ┃                                                                                                                         ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ SYSTEM DISK ENCRYPTION DETECTED (P+3 H+5)                                                                               ┃
┃              ┃ evidence : root=/dev/mapper/C1--vg-root; luks=['sda5']; crypt=['sda5_crypt']                                           ┃
┃              ┃ why : Root disk encryption mostly protects data at rest: theft, loss, or physical access while the session is closed.   ┃
┃              ┃ solution : Keep a safe backup of the passphrase and make sure swap and backups follow the same protection model.        ┃
┃              ┃ learn more : https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system                                      ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ TO KNOW      ┃ ACTIVE SWAP WITHOUT OBVIOUS ENCRYPTION                                                                                  ┃
┃              ┃ evidence : swap=['/dev/dm-2']; crypttab_swap=False                                                                      ┃
┃              ┃ why : Swap can contain memory fragments: documents, temporary keys, browser pages. If it is not encrypted, it weakens   ┃
┃              ┃       an encrypted root disk setup.                                                                                     ┃
┃              ┃ solution : Check swapon --show and lsblk -f. Ideally keep swap inside the LUKS volume or use encrypted swap.            ┃
┃              ┃ learn more : https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption                                                  ┃
╠══════════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
┃ [firewall]   ┃                                                                                                                         ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ FIREWALL ACTIVE OR RULES PRESENT (H+3)                                                                                  ┃
┃              ┃ evidence : nftables ruleset présent; iptables rules présentes                                                           ┃
┃              ┃ why : An inbound firewall reduces accidental exposure of local services.                                                ┃
┃              ┃ solution : On a workstation, keep a restrictive inbound policy. Check with ufw status, nft list ruleset, or equivalent  ┃
┃              ┃            tools.                                                                                                       ┃
┃              ┃ learn more : https://wiki.debian.org/nftables                                                                           ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ NO OBVIOUS SENSITIVE OR UNEXPECTED NETWORK PORT (P+1 H+2)                                                               ┃
┃              ┃ evidence : network-visible=11, local-only=1, lan/discovery=5, vpn/tunnel=3, client/dynamic=3; source=ss -tulpn;         ┃
┃              ┃            privilege=root; unresolved-probe=ss -a/-l -e; enriched=2; probe-privilege=root                               ┃
┃              ┃ why : No risky exposed network service was found by the local scan, reducing the attack surface.                        ┃
┃              ┃ solution : Keep checking after installing new services: ss -tulpen.                                                     ┃
┃              ┃ learn more : https://man7.org/linux/man-pages/man8/ss.8.html                                                            ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ INFO         ┃ PORTS LINKED TO VPN OR TUNNEL DETECTED                                                                                  ┃
┃              ┃ evidence : proto  listen         process   service          class                                                       ┃
┃              ┃            -----  -------------  --------  ---------------  ----------                                                  ┃
┃              ┃            udp    *:41411        nordvpnd  dynamic/unknown  vpn/tunnel                                                  ┃
┃              ┃            udp    0.0.0.0:56453  nordvpnd  dynamic/unknown  vpn/tunnel                                                  ┃
┃              ┃            udp    [::]:56453     nordvpnd  dynamic/unknown  vpn/tunnel                                                  ┃
┃              ┃            source=ss -tulpn; privilege=root; unresolved-probe=ss -a/-l -e; enriched=2; probe-privilege=root             ┃
┃              ┃ why : Some VPN/tunnel clients open local or dynamic UDP sockets. This is not necessarily an exposed server-like         ┃
┃              ┃       service.                                                                                                          ┃
┃              ┃ solution : Check that the process is the expected VPN client. If it is, treat this as informational; otherwise inspect  ┃
┃              ┃            with ss -tulpen and systemctl.                                                                               ┃
┃              ┃ learn more : https://man7.org/linux/man-pages/man8/ss.8.html                                                            ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ INFO         ┃ LAN/LOCAL DISCOVERY SERVICES DETECTED                                                                                   ┃
┃              ┃ evidence : proto  listen                process   service       class                                                   ┃
┃              ┃            -----  --------------------  --------  ------------  -----                                                   ┃
┃              ┃            udp    10.5.0.2:3702         python3   WS-Discovery  lan                                                     ┃
┃              ┃            udp    172.17.0.1:3702       python3   WS-Discovery  lan                                                     ┃
┃              ┃            udp    192.168.1.18:3702     python3   WS-Discovery  lan                                                     ┃
┃              ┃            udp    239.255.255.250:3702  python3   WS-Discovery  lan                                                     ┃
┃              ┃            udp    224.0.0.251:5353      chromium  mDNS          lan                                                     ┃
┃              ┃            source=ss -tulpn; privilege=root; unresolved-probe=ss -a/-l -e; enriched=2; probe-privilege=root             ┃
┃              ┃ why : LAN discovery services such as mDNS or DHCP are common on workstations, but they make the machine more visible on ┃
┃              ┃       the local network.                                                                                                ┃
┃              ┃ solution : Keep them if needed. Disable them only for a very quiet profile or a hostile local network.                  ┃
┃              ┃ learn more : https://wiki.archlinux.org/title/Avahi                                                                     ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ INFO         ┃ CLIENT OR DYNAMIC UDP SOCKETS DETECTED                                                                                  ┃
┃              ┃ evidence : proto  listen         process  service          class                                                        ┃
┃              ┃            -----  -------------  -------  ---------------  ------                                                       ┃
┃              ┃            udp    0.0.0.0:43305  python3  dynamic/unknown  client                                                       ┃
┃              ┃            udp    0.0.0.0:45689  python3  dynamic/unknown  client                                                       ┃
┃              ┃            udp    0.0.0.0:59516  python3  dynamic/unknown  client                                                       ┃
┃              ┃            source=ss -tulpn; privilege=root; unresolved-probe=ss -a/-l -e; enriched=2; probe-privilege=root             ┃
╠══════════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
┃ [network]    ┃                                                                                                                         ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ ACTIVE VPN/TUNNEL INTERFACE DETECTED (P+2)                                                                              ┃
┃              ┃ evidence : interfaces=['nordlynx'], wg_peers=1                                                                          ┃
┃              ┃ why : A VPN hides traffic from the ISP and changes the visible IP address, but it does not provide anonymity by itself. ┃
┃              ┃ solution : For web anonymity, use Tor Browser and avoid personal accounts. For daily privacy, also check DNS and WebRTC ┃
┃              ┃            leaks.                                                                                                       ┃
┃              ┃ learn more : https://www.privacyguides.org/en/vpn/                                                                      ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ WIREGUARD VPN PROTOCOL DETECTED (P+1)                                                                                   ┃
┃              ┃ evidence : interfaces=['nordlynx'], wg_peers=1                                                                          ┃
┃              ┃ why : WireGuard is modern, fast and technically clean, but its traffic is fairly recognizable without an obfuscation    ┃
┃              ┃       layer.                                                                                                            ┃
┃              ┃ solution : Very good for a standard VPN. Under active censorship or filtering, consider AmneziaWG or XRay/Reality       ┃
┃              ┃            depending on the threat model.                                                                               ┃
┃              ┃ learn more : https://www.wireguard.com/                                                                                 ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ VPN OR PRIVACY PROVIDER DNS DETECTED (P+2)                                                                              ┃
┃              ┃ evidence : 103.86.99.100 -> NordVPN DNS via resolv.conf [/etc/resolv.conf]; 103.86.96.100 -> NordVPN DNS via            ┃
┃              ┃            resolv.conf [/etc/resolv.conf]                                                                               ┃
┃              ┃ why : DNS reveals requested domains. Encrypted or controlled DNS reduces leaks to the ISP or local network.             ┃
┃              ┃ solution : Check resolvectl status. Prefer encrypted DNS, VPN DNS, local Unbound, or a provider that fits your threat   ┃
┃              ┃            model.                                                                                                       ┃
┃              ┃ learn more : https://www.privacyguides.org/en/dns/                                                                      ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ LOCAL TOR TOOLS DETECTED (P+1 A+2)                                                                                      ┃
┃              ┃ evidence : tor, torsocks, torify                                                                                        ┃
┃              ┃ why : tor/torsocks can route some applications through Tor, but this is not equivalent to Tor Browser for web browsing. ┃
┃              ┃ solution : Use Tor Browser for anonymous browsing. Keep torsocks for compatible and tested CLI tools.                   ┃
┃              ┃ learn more : https://support.torproject.org/                                                                            ┃
╠══════════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
┃ [system]     ┃                                                                                                                         ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ INFO         ┃ USEFUL SYSTEM COMMANDS ARE MISSING                                                                                      ┃
┃              ┃ evidence : resolvectl                                                                                                   ┃
┃              ┃ why : Some system commands improve scan accuracy, but their absence should never crash the application.                 ┃
┃              ┃ solution : Install useful packages for your distribution. On Debian/Ubuntu: iproute2 for ip/ss, util-linux for          ┃
┃              ┃            lsblk/findmnt/swapon.                                                                                        ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ LINUX SYSTEM DETECTED (P+2 H+1)                                                                                         ┃
┃              ┃ evidence : Kali GNU/Linux Rolling                                                                                       ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ TO KNOW      ┃ PACKAGES PENDING UPDATE DETECTED                                                                                        ┃
┃              ┃ evidence : unattended-upgrades=no, upgradable=11, held=0, held_upgradable=0, effective_upgradable=11                    ┃
┃              ┃ why : Outdated packages may contain known vulnerabilities. Packages intentionally held back must be separated from real ┃
┃              ┃       update neglect.                                                                                                   ┃
┃              ┃ solution : Check: apt list --upgradable and apt-mark showhold. Update everything that is not intentionally held.        ┃
┃              ┃ learn more : https://wiki.debian.org/UnattendedUpgrades                                                                 ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ CORRECT      ┃ HOME DIRECTORY PERMISSIONS LOOK CORRECT (P+1 H+1)                                                                       ┃
┃              ┃ evidence : /root mode 0o700; others_utilisateurs=['user1']                                                                 ┃
┃              ┃ why : A home directory readable by other local users may expose documents, browser profiles, SSH keys or shell history. ┃
┃              ┃       If there are no other human users, the practical risk is lower.                                                   ┃
┃              ┃ solution : List human users, then use chmod 700 $HOME if needed. Be careful with intentionally shared folders.          ┃
┃              ┃ learn more : https://wiki.archlinux.org/title/File_permissions_and_attributes                                           ┃
┗━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```
