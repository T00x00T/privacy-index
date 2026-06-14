from __future__ import annotations

import glob
import json
import re
import sqlite3
import shutil
import tempfile
from pathlib import Path
from privacy_index.core.models import Finding, ScanContext, Severity
from privacy_index.core.utils import HOME, command_exists, read_text_safe, load_json_safe, run_cmd, desktop_app_exists


BROWSER_COMMANDS = {
    "tor-browser": ["tor-browser", "torbrowser-launcher", "start-tor-browser"],
    "mullvad-browser": ["mullvad-browser", "mullvad-browser-stable"],
    "librewolf": ["librewolf", "librewolf-bin", "librewolf-appimage", "librewolf-git"],
    "brave": ["brave-browser", "brave"],
    "firefox": ["firefox", "firefox-esr"],
    "chromium": ["chromium", "chromium-browser"],
    "chrome": ["google-chrome", "google-chrome-stable"],
    "edge": ["microsoft-edge", "microsoft-edge-stable"],
    "opera": ["opera", "opera-stable"],
    "vivaldi": ["vivaldi", "vivaldi-stable"],
}

PRIVACY_EXTENSIONS = {
    "ublock origin", "noscript", "clearurls", "privacy badger", "cookie autodelete",
    "decentraleyes", "localcdn", "temporary containers", "multi-account containers",
    "webrtc control", "web rtc control", "disable webrtc", "ublock",
}
RISKY_EXTENSIONS = {
    "honey", "grammarly", "lastpass", "avast", "avg", "norton", "mcafee",
}

                                                                                     
                                                                             
PRIVACY_EXTENSION_IDS = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "jflhchccmppkcccejihaekdnjhpcfpcd": "WebRTC Control",
    "hdokiejnpimakedhajhdlcegeplioahd": "LastPass? / known extension ID collision check",
}
                                                                                            
PRIVACY_EXTENSION_IDS.pop("hdokiejnpimakedhajhdlcegeplioahd", None)


def _flatpak_names() -> str:
    rc, out, _ = run_cmd(["flatpak", "list", "--app", "--columns=application,name"], timeout=3)
    return out.lower() if rc == 0 else ""






def _tokenize_command(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
                                                    
    value = re.sub(r"\s+%[a-zA-Z]", "", value)
                                                                   
    return value.split()[0].strip('"\'')


def _desktop_hits_for_browser(browser: str, commands: list[str], labels: list[str]) -> list[str]:
    hits: list[str] = []
    cmd_set = set(commands)
    labels_l = [x.lower() for x in labels]
    try:
        from privacy_index.core.utils import desktop_entries
        entries = desktop_entries()
    except Exception:
        return []
    for e in entries:
        hay = " ".join(e.get(k, "") for k in ["id", "Name", "GenericName", "Exec", "TryExec", "StartupWMClass"]).lower()
        if not any(label in hay for label in labels_l):
            continue
        exec_cmd = _tokenize_command(e.get("TryExec", "") or e.get("Exec", ""))
        base = Path(exec_cmd).name if exec_cmd else ""
        valid = False
        if exec_cmd:
            if exec_cmd.startswith("/") and Path(exec_cmd).exists():
                valid = True
            elif command_exists(exec_cmd) or base in cmd_set or any(command_exists(c) for c in cmd_set if c == base):
                valid = True
                                                                      
        if "flatpak run" in (e.get("Exec", "").lower()) and browser in _flatpak_detected_browsers():
            valid = True
        if valid:
            hits.append(f"desktop:{Path(e.get('path','')).name or browser}")
    return sorted(set(hits))


def _dpkg_installed(names: list[str]) -> list[str]:
    if not command_exists("dpkg-query"):
        return []
    hits: list[str] = []
    for name in names:
        rc, out, _ = run_cmd(["dpkg-query", "-W", "-f=${db:Status-Abbrev} ${binary:Package}\n", name], timeout=2)
        if rc == 0 and out.startswith("ii "):
            hits.append(f"dpkg:{name}")
    return hits


def _pacman_installed(names: list[str]) -> list[str]:
    if not command_exists("pacman"):
        return []
    hits: list[str] = []
    for name in names:
        rc, _, _ = run_cmd(["pacman", "-Q", name], timeout=2)
        if rc == 0:
            hits.append(f"pacman:{name}")
    return hits


def _rpm_installed(names: list[str]) -> list[str]:
    if not command_exists("rpm"):
        return []
    hits: list[str] = []
    for name in names:
        rc, _, _ = run_cmd(["rpm", "-q", name], timeout=2)
        if rc == 0:
            hits.append(f"rpm:{name}")
    return hits


BROWSER_PACKAGES = {
    "tor-browser": ["torbrowser-launcher", "tor-browser", "tor-browser-launcher"],
    "mullvad-browser": ["mullvad-browser", "mullvad-browser-stable"],
    "librewolf": ["librewolf", "librewolf-bin", "librewolf-appimage", "librewolf-git"],
    "brave": ["brave-browser", "brave-browser-stable"],
    "firefox": ["firefox", "firefox-esr"],
    "chromium": ["chromium", "chromium-browser"],
    "chrome": ["google-chrome-stable", "google-chrome"],
    "edge": ["microsoft-edge-stable", "microsoft-edge"],
    "opera": ["opera-stable", "opera"],
    "vivaldi": ["vivaldi-stable", "vivaldi"],
}


FLATPAK_APP_IDS = {
    "brave": ["com.brave.Browser"],
    "librewolf": ["io.gitlab.librewolf-community"],
    "mullvad-browser": ["net.mullvad.MullvadBrowser"],
    "tor-browser": ["com.github.micahflee.torbrowser-launcher"],
    "chrome": ["com.google.Chrome"],
    "edge": ["com.microsoft.Edge"],
    "opera": ["com.opera.Opera"],
    "chromium": ["org.chromium.Chromium"],
    "vivaldi": ["com.vivaldi.Vivaldi"],
}


def _flatpak_detected_browsers() -> set[str]:
    flatpak = _flatpak_names()
    found: set[str] = set()
    for browser, app_ids in FLATPAK_APP_IDS.items():
        if any(app_id.lower() in flatpak for app_id in app_ids):
            found.add(browser)
    return found


def detect_browser_sources() -> dict[str, list[str]]:
    sources: dict[str, list[str]] = {}
    for browser, commands in BROWSER_COMMANDS.items():
        hits: list[str] = []
        hits.extend(f"PATH:{c}" for c in commands if command_exists(c))
        pkgs = BROWSER_PACKAGES.get(browser, commands)
        hits.extend(_dpkg_installed(pkgs))
        hits.extend(_pacman_installed(pkgs))
        hits.extend(_rpm_installed(pkgs))
        if browser in _flatpak_detected_browsers():
            hits.append("flatpak")
        labels = {
            "brave": ["brave-browser", "brave browser"],
            "librewolf": ["librewolf", "librewolf-bin", "librewolf-appimage", "librewolf-git"],
            "mullvad-browser": ["mullvad-browser", "mullvad browser"],
            "tor-browser": ["torbrowser", "tor browser", "start-tor-browser"],
            "chrome": ["google-chrome", "google chrome"],
            "edge": ["microsoft-edge", "microsoft edge"],
            "opera": ["opera-stable", "opera browser", "com.opera.opera"],
            "chromium": ["chromium-browser", "chromium"],
            "vivaldi": ["vivaldi-stable", "vivaldi"],
            "firefox": ["firefox", "firefox-esr"],
        }.get(browser, commands)
        hits.extend(_desktop_hits_for_browser(browser, commands, labels))
        if browser == "tor-browser":
            hits.extend(f"tarball:{m}" for m in _tor_browser_install_markers()[:2])
        if browser == "mullvad-browser":
            hits.extend(f"tarball:{m}" for m in _mullvad_browser_install_markers()[:2])
        if browser == "librewolf":
            hits.extend(f"portable:{m}" for m in _librewolf_install_markers()[:2])
        if hits:
            sources[browser] = sorted(set(hits))
    return sources


def _tor_browser_install_markers() -> list[str]:
    candidates = [
        HOME / "tor-browser",
        HOME / "Downloads" / "tor-browser",
        HOME / "Applications" / "tor-browser",
        HOME / ".local" / "share" / "torbrowser",
        HOME / ".local" / "share" / "tor-browser",
        HOME / ".tor-browser",
    ]
    markers: list[str] = []
    for base in candidates:
        for rel in [
            Path("Browser/start-tor-browser"),
            Path("start-tor-browser.desktop"),
            Path("Browser/TorBrowser/Data/Browser/profile.default/prefs.js"),
        ]:
            if (base / rel).exists():
                markers.append(str(base / rel))
                break
                                                                    
    for pattern in ["tor-browser*", "Tor Browser*"]:
        for base in HOME.glob(pattern):
            if (base / "Browser" / "start-tor-browser").exists():
                markers.append(str(base / "Browser" / "start-tor-browser"))
                                                                              
    if not markers:
        for d in _broad_browser_dir_search(["*tor-browser*", "*torbrowser*"]):
            base = Path(d)
            for rel in [
                Path("Browser/start-tor-browser"),
                Path("start-tor-browser.desktop"),
                Path("Browser/TorBrowser/Data/Browser/profile.default/prefs.js"),
            ]:
                if (base / rel).exists():
                    markers.append(str(base / rel))
                    break
            else:
                markers.append(str(base))
    return sorted(set(markers))


def _mullvad_browser_install_markers() -> list[str]:
    candidates = [
        HOME / "mullvad-browser",
        HOME / "Downloads" / "mullvad-browser",
        HOME / "Applications" / "mullvad-browser",
        HOME / ".mullvad" / "mullvad-browser",
        HOME / ".local" / "share" / "mullvad-browser",
        HOME / ".local" / "share" / "Mullvad Browser",
        HOME / ".var" / "app" / "net.mullvad.MullvadBrowser" / ".mullvad" / "mullvad-browser",
    ]
    markers: list[str] = []
    for base in candidates:
        for rel in [
            Path("Browser/start-mullvad-browser"),
            Path("start-mullvad-browser.desktop"),
            Path("Browser/TorBrowser/Data/Browser/profile.default/prefs.js"),
            Path("Browser/MullvadBrowser/Data/Browser/profile.default/prefs.js"),
        ]:
            if (base / rel).exists():
                markers.append(str(base / rel))
                break
    for pattern in ["mullvad-browser*", "Mullvad Browser*"]:
        for base in HOME.glob(pattern):
            if (base / "Browser" / "start-mullvad-browser").exists() or (base / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default" / "prefs.js").exists() or (base / "Browser" / "MullvadBrowser" / "Data" / "Browser" / "profile.default" / "prefs.js").exists():
                markers.append(str(base))
    if not markers:
        for d in _broad_browser_dir_search(["*mullvad-browser*", "*mullvad browser*"]):
            base = Path(d)
            for rel in [
                Path("Browser/start-mullvad-browser"),
                Path("start-mullvad-browser.desktop"),
                Path("Browser/TorBrowser/Data/Browser/profile.default/prefs.js"),
                Path("Browser/MullvadBrowser/Data/Browser/profile.default/prefs.js"),
            ]:
                if (base / rel).exists():
                    markers.append(str(base / rel))
                    break
            else:
                markers.append(str(base))
    return sorted(set(markers))




def _librewolf_install_markers() -> list[str]:
    markers: list[str] = []
    candidates = [
        HOME / "Applications",
        HOME / "Downloads",
        HOME / ".local" / "bin",
        HOME / ".local" / "share" / "applications",
        Path("/opt"),
        Path("/usr/lib"),
        Path("/usr/local"),
    ]
    for base in candidates:
        if not base.exists():
            continue
        for pat in ["LibreWolf*.AppImage", "librewolf*.AppImage", "librewolf", "LibreWolf", "librewolf*"]:
            for hit in base.glob(pat):
                if hit.exists():
                    markers.append(str(hit))
                    if len(markers) >= 8:
                        return sorted(set(markers))
    return sorted(set(markers))


def _broad_browser_dir_search(patterns: list[str], *, max_results: int = 12) -> list[str]:
    find_bin = shutil.which("find")
    if not find_bin:
        return []
    roots = ["/home", "/opt", "/usr/local", "/usr/lib", "/var/lib/flatpak", str(HOME)]
    found: list[str] = []
    seen_roots: set[str] = set()
    for root in roots:
        if not root or root in seen_roots or not Path(root).exists():
            continue
        seen_roots.add(root)
                                                                      
        expr: list[str] = []
        for i, pat in enumerate(patterns):
            if i:
                expr.append("-o")
            expr.extend(["-iname", pat])
        cmd = [find_bin, root, "-maxdepth", "5", "-type", "d", "(", *expr, ")"]
        rc, out, _ = run_cmd(cmd, timeout=4)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                line = line.strip()
                if line and line not in found:
                    found.append(line)
                    if len(found) >= max_results:
                        return found
    return found

def _tor_browser_data_dirs() -> list[Path]:
    dirs: list[Path] = [
        HOME / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        HOME / "Downloads" / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        HOME / "Applications" / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        HOME / ".local" / "share" / "torbrowser" / "tbb" / "x86_64" / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        HOME / ".local" / "share" / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        HOME / ".var" / "app" / "com.github.micahflee.torbrowser-launcher" / "data" / "torbrowser" / "tbb" / "x86_64" / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
    ]
    for pattern in ["tor-browser*", "Tor Browser*"]:
        for base in HOME.glob(pattern):
            dirs.append(base / "Browser" / "TorBrowser" / "Data" / "Browser")
    for marker in _tor_browser_install_markers():
        m = Path(marker)
        candidates = [m, m.parent, m.parent.parent, m.parent.parent.parent]
        for c in candidates:
            dirs.append(c / "Browser" / "TorBrowser" / "Data" / "Browser")
            if c.name in {"Browser", "tor-browser", "tor-browser_en-US"} or "tor-browser" in str(c).lower():
                dirs.append(c / "TorBrowser" / "Data" / "Browser")
    return sorted({d for d in dirs if d.exists() or (d / "profile.default" / "prefs.js").exists()})


def _mullvad_browser_data_dirs() -> list[Path]:
    roots = [
        HOME / "mullvad-browser",
        HOME / "Downloads" / "mullvad-browser",
        HOME / "Applications" / "mullvad-browser",
        HOME / ".mullvad" / "mullvad-browser",
        HOME / ".local" / "share" / "mullvad-browser",
        HOME / ".local" / "share" / "Mullvad Browser",
        HOME / ".var" / "app" / "net.mullvad.MullvadBrowser" / ".mullvad" / "mullvad-browser",
        HOME / ".var" / "app" / "net.mullvad.MullvadBrowser" / "data" / "mullvad-browser",
    ]
    dirs: list[Path] = []
    for root in roots:
        for app_dir in ["TorBrowser", "MullvadBrowser"]:
            dirs.append(root / "Browser" / app_dir / "Data" / "Browser")
    for pattern in ["mullvad-browser*", "Mullvad Browser*"]:
        for base in HOME.glob(pattern):
            for app_dir in ["TorBrowser", "MullvadBrowser"]:
                dirs.append(base / "Browser" / app_dir / "Data" / "Browser")
    for marker in _mullvad_browser_install_markers():
        m = Path(marker)
        candidates = [m, m.parent, m.parent.parent, m.parent.parent.parent]
        for c in candidates:
            for app_dir in ["TorBrowser", "MullvadBrowser"]:
                dirs.append(c / "Browser" / app_dir / "Data" / "Browser")
                dirs.append(c / app_dir / "Data" / "Browser")
    return sorted({d for d in dirs if d.exists() or (d / "profile.default" / "prefs.js").exists()})


def _profile_dirs_for_data_dirs(data_dirs: list[Path]) -> list[Path]:
    return _profile_dirs(data_dirs)


def detect_browsers() -> list[str]:
    return sorted(detect_browser_sources().keys())


def _profile_dirs(base_dirs: list[Path]) -> list[Path]:
    profiles: list[Path] = []
    for base in base_dirs:
        if not base.exists():
            continue
        profiles.extend(Path(p) for p in glob.glob(str(base / "*.default*")))
        profiles.extend(Path(p) for p in glob.glob(str(base / "*.librewolf*")))
        profiles.extend(Path(p) for p in glob.glob(str(base / "profile.default*")))
        if (base / "prefs.js").exists():
            profiles.append(base)
                                        
    out=[]; seen=set()
    for p in profiles:
        if p not in seen:
            out.append(p); seen.add(p)
    return out


def _pref_bool(txt: str, name: str) -> bool | None:
    m = re.search(r'user_pref\("' + re.escape(name) + r'",\s*(true|false)\)', txt)
    if not m:
        return None
    return m.group(1) == "true"


def _has_any_false(txt: str, names: list[str]) -> bool:
    return any(_pref_bool(txt, n) is False for n in names)


def scan_firefox_like(ctx: ScanContext, product: str, base_dirs: list[Path], *, hardened_by_default: bool = False) -> None:
    profiles = _profile_dirs(base_dirs)
    prefs_files = [p / "prefs.js" for p in profiles if (p / "prefs.js").exists()]
    if not prefs_files:
        return

    good = 0
    hard_bad = 0
    evidence_parts = []
    for prefs in prefs_files[:5]:
        txt = read_text_safe(prefs)
        rfp = _pref_bool(txt, "privacy.resistFingerprinting")
        webrtc = _pref_bool(txt, "media.peerconnection.enabled")
        webrtc_off = webrtc is False

        telemetry_enabled = any(_pref_bool(txt, n) is True for n in [
            "toolkit.telemetry.enabled",
            "toolkit.telemetry.unified",
            "datareporting.healthreport.uploadEnabled",
            "datareporting.policy.dataSubmissionEnabled",
            "browser.newtabpage.activity-stream.feeds.telemetry",
            "browser.newtabpage.activity-stream.telemetry",
        ])
        telemetry_off = _has_any_false(txt, [
            "toolkit.telemetry.enabled",
            "toolkit.telemetry.unified",
            "datareporting.healthreport.uploadEnabled",
            "datareporting.policy.dataSubmissionEnabled",
            "browser.newtabpage.activity-stream.feeds.telemetry",
            "browser.newtabpage.activity-stream.telemetry",
        ])
                                                                                   
                                                                                 
        telemetry_state = "off" if telemetry_off else ("on" if telemetry_enabled else "unknown")

        trr = re.search(r'user_pref\("network\.trr\.mode",\s*([0-9]+)\)', txt)
        doh = bool(trr and trr.group(1) in {"2", "3"})

        good += int(rfp is True or hardened_by_default) + int(webrtc_off) + int(telemetry_state != "on") + int(doh)
        hard_bad += int(webrtc is True) + int(telemetry_state == "on")
        evidence_parts.append(
            f"{prefs.parent.name}: RFP={rfp if rfp is not None else ('default/hardened' if hardened_by_default else 'absent')}, "
            f"WebRTC={'disabled' if webrtc_off else ('enabled' if webrtc is True else 'unknown/default')}, telemetry={telemetry_state}, DoH={doh}"
        )

    if hardened_by_default and hard_bad == 0:
                                                                                
                                                                                
                                                                             
                                     
        status = Severity.INFO
        title = f"Paramètres {product} standards observés"
        privacy = 1
        anon = 1
        recommendation = "Conserver les réglages par défaut sauf besoin très précis. Ajouter des extensions ou modifier about:config peut réduire l'uniformité du fingerprint."
    else:
        status = Severity.OK if hard_bad == 0 and good >= 3 else Severity.WARN
        title = f"Réglages {product} favorables" if status == Severity.OK else f"Réglages {product} à vérifier"
        privacy = 2 if status == Severity.OK else 0
        anon = 2 if status == Severity.OK else -1
        recommendation = "Vérifier RFP/anti-fingerprinting, WebRTC, télémétrie et éventuellement DoH/TRR. Une valeur absente peut être un défaut navigateur, pas forcément un problème confirmé."

    ctx.add(Finding(
        category="browser",
        key=f"{product.lower().replace(' ', '-')}.prefs",
        title=title,
        status=status,
        privacy=privacy,
        anonymity=anon,
        evidence="; ".join(evidence_parts),
        recommendation=recommendation,
        confidence="medium",
    ))



def scan_individual_browser_inventory(ctx: ScanContext, browser_sources: dict[str, list[str]]) -> None:
    labels = {
        "brave": "Brave",
        "firefox": "Firefox",
        "chromium": "Chromium",
        "chrome": "Google Chrome",
        "edge": "Microsoft Edge",
        "opera": "Opera",
        "vivaldi": "Vivaldi",
    }
    statuses = {
        "brave": Severity.OK,
        "firefox": Severity.INFO,
        "chromium": Severity.WARN,
        "chrome": Severity.BAD,
        "edge": Severity.BAD,
        "opera": Severity.BAD,
        "vivaldi": Severity.WARN,
    }
    recommendations = {
        "brave": "Bon choix possible pour un usage quotidien si Shields, WebRTC, cookies tiers, sync et moteur de recherche sont vérifiés.",
        "firefox": "Navigateur correct si durci: vérifier RFP/anti-fingerprinting, WebRTC, télémétrie, DNS/DoH, extensions et moteur de recherche.",
        "chromium": "Base open source correcte, mais moins privacy par défaut: vérifier WebRTC, sync, Safe Browsing, cookies tiers, extensions et moteur de recherche.",
        "chrome": "À éviter comme navigateur principal pour les usages sensibles. Préférer Brave, LibreWolf, Mullvad Browser ou Tor Browser selon l'objectif.",
        "edge": "À éviter comme navigateur principal pour les usages sensibles. Vérifier télémétrie, sync, moteur de recherche et intégration au compte.",
        "opera": "À éviter comme navigateur principal pour les usages sensibles. Vérifier VPN intégré, télémétrie, sync et extensions.",
        "vivaldi": "Navigateur personnalisable mais à vérifier: télémétrie, sync, moteur de recherche, extensions et protection WebRTC.",
    }
    for browser_id in sorted(browser_sources.keys()):
        if browser_id in {"tor-browser", "mullvad-browser", "librewolf"}:
            continue
        label = labels.get(browser_id, browser_id)
        ctx.add(Finding(
            category="browser",
            key=f"browser.inventory.{browser_id}",
            title=f"Navigateur {label} détecté",
            status=statuses.get(browser_id, Severity.INFO),
            privacy=0,
            anonymity=0,
            hardening=0,
            evidence="; ".join(browser_sources.get(browser_id, [])[:8]) or "source non précisée",
            recommendation=recommendations.get(browser_id, "Vérifier les réglages, les extensions, le moteur de recherche et les données de profil."),
            confidence="high" if browser_sources.get(browser_id) else "medium",
        ))


def scan_tor_browser(ctx: ScanContext, browsers: list[str]) -> None:
    markers = _tor_browser_install_markers()
    profile_candidates = _profile_dirs_for_data_dirs(_tor_browser_data_dirs())
    has_profile = any((p / "prefs.js").exists() for p in profile_candidates)
    ctx.fact("browser.tor_browser_markers", markers)
    if "tor-browser" in browsers or markers or has_profile:
        ctx.add(Finding(
            category="browser",
            key="tor-browser.detected",
            title="Tor Browser détecté",
            status=Severity.OK,
            privacy=2,
            anonymity=5,
            evidence=", ".join(markers[:3]) if markers else ("commande/desktop" if "tor-browser" in browsers else "profil Tor Browser détecté"),
            recommendation="Brique majeure pour l'anonymat web. Éviter les extensions supplémentaires, le plein écran distinctif et les connexions à des comptes personnels.",
            confidence="high" if "tor-browser" in browsers or markers else "medium",
        ))
        scan_firefox_like(ctx, "Tor Browser", profile_candidates, hardened_by_default=True)


def scan_mullvad_browser(ctx: ScanContext, browsers: list[str]) -> None:
    markers = _mullvad_browser_install_markers()
    candidates = _profile_dirs_for_data_dirs(_mullvad_browser_data_dirs())
    has_profile = any((p / "prefs.js").exists() for p in candidates)
    if "mullvad-browser" in browsers or markers or has_profile:
        ctx.add(Finding(
            category="browser",
            key="mullvad-browser.detected",
            title="Mullvad Browser détecté",
            status=Severity.OK,
            privacy=3,
            anonymity=3,
            evidence=", ".join(markers[:3]) if markers else ("commande/desktop/profil" if "mullvad-browser" in browsers else "profil Mullvad Browser détecté"),
            recommendation="Excellent choix pour réduire le fingerprinting en navigation classique. Éviter d'ajouter trop d'extensions pour ne pas casser l'uniformité du profil.",
            confidence="high" if "mullvad-browser" in browsers or markers else "medium",
        ))
        scan_firefox_like(ctx, "Mullvad Browser", candidates, hardened_by_default=True)


def _chromium_pref_paths() -> list[tuple[str, Path]]:
    candidates = [
        ("Brave", HOME / ".config/BraveSoftware/Brave-Browser/Default/Preferences"),
        ("Chromium", HOME / ".config/chromium/Default/Preferences"),
        ("Chrome", HOME / ".config/google-chrome/Default/Preferences"),
        ("Edge", HOME / ".config/microsoft-edge/Default/Preferences"),
        ("Vivaldi", HOME / ".config/vivaldi/Default/Preferences"),
        ("Opera", HOME / ".config/opera/Preferences"),
    ]
    return [(n, p) for n, p in candidates if p.exists()]


def scan_chromium_prefs(ctx: ScanContext, browsers: list[str]) -> None:
    installed_products = {
        'Brave': 'brave', 'Chromium': 'chromium', 'Chrome': 'chrome', 'Edge': 'edge', 'Vivaldi': 'vivaldi', 'Opera': 'opera'
    }
    for name, path in _chromium_pref_paths():
        browser_id = installed_products.get(name, name.lower())
        if browser_id not in browsers:
                                                                                
            continue
        data = load_json_safe(path)
        if not data:
            continue
        safebrowsing = data.get("safebrowsing", {}).get("enabled")
        intl = data.get("intl", {})
        search = data.get("default_search_provider", {}).get("short_name", "")
        webrtc_policy = data.get("webrtc", {}) or data.get("profile", {}).get("content_settings", {}).get("exceptions", {}).get("media_stream_mic", {})
        evidence = f"profile={path.parent.name}, search={search or 'inconnu'}, safebrowsing={safebrowsing}, intl={intl}, webrtc={webrtc_policy or 'non lisible'}"
        privacy_points = 1 if name == "Brave" else 0
        anon_points = 0 if name == "Brave" else -1
        status = Severity.OK if name == "Brave" else Severity.WARN
        ctx.add(Finding(
            category="browser",
            key=f"{name.lower()}.prefs",
            title=f"Profil {name} détecté" + (" — Shields à vérifier manuellement" if name == "Brave" else ""),
            status=status,
            privacy=privacy_points,
            anonymity=anon_points,
            evidence=evidence[:500],
            recommendation="Pour Chromium-like, la lecture locale ne suffit pas toujours: vérifier anti-fingerprint, cookies tiers, WebRTC, sync et télémétrie dans l'interface. Une extension comme WebRTC Control est un bon signal, mais ne prouve pas tout.",
            confidence="low" if name == "Brave" else "medium",
        ))


def _firefox_residual_profile_paths(product: str) -> list[Path]:
    bases = {
        "Firefox": [
            HOME / ".mozilla" / "firefox",
            HOME / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
            HOME / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
        ],
        "LibreWolf": [
            HOME / ".librewolf",
            HOME / ".var" / "app" / "io.gitlab.librewolf-community" / ".librewolf",
        ],
    }.get(product, [])
    profiles: list[Path] = []
    for base in bases:
        profiles.extend(_profile_dirs([base]))
    return sorted({p for p in profiles if (p / "prefs.js").exists()})


def scan_residual_browser_profiles(ctx: ScanContext, browser_sources: dict[str, list[str]]) -> None:
    installed = set(browser_sources.keys())
    residual: list[str] = []

    chromium_ids = {
        'Brave': 'brave', 'Chromium': 'chromium', 'Chrome': 'chrome',
        'Edge': 'edge', 'Vivaldi': 'vivaldi', 'Opera': 'opera',
    }
    for name, path in _chromium_pref_paths():
        browser_id = chromium_ids.get(name, name.lower())
        if browser_id not in installed:
            residual.append(f"{name}:{path.parent}")

    for product, browser_id in [("Firefox", "firefox"), ("LibreWolf", "librewolf")]:
        if browser_id not in installed:
            for profile in _firefox_residual_profile_paths(product):
                residual.append(f"{product}:{profile}")

                                                                                
                                                                       
    if "tor-browser" not in installed and not _tor_browser_install_markers():
        for profile in _profile_dirs_for_data_dirs(_tor_browser_data_dirs()):
            if (profile / "prefs.js").exists():
                residual.append(f"Tor Browser:{profile}")
    if "mullvad-browser" not in installed and not _mullvad_browser_install_markers():
        for profile in _profile_dirs_for_data_dirs(_mullvad_browser_data_dirs()):
            if (profile / "prefs.js").exists():
                residual.append(f"Mullvad Browser:{profile}")

    residual = sorted(dict.fromkeys(residual))
    if not residual:
        return
    ctx.fact("browser.residual_profiles", residual)
    ctx.add(Finding(
        category="browser",
        key="browser.residual_profiles",
        title="Profils navigateurs résiduels détectés",
        status=Severity.INFO,
        privacy=0,
        anonymity=0,
        hardening=0,
        evidence="; ".join(residual[:12]),
        recommendation="Ces dossiers appartiennent probablement à des navigateurs désinstallés ou déplacés. Les supprimer uniquement après sauvegarde ou vérification, car ils peuvent contenir favoris, sessions, extensions, cookies, cache et anciens réglages.",
        confidence="medium",
    ))


def _resolve_manifest_name(manifest: Path, raw_name: str) -> str:
    name = raw_name or ""
    m = re.fullmatch(r"__MSG_(.+)__", name)
    if not m:
        return name
    key = m.group(1)
    for loc in ["en", "en_US", "fr", "fr_FR"]:
        msg = manifest.parent / "_locales" / loc / "messages.json"
        data = load_json_safe(msg)
        if key in data and isinstance(data[key], dict):
            return str(data[key].get("message", name))
    return name


def scan_extensions(ctx: ScanContext) -> None:
    roots = [
        HOME / ".mozilla/firefox",
        HOME / ".librewolf",
        HOME / ".mullvad" / "mullvad-browser",
        HOME / ".config/BraveSoftware/Brave-Browser/Default/Extensions",
        HOME / ".config/chromium/Default/Extensions",
        HOME / ".config/google-chrome/Default/Extensions",
    ]
    names: set[str] = set()
    id_hits: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        for manifest in root.glob("**/manifest.json"):
            data = load_json_safe(manifest)
            raw_name = str(data.get("name", ""))
            name = _resolve_manifest_name(manifest, raw_name).lower()
            if name and not name.startswith("__msg_"):
                names.add(name)
            parts = set(manifest.parts)
            for ext_id, label in PRIVACY_EXTENSION_IDS.items():
                if ext_id in parts:
                    id_hits.add(label)
    good = sorted([n for n in names if any(x in n for x in PRIVACY_EXTENSIONS)] + list(id_hits))
    risky = sorted([n for n in names if any(x in n for x in RISKY_EXTENSIONS)])
    if good:
        ctx.add(Finding(
            category="browser",
            key="extensions.privacy",
            title="Extensions utiles à la confidentialité détectées",
            status=Severity.OK,
            privacy=1,
            anonymity=0,
            evidence=", ".join(good[:10]),
            recommendation="Garder peu d'extensions: trop d'extensions rendent le navigateur plus fingerprintable. Sur Mullvad/Tor Browser, éviter les extensions supplémentaires.",
            confidence="medium",
        ))
    if risky:
        ctx.add(Finding(
            category="browser",
            key="extensions.risky",
            title="Extensions potentiellement bavardes détectées",
            status=Severity.WARN,
            privacy=-1,
            anonymity=-1,
            evidence=", ".join(risky[:8]),
            recommendation="Désinstaller les extensions inutiles, surtout celles qui lisent toutes les pages.",
            confidence="medium",
        ))



                                                                      
                                                                                                    
SEARCH_ENGINE_ALIASES = {
    "searx": "searx", "searxng": "searx", "searx.be": "searx",
    "mojeek": "mojeek",
    "brave": "brave search", "brave search": "brave search", "search.brave.com": "brave search",
    "duckduckgo": "duckduckgo", "duck duck go": "duckduckgo", "ddg": "duckduckgo", "duckduckgo.com": "duckduckgo",
    "startpage": "startpage", "startpage.com": "startpage",
    "qwant": "qwant", "qwant.com": "qwant",
    "google": "google", "google search": "google", "google.com": "google",
    "bing": "bing", "bing.com": "bing",
    "yandex": "yandex", "yandex.com": "yandex", "yandex.ru": "yandex",
    "baidu": "baidu", "baidu.com": "baidu",
    "yahoo": "yahoo", "search.yahoo": "yahoo",
    "ecosia": "ecosia", "ecosia.org": "ecosia",
}
SEARCH_ENGINE_CLASS = {
    "searx": "strong",
    "mojeek": "strong",
    "brave search": "good",
    "duckduckgo": "good",
    "startpage": "good",
    "qwant": "moderate",
    "google": "avoid",
    "bing": "avoid",
    "yandex": "avoid",
    "baidu": "avoid",
    "yahoo": "avoid",
    "ecosia": "avoid",
}


def _classify_search_engine(value: str) -> str | None:
    low = (value or "").lower()
    if not low:
        return None
                                                                       
    for needle, canonical in sorted(SEARCH_ENGINE_ALIASES.items(), key=lambda x: len(x[0]), reverse=True):
        if needle in low:
            return canonical
    return None


def _moz_lz4_json(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        if raw.startswith(b"mozLz40\x00"):
            try:
                import lz4.block                
                raw = lz4.block.decompress(raw[8:])
            except Exception:
                return {}
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {}


def _firefox_search_profiles(product: str, base_dirs: list[Path]) -> list[tuple[str, str, str]]:
    hits: list[tuple[str, str, str]] = []
    for profile in _profile_dirs(base_dirs):
        prefs = profile / "prefs.js"
        if prefs.exists():
            txt = read_text_safe(prefs)
            for pref in [
                "browser.search.defaultenginename",
                "browser.search.selectedEngine",
                "browser.search.defaultenginename.US",
            ]:
                m = re.search(r'user_pref\("' + re.escape(pref) + r'",\s*"([^"]+)"\)', txt)
                if m:
                    eng = _classify_search_engine(m.group(1))
                    if eng:
                        hits.append((product, profile.name, eng))
        sj = profile / "search.json.mozlz4"
        if sj.exists():
            data = _moz_lz4_json(sj)
            meta = data.get("metaData", {}) if isinstance(data, dict) else {}
            candidates = []
            for k in ["current", "defaultEngineId", "privateDefaultEngineId"]:
                if meta.get(k):
                    candidates.append(str(meta.get(k)))
            for engine in data.get("engines", []) if isinstance(data, dict) else []:
                if isinstance(engine, dict):
                                                                                                         
                    candidates.extend(str(engine.get(k, "")) for k in ["name", "id", "alias", "_name"])
                    for url in engine.get("urls", []) or []:
                        if isinstance(url, dict):
                            candidates.append(str(url.get("template", "")))
            for c in candidates:
                eng = _classify_search_engine(c)
                if eng:
                    hits.append((product, profile.name, eng))
                    break
    return hits


def _chromium_webdata_engines(path: Path) -> list[str]:
    db = path.parent / "Web Data"
    if not db.exists():
        return []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="privacy-index-webdata-", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        shutil.copy2(db, tmp_path)
        con = sqlite3.connect(str(tmp_path))
        try:
            cur = con.execute("SELECT short_name, keyword, url, suggest_url FROM keywords")
            engines = []
            for row in cur.fetchall():
                joined = " ".join(str(x or "") for x in row)
                eng = _classify_search_engine(joined)
                if eng:
                    engines.append(eng)
            return list(dict.fromkeys(engines))
        finally:
            con.close()
    except Exception:
        return []
    finally:
        if tmp_path:
            try:
                tmp_path.unlink()
            except Exception:
                pass


def _chromium_search_profiles(browsers: list[str]) -> list[tuple[str, str, str, str]]:
    product_ids = {'Brave': 'brave', 'Chromium': 'chromium', 'Chrome': 'chrome', 'Edge': 'edge', 'Vivaldi': 'vivaldi', 'Opera': 'opera'}
    hits: list[tuple[str, str, str, str]] = []
    for name, path in _chromium_pref_paths():
        if product_ids.get(name, name.lower()) not in browsers:
            continue
        data = load_json_safe(path)
                                                                                     
        candidates: list[str] = []
        dsp = data.get("default_search_provider", {}) if isinstance(data, dict) else {}
        if isinstance(dsp, dict):
            for k in ["short_name", "name", "keyword", "search_url", "suggest_url", "favicon_url"]:
                if dsp.get(k):
                    candidates.append(str(dsp.get(k)))
        for c in candidates:
            eng = _classify_search_engine(c)
            if eng:
                hits.append((name, path.parent.name, eng, "Preferences"))
                break
        else:
            engines = _chromium_webdata_engines(path)
                                                                                     
            if len(engines) == 1:
                hits.append((name, path.parent.name, engines[0], "Web Data"))
            elif engines:
                                                                                                     
                hits.append((name, path.parent.name, "/".join(engines[:4]), "Web Data candidates"))
    return hits


def scan_search_engines(ctx: ScanContext, browsers: list[str]) -> None:
    hits3: list[tuple[str, str, str]] = []
    if 'firefox' in browsers:
        hits3.extend(_firefox_search_profiles("Firefox", [HOME / ".mozilla/firefox"]))
    if 'librewolf' in browsers:
        hits3.extend(_firefox_search_profiles("LibreWolf", [HOME / ".librewolf"]))
    if 'mullvad-browser' in browsers:
        hits3.extend(_firefox_search_profiles("Mullvad Browser", _mullvad_browser_data_dirs()))
    if 'tor-browser' in browsers:
        hits3.extend(_firefox_search_profiles("Tor Browser", _tor_browser_data_dirs()))
    hits4 = _chromium_search_profiles(browsers)

    tor_dirs = _tor_browser_data_dirs() if 'tor-browser' in browsers else []
    mullvad_dirs = _mullvad_browser_data_dirs() if 'mullvad-browser' in browsers else []

    ctx.fact("browser.search_engine_profile_dirs", {
        "tor_browser": [str(p) for p in tor_dirs],
        "mullvad_browser": [str(p) for p in mullvad_dirs],
    })
    ctx.fact("browser.search_engines", {"firefox_like": hits3, "chromium_like": hits4})

    evidence_items: list[str] = []
    engines: list[str] = []
    low_confidence = False

    for product, profile, engine in hits3:
        engines.append(engine)
        evidence_items.append(f"{product}/{profile}: {engine}")
    for product, profile, engine, source in hits4:
        if "/" in engine:
            low_confidence = True
            engines.extend(engine.split("/"))
        else:
            engines.append(engine)
        evidence_items.append(f"{product}/{profile}: {engine} ({source})")

                                                                            
                                                                                 
                                                             
    browser_display = {
        "firefox": "Firefox",
        "librewolf": "LibreWolf",
        "mullvad-browser": "Mullvad Browser",
        "tor-browser": "Tor Browser",
        "brave": "Brave",
        "chromium": "Chromium",
        "chrome": "Chrome",
        "edge": "Edge",
        "opera": "Opera",
        "vivaldi": "Vivaldi",
    }
    found_products = {product for product, _profile, _engine in hits3}
    found_products.update({product for product, _profile, _engine, _source in hits4})
    for browser_id in browsers:
        product = browser_display.get(browser_id, browser_id)
        if product not in found_products:
            evidence_items.append(f"{product}/default: inconnu")
            low_confidence = True

    engines = list(dict.fromkeys([e for e in engines if e]))
    evidence = "; ".join(evidence_items[:20]) if evidence_items else "Firefox search.json.mozlz4 / Chromium Preferences-Web Data non concluants"

    if not engines:
        ctx.add(Finding(
            category="browser",
            key="search_engine.unknown",
            title="Moteur de recherche par défaut non déterminé localement",
            status=Severity.UNKNOWN,
            privacy=0,
            anonymity=0,
            evidence=evidence,
            recommendation="Vérifier dans chaque navigateur le moteur par défaut et le moteur en navigation privée. Préférer Mojeek, SearXNG, Brave Search, DuckDuckGo, StartPage ou Qwant selon le modèle de menace.",
            confidence="low",
        ))
        return

    avoid = [e for e in engines if SEARCH_ENGINE_CLASS.get(e) == "avoid"]
    strong = [e for e in engines if SEARCH_ENGINE_CLASS.get(e) == "strong"]
    good = [e for e in engines if SEARCH_ENGINE_CLASS.get(e) in {"good", "moderate"}]

    if avoid and not (strong or good):
        ctx.add(Finding(
            category="browser",
            key="search_engine.avoid",
            title="Moteur de recherche peu favorable détecté",
            status=Severity.BAD,
            privacy=-2,
            anonymity=-1,
            evidence=evidence,
            recommendation="Remplacer Google/Bing/Yandex/Baidu/Yahoo/Ecosia par Mojeek, SearXNG, Brave Search, DuckDuckGo, StartPage ou Qwant selon l'objectif.",
            confidence="medium" if not low_confidence else "low",
        ))
    elif avoid and (strong or good):
        ctx.add(Finding(
            category="browser",
            key="search_engine.mixed",
            title="Moteurs de recherche mixtes détectés",
            status=Severity.WARN,
            privacy=0,
            anonymity=0,
            evidence=evidence,
            recommendation="Plusieurs moteurs semblent présents. Vérifier le moteur par défaut de chaque navigateur et celui utilisé en navigation privée.",
            confidence="low" if low_confidence else "medium",
        ))
    elif strong:
        ctx.add(Finding(
            category="browser",
            key="search_engine.privacy_strong",
            title="Moteur de recherche très favorable à la vie privée détecté",
            status=Severity.OK,
            privacy=2,
            anonymity=1,
            evidence=evidence,
            recommendation="Bon choix. SearXNG auto-hébergé ou Mojeek réduisent fortement la dépendance aux grands moteurs publicitaires; garder aussi un navigateur bien réglé.",
            confidence="medium" if not low_confidence else "low",
        ))
    else:
        ctx.add(Finding(
            category="browser",
            key="search_engine.privacy_good",
            title="Moteur de recherche plutôt favorable à la vie privée détecté",
            status=Severity.OK,
            privacy=1,
            anonymity=0,
            evidence=evidence,
            recommendation="Bon signal. DuckDuckGo/Brave Search/StartPage/Qwant sont préférables aux moteurs publicitaires classiques, même si cela ne remplace pas Tor/Mullvad Browser pour l'anonymat.",
            confidence="medium" if not low_confidence else "low",
        ))

def scan(ctx: ScanContext) -> None:
    browser_sources = detect_browser_sources()
    browsers = sorted(browser_sources.keys())
    ctx.fact("browsers.installed", browsers)
    ctx.fact("browsers.installed_sources", browser_sources)
    if not browsers:
        scan_residual_browser_profiles(ctx, browser_sources)
        ctx.add(Finding(
            category="browser",
            key="browser.none",
            title="Aucun navigateur connu détecté",
            status=Severity.UNKNOWN,
            evidence="PATH, desktop files, flatpak",
            recommendation="Vérifier manuellement si le navigateur est installé hors chemins standards.",
            confidence="low",
        ))
        return

    good = {"tor-browser", "mullvad-browser", "librewolf", "brave"}
    ok = {"firefox", "chromium"}
    bad = {"chrome", "edge", "opera"}
    has_good = any(b in browsers for b in good)
    has_bad = any(b in browsers for b in bad)
    privacy = 3 if has_good else (1 if any(b in browsers for b in ok) else -2)
    anonymity = 4 if "tor-browser" in browsers or "mullvad-browser" in browsers else (1 if "librewolf" in browsers else -1 if has_bad else 0)
    status = Severity.OK if has_good else Severity.WARN if any(b in browsers for b in ok) else Severity.BAD
    ctx.add(Finding(
        category="browser",
        key="browser.installed",
        title="Navigateurs orientés vie privée détectés" if has_good else "Navigateurs installés à durcir ou remplacer",
        status=status,
        privacy=privacy,
        anonymity=anonymity,
        evidence="; ".join(f"{b} ({', '.join(browser_sources.get(b, [])[:3])})" for b in browsers),
        recommendation="Priorité: Tor Browser/Mullvad Browser pour anonymat ou anti-fingerprinting, LibreWolf ou Brave durci pour usage quotidien.",
        confidence="high",
    ))
    scan_individual_browser_inventory(ctx, browser_sources)

    if "librewolf" in browsers:
        ctx.add(Finding(
            category="browser",
            key="librewolf.detected",
            title="Navigateur LibreWolf détecté",
            status=Severity.OK,
            privacy=2,
            anonymity=1,
            evidence="; ".join(browser_sources.get("librewolf", [])),
            recommendation="LibreWolf est un bon choix pour un usage quotidien orienté privacy. Vérifier quand même les extensions, le moteur de recherche et les exceptions de sites.",
            confidence="high",
        ))

    if has_bad:
        ctx.add(Finding(
            category="browser",
            key="browser.tracking_risk",
            title="Navigateur commercial peu favorable détecté",
            status=Severity.BAD,
            privacy=-2,
            anonymity=-2,
            evidence=", ".join([b for b in browsers if b in bad]),
            recommendation="Éviter de l'utiliser comme navigateur principal pour les usages sensibles. Si c'est un faux positif, lancer avec --debug-facts ou vérifier les .desktop/flatpak/PATH.",
            confidence="medium",
        ))

    scan_tor_browser(ctx, browsers)
    scan_mullvad_browser(ctx, browsers)
    scan_firefox_like(ctx, "Firefox", [HOME / ".mozilla/firefox"])
    scan_firefox_like(ctx, "LibreWolf", [HOME / ".librewolf"])
    scan_chromium_prefs(ctx, browsers)
    scan_residual_browser_profiles(ctx, browser_sources)
    scan_search_engines(ctx, browsers)
    scan_extensions(ctx)
