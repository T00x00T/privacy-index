from __future__ import annotations

import shutil
import subprocess
import tempfile
import webbrowser
from dataclasses import dataclass
from pathlib import Path

from privacy_index.core.i18n import browser_ui as bui, html_lang, normalize_lang


EXTERNAL_TESTS = [
    ("WebRTC leak test", "https://browserleaks.com/webrtc"),
    ("DNS leak test", "https://www.dnsleaktest.com/"),
    ("Fingerprint test", "https://coveryourtracks.eff.org/"),
]


@dataclass(frozen=True)
class BrowserCandidate:
    label: str
    command: str
    args: tuple[str, ...] = ()


                                                                                 
                                                                                    
                                                          
KNOWN_BROWSERS: tuple[BrowserCandidate, ...] = (
    BrowserCandidate("Mullvad Browser", "mullvad-browser", ("--new-tab",)),
    BrowserCandidate("Tor Browser Launcher", "torbrowser-launcher", ()),
    BrowserCandidate("Tor Browser", "tor-browser", ()),
    BrowserCandidate("LibreWolf", "librewolf", ("--new-tab",)),
    BrowserCandidate("Firefox", "firefox", ("--new-tab",)),
    BrowserCandidate("Firefox ESR", "firefox-esr", ("--new-tab",)),
    BrowserCandidate("Brave", "brave-browser", ("--new-tab",)),
    BrowserCandidate("Chromium", "chromium", ("--new-tab",)),
    BrowserCandidate("Google Chrome", "google-chrome", ("--new-tab",)),
)


def _yes(prompt: str) -> bool:
    return input(prompt).strip().lower() in {"o", "oui", "y", "yes", "j", "ja"}


def detected_browsers() -> list[BrowserCandidate]:
    return [b for b in KNOWN_BROWSERS if shutil.which(b.command)]


def open_with_browser(browser: BrowserCandidate | None, url: str, *, lang: str = "fr") -> bool:
    try:
        if browser is None:
            return bool(webbrowser.open_new_tab(url))
        subprocess.Popen(
            [browser.command, *browser.args, url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except Exception as exc:
        label = browser.label if browser else bui(lang, "default_browser")
        print(bui(lang, "cannot_open").format(url=url, label=label, exc=exc))
        return False


def _select_browsers(target: str | None, assume_yes: bool, *, lang: str) -> list[BrowserCandidate | None]:
    if target:
        t = target.strip().lower()
        if t in {"default", "system", "auto"}:
            return [None]
        matches = [b for b in detected_browsers() if t in b.label.lower() or t == b.command.lower()]
        if matches:
            return matches[:1]
        custom = shutil.which(target)
        if custom:
            return [BrowserCandidate(target, custom, ("--new-tab",))]
        print(f"{bui(lang, 'not_found')}: {target}. {bui(lang, 'fallback')}")
        return [None]

    found = detected_browsers()
    if not found:
        return [None]
    print(bui(lang, "detected"))
    for i, b in enumerate(found, start=1):
        print(f"  {i}. {b.label} ({b.command})")
    print(f"  0. {bui(lang, 'default_browser')}")
    if assume_yes:
        return [found[0]]
    raw = input(bui(lang, "choose")).strip().lower() or "0"
    if raw in {"tous", "all", "a", "alle"}:
        return list(found)
    try:
        idx = int(raw)
        if idx == 0:
            return [None]
        if 1 <= idx <= len(found):
            return [found[idx - 1]]
    except ValueError:
        pass
    print(bui(lang, "invalid"))
    return [None]


def _local_test_html(lang: str) -> str:
    t = html_lang(lang)
    return f"""<!doctype html>
<html lang="{normalize_lang(lang)}">
<head>
<meta charset="utf-8">
<title>{t['title']}</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 980px; margin: 2rem auto; line-height: 1.45; }}
 code, pre {{ background:#eee; padding:.15rem .3rem; border-radius:4px; }}
 .ok {{ color:#087f23; font-weight:700; }}
 .warn {{ color:#9a6700; font-weight:700; }}
 .bad {{ color:#b00020; font-weight:700; }}
 table {{ border-collapse: collapse; width:100%; margin-top:1rem; }}
 td, th {{ border:1px solid #ccc; padding:.4rem .55rem; vertical-align: top; }}
 button {{ padding:.5rem .8rem; margin-top:1rem; }}
</style>
</head>
<body>
<h1>{t['h1']}</h1>
<p><b>{t['intro'].split('.')[0]}.</b>{'.'.join(t['intro'].split('.')[1:])}</p>
<table>
<tr><th>{t['element']}</th><th>{t['value']}</th><th>{t['quick']}</th></tr>
<tr><td>{t['rtc']}</td><td id="rtc">?</td><td id="rtc_note">?</td></tr>
<tr><td>{t['dnt']}</td><td id="dnt">?</td><td id="dnt_note">?</td></tr>
<tr><td>{t['gpc']}</td><td id="gpc">?</td><td id="gpc_note">?</td></tr>
<tr><td>{t['langs']}</td><td id="langs">?</td><td>{t['langs_note']}</td></tr>
<tr><td>{t['cookies']}</td><td id="cookies">?</td><td>{t['cookies_note']}</td></tr>
<tr><td>{t['hc']}</td><td id="hc">?</td><td>{t['hc_note']}</td></tr>
<tr><td>{t['dm']}</td><td id="dm">?</td><td>{t['dm_note']}</td></tr>
<tr><td>{t['ua']}</td><td id="ua">?</td><td>{t['ua_note']}</td></tr>
</table>
<button onclick="copyJson()">{t['copy']}</button>
<pre id="json"></pre>
<p><b>{t['webrtc_note']}</b></p>
<script>
const TXT = {{
  rtc_available: {t['rtc_available']!r}, rtc_blocked: {t['rtc_blocked']!r},
  rtc_warn: {t['rtc_warn']!r}, rtc_ok: {t['rtc_ok']!r},
  dnt_ok: {t['dnt_ok']!r}, dnt_warn: {t['dnt_warn']!r},
  gpc_ok: {t['gpc_ok']!r}, gpc_warn: {t['gpc_warn']!r},
  yes: {t['yes']!r}, noexp: {t['noexp']!r}, copied: {t['copied']!r}
}};
const rtc = !!(window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection);
const dnt = navigator.doNotTrack || window.doNotTrack || 'undefined';
const gpc = navigator.globalPrivacyControl === true;
const result = {{
  rtc_api_available: rtc,
  do_not_track: dnt,
  global_privacy_control: gpc,
  languages: navigator.languages || [navigator.language],
  cookies_enabled: navigator.cookieEnabled,
  hardware_concurrency: navigator.hardwareConcurrency || null,
  device_memory: navigator.deviceMemory || null,
  user_agent: navigator.userAgent,
  platform: navigator.platform || null,
  vendor: navigator.vendor || null,
}};
function cls(id, c) {{ document.getElementById(id).className = c; }}
document.getElementById('rtc').textContent = rtc ? TXT.rtc_available : TXT.rtc_blocked;
document.getElementById('rtc_note').textContent = rtc ? TXT.rtc_warn : TXT.rtc_ok;
cls('rtc_note', rtc ? 'warn' : 'ok');
document.getElementById('dnt').textContent = dnt;
document.getElementById('dnt_note').textContent = (dnt == '1' || dnt == 'yes') ? TXT.dnt_ok : TXT.dnt_warn;
cls('dnt_note', (dnt == '1' || dnt == 'yes') ? 'ok' : 'warn');
document.getElementById('gpc').textContent = gpc ? 'true' : 'false';
document.getElementById('gpc_note').textContent = gpc ? TXT.gpc_ok : TXT.gpc_warn;
cls('gpc_note', gpc ? 'ok' : 'warn');
document.getElementById('langs').textContent = result.languages.join(', ');
document.getElementById('cookies').textContent = result.cookies_enabled ? TXT.yes : 'no';
document.getElementById('hc').textContent = result.hardware_concurrency ?? TXT.noexp;
document.getElementById('dm').textContent = result.device_memory ?? TXT.noexp;
document.getElementById('ua').textContent = result.user_agent;
document.getElementById('json').textContent = JSON.stringify(result, null, 2);
async function copyJson() {{
  await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
  alert(TXT.copied);
}}
</script>
</body></html>"""


def run_browser_tests(*, assume_yes: bool = False, target: str | None = None, lang: str = "fr") -> None:
    lang = normalize_lang(lang)
    print(f"\n{bui(lang, 'heading')}")
    print("=" * 30)
    print(bui(lang, "local_desc"))
    print(bui(lang, "external_desc"))
    print(bui(lang, "no_collect"))
    print(bui(lang, "same_instance"))

    if not assume_yes and not _yes(bui(lang, "open_local")):
        print(bui(lang, "ignored"))
        return

    tmp = Path(tempfile.gettempdir()) / f"privacy-index-browser-local-test-{lang}.html"
    tmp.write_text(_local_test_html(lang), encoding="utf-8")
    targets = _select_browsers(target, assume_yes, lang=lang)
    for b in targets:
        label = b.label if b else bui(lang, "default_browser")
        ok = open_with_browser(b, tmp.as_uri(), lang=lang)
        if ok:
            print(bui(lang, "local_opened").format(label=label, path=tmp))

    if not assume_yes and not _yes(bui(lang, "open_external_all")):
        return

    print(f"\n{bui(lang, 'external_one_by_one')}")
                                                                                        
                                                                         
    browser = targets[0] if targets else None
    for label, url in EXTERNAL_TESTS:
        if not assume_yes and not _yes(bui(lang, "open_test").format(label=label)):
            continue
        print(bui(lang, "opening").format(label=label, url=url))
        open_with_browser(browser, url, lang=lang)
