from __future__ import annotations

from privacy_index.core.models import Finding, ScanContext, Severity
from privacy_index.core.utils import command_exists, run_cmd, desktop_app_exists

MESSAGING = {
    "signal-desktop": "Signal",
    "session-desktop": "Session",
    "element-desktop": "Element",
    "ricochet-refresh": "Ricochet Refresh",
    "telegram-desktop": "Telegram",
    "thunderbird": "Thunderbird",
}
ENCRYPTION = {
    "veracrypt": "VeraCrypt",
    "zulucrypt-gui": "ZuluCrypt",
    "zulucrypt-cli": "ZuluCrypt",
    "cryptsetup": "cryptsetup/LUKS",
    "gpg": "GnuPG",
    "age": "age",
}
PASSWORDS = {
    "keepassxc": "KeePassXC",
    "pass": "pass",
    "bitwarden": "Bitwarden",
}
SANDBOX = {
    "firejail": "Firejail",
    "flatpak": "Flatpak",
    "bwrap": "Bubblewrap",
}

DESKTOP_NEEDLES = {
    "Signal": ["signal-desktop", "signal"],
    "Session": ["session-desktop", "session"],
    "Element": ["element-desktop", "element"],
    "Ricochet Refresh": ["ricochet-refresh", "ricochet"],
    "Telegram": ["telegram-desktop", "telegram"],
    "Thunderbird": ["thunderbird"],
    "VeraCrypt": ["veracrypt"],
    "ZuluCrypt": ["zulucrypt"],
    "cryptsetup/LUKS": ["cryptsetup"],
    "GnuPG": ["gpg", "gnupg"],
    "age": ["age"],
    "KeePassXC": ["keepassxc", "keepassxc.desktop", "org.keepassxc.keepassxc"],
    "pass": ["pass"],
    "Bitwarden": ["bitwarden", "com.bitwarden.desktop"],
    "Firejail": ["firejail"],
    "Flatpak": ["flatpak"],
    "Bubblewrap": ["bwrap", "bubblewrap"],
}

                                                                                
                                                                                  
DESKTOP_ENABLED_LABELS = {
    "Signal", "Session", "Element", "Ricochet Refresh", "Telegram", "Thunderbird",
    "VeraCrypt", "ZuluCrypt", "KeePassXC", "Bitwarden", "Firejail"
}


def _flatpak_contains(labels: list[str]) -> list[str]:
    rc, out, _ = run_cmd(["flatpak", "list", "--app", "--columns=name,application"], timeout=3)
    if rc != 0:
        return []
    lower = out.lower()
    return [n for n in labels if n.lower() in lower or any(x in lower for x in DESKTOP_NEEDLES.get(n, []))]


def _detect(mapping: dict[str, str]) -> tuple[list[str], list[str]]:
    found: set[str] = set()
    sources: list[str] = []
    for cmd, label in mapping.items():
        if command_exists(cmd):
            found.add(label)
            sources.append(f"{label}:PATH")
    for label in mapping.values():
        if label in DESKTOP_ENABLED_LABELS and desktop_app_exists(*DESKTOP_NEEDLES.get(label, [label])):
            found.add(label)
            sources.append(f"{label}:.desktop")
    for label in _flatpak_contains(list(mapping.values())):
        found.add(label)
        sources.append(f"{label}:flatpak")
    return sorted(found), sorted(set(sources))


def scan(ctx: ScanContext) -> None:
    msg, msg_sources = _detect(MESSAGING)
    ctx.fact("apps.messaging", msg)
    ctx.fact("apps.messaging.sources", msg_sources)
    secure = [m for m in msg if m in {"Signal", "Session", "Element", "Ricochet Refresh"}]
    telegram_only = msg == ["Telegram"]
    if secure:
        ctx.add(Finding(
            category="apps",
            key="messaging.secure",
            title="Messagerie chiffrée/privée détectée",
            status=Severity.OK,
            privacy=1,
            anonymity=1 if any(m in secure for m in ["Session", "Ricochet Refresh"]) else 0,
            evidence=", ".join(msg_sources or msg),
            recommendation="Vérifier les réglages: sauvegardes cloud, contacts, identifiant téléphone, notifications.",
            confidence="medium",
        ))
    elif telegram_only:
        ctx.add(Finding(
            category="apps",
            key="messaging.telegram_only",
            title="Telegram détecté seul",
            status=Severity.WARN,
            privacy=0,
            anonymity=-1,
            evidence=", ".join(msg_sources or msg),
            recommendation="Telegram n'est pas équivalent à Signal/Session par défaut. Les chats cloud ne sont pas E2EE.",
            confidence="medium",
        ))
    else:
        ctx.add(Finding(
            category="apps",
            key="messaging.none",
            title="Aucune messagerie privée courante détectée",
            status=Severity.INFO,
            privacy=0,
            evidence=", ".join(msg_sources or msg) if msg else "aucune",
            recommendation="Installer Signal, Session ou Element selon l'usage.",
            confidence="medium",
        ))

    enc, enc_sources = _detect(ENCRYPTION)
    ctx.fact("apps.encryption", enc)
    ctx.fact("apps.encryption.sources", enc_sources)
    ctx.add(Finding(
        category="apps",
        key="encryption.tools",
        title="Outils de chiffrement présents" if enc else "Aucun outil de chiffrement courant détecté",
        status=Severity.OK if enc else Severity.WARN,
        privacy=1 if enc else 0,
        hardening=1 if enc else 0,
        evidence=", ".join(enc_sources or enc) if enc else "veracrypt/zulucrypt/cryptsetup/gpg/age absents du PATH et des lanceurs .desktop",
        recommendation="VeraCrypt pour conteneurs multi-OS; LUKS/cryptsetup pour Linux système; age/GPG pour fichiers.",
        confidence="medium",
    ))

    pw, pw_sources = _detect(PASSWORDS)
    ctx.fact("apps.password_managers", pw)
    ctx.fact("apps.password_managers.sources", pw_sources)
    ctx.add(Finding(
        category="apps",
        key="password.manager",
        title="Gestionnaire de mots de passe détecté" if pw else "Aucun gestionnaire de mots de passe local détecté",
        status=Severity.OK if pw else Severity.WARN,
        privacy=1 if pw else 0,
        hardening=1 if pw else 0,
        evidence=", ".join(pw_sources or pw) if pw else "keepassxc/pass/bitwarden absents du PATH, des lanceurs .desktop et de Flatpak",
        recommendation="KeePassXC ou pass sont de bons choix locaux; Bitwarden dépend du modèle de confiance serveur. Une installation non exposée dans le PATH est acceptable si le lanceur .desktop existe.",
        confidence="high" if pw else "medium",
    ))

    sandbox, sandbox_sources = _detect(SANDBOX)
    ctx.fact("apps.sandbox", sandbox)
    ctx.fact("apps.sandbox.sources", sandbox_sources)
    if sandbox:
        ctx.add(Finding(
            category="apps",
            key="sandbox.tools",
            title="Outils de sandboxing/cloisonnement détectés",
            status=Severity.OK,
            privacy=1,
            hardening=1,
            evidence=", ".join(sandbox_sources or sandbox),
            recommendation="Vérifier les permissions Flatpak avec Flatseal ou flatpak permission-show.",
            confidence="medium",
        ))
