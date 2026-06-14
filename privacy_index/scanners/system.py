from __future__ import annotations

from pathlib import Path
import getpass
import pwd
from privacy_index.core.models import Finding, ScanContext, Severity
from privacy_index.core.utils import command_exists, parse_os_release, run_cmd


def scan(ctx: ScanContext) -> None:
    osr = parse_os_release()
    ctx.os_id = osr.get("ID", "unknown")
    ctx.os_like = osr.get("ID_LIKE", "")
    ctx.distro_pretty_name = osr.get("PRETTY_NAME", ctx.os_id)

    if command_exists("apt") or command_exists("dpkg"):
        ctx.package_manager = "apt/dpkg"
    elif command_exists("pacman"):
        ctx.package_manager = "pacman"
    elif command_exists("dnf"):
        ctx.package_manager = "dnf"
    else:
        ctx.package_manager = "unknown"

    ctx.fact("os.id", ctx.os_id)
    ctx.fact("os.like", ctx.os_like)
    ctx.fact("os.package_manager", ctx.package_manager)

                                                                                
                                                                              
    important_commands = ["ip", "ss", "lsblk", "findmnt", "swapon", "systemctl", "resolvectl"]
    missing_commands = [c for c in important_commands if not command_exists(c)]
    ctx.fact("system.missing_commands", missing_commands)
    if missing_commands:
        ctx.add(Finding(
            category="system",
            key="scanner.commands_missing",
            title="Commandes système utiles absentes",
            status=Severity.INFO,
            privacy=0,
            hardening=0,
            evidence=", ".join(missing_commands),
            recommendation="L'application continue sans planter, mais certains tests deviennent moins précis. Sur Debian/Ubuntu, iproute2 fournit souvent ip/ss; util-linux fournit lsblk/findmnt/swapon.",
            confidence="high",
        ))

    linux_like = Path("/proc/version").exists()
    ctx.add(Finding(
        category="system",
        key="os.linux",
        title="Système Linux détecté" if linux_like else "Système non Linux ou non reconnu",
        status=Severity.OK if linux_like else Severity.UNKNOWN,
        privacy=2 if linux_like else 0,
        hardening=1 if linux_like else 0,
        evidence=ctx.distro_pretty_name,
        recommendation="Linux facilite l'audit local et le durcissement, mais ne suffit pas sans chiffrement, mises à jour et navigateur propre.",
        confidence="high" if linux_like else "low",
    ))

                                                                     
    if ctx.package_manager == "apt/dpkg":
        apt_periodic = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        has_unattended = apt_periodic.exists() or command_exists("unattended-upgrade")
        rc, out, _ = run_cmd(["apt", "list", "--upgradable"], timeout=5)
        upgradable_names: list[str] = []
        if rc == 0:
            for line in out.splitlines():
                if "/" in line and not line.lower().startswith("listing"):
                    upgradable_names.append(line.split("/", 1)[0].strip())
        upgradable_count = len(upgradable_names) if rc == 0 else -1

        rc_hold, hold_out, _ = run_cmd(["apt-mark", "showhold"], timeout=3)
        held = sorted({x.strip() for x in hold_out.splitlines() if x.strip()}) if rc_hold == 0 else []
        held_upgradable = sorted(set(upgradable_names) & set(held))
        effective_upgradable = max(0, upgradable_count - len(held_upgradable)) if upgradable_count >= 0 else -1
        ctx.fact("updates.apt_upgradable", upgradable_names[:200])
        ctx.fact("updates.apt_held", held)
        ctx.fact("updates.apt_held_upgradable", held_upgradable)

        if has_unattended:
            status = Severity.OK
            title = "Mises à jour automatiques probablement activées"
            hard = 2
        elif upgradable_count == 0:
            status = Severity.OK
            title = "Aucun paquet clairement en attente de mise à jour"
            hard = 2
        elif effective_upgradable == 0 and held_upgradable:
            status = Severity.INFO
            title = f"Paquets en attente uniquement parce qu'ils sont en hold: {len(held_upgradable)}"
            hard = 1
        elif effective_upgradable > 0:
            status = Severity.WARN
            title = f"Paquets à mettre à jour détectés: {effective_upgradable}"
            hard = 0
        else:
            status = Severity.UNKNOWN
            title = "État des mises à jour non vérifiable"
            hard = 0
        evidence = (
            f"unattended-upgrades={'oui' if has_unattended else 'non'}, "
            f"upgradable={upgradable_count if upgradable_count >= 0 else 'inconnu'}, "
            f"held={len(held)}, held_upgradable={len(held_upgradable)}, "
            f"effective_upgradable={effective_upgradable if effective_upgradable >= 0 else 'inconnu'}"
        )
    elif ctx.package_manager == "pacman":
        rc, out, _ = run_cmd(["checkupdates"], timeout=5)
        count = len(out.splitlines()) if out else 0
        status = Severity.OK if count == 0 else Severity.WARN
        title = "Aucun paquet Arch en attente" if count == 0 else f"Paquets Arch à mettre à jour détectés: {count}"
        evidence = "checkupdates" if rc in (0, 2) else "checkupdates indisponible"
        hard = 1 if count == 0 else 0
    else:
        status = Severity.UNKNOWN
        title = "Gestion des mises à jour non évaluée"
        evidence = ctx.package_manager
        hard = 0

    ctx.add(Finding(
        category="system",
        key="updates.status",
        title=title,
        status=status,
        hardening=hard,
        evidence=evidence,
        recommendation="Garder le système à jour. Sur Debian/Ubuntu: unattended-upgrades peut réduire le risque d'oubli.",
        confidence="medium",
    ))

                                                                              
    home = Path.home()
    try:
        mode = home.stat().st_mode & 0o777
        too_open = bool(mode & 0o077)
        current_names = {getpass.getuser()}
        try:
            owner = pwd.getpwuid(home.stat().st_uid).pw_name
            current_names.add(owner)
        except Exception:
            pass
        real_users = []
        for u in pwd.getpwall():
            if u.pw_uid >= 1000 and u.pw_name not in current_names | {"nobody"} and u.pw_shell not in {"/usr/sbin/nologin", "/bin/false"}:
                real_users.append(u.pw_name)
        ctx.fact("system.other_real_users", real_users)
        if too_open and real_users:
            title = "Dossier personnel lisible par d'autres utilisateurs locaux"
            status = Severity.WARN
            privacy = hardening = -1
            rec = "chmod 700 $HOME est recommandé si plusieurs comptes humains existent sur la machine."
        elif too_open and not real_users:
            title = "Dossier personnel ouvert, mais aucun autre utilisateur humain détecté"
            status = Severity.INFO
            privacy = 0
            hardening = 0
            rec = "Risque faible en poste mono-utilisateur. chmod 700 $HOME reste plus propre si tu veux une posture stricte."
        else:
            title = "Permissions du dossier personnel correctes"
            status = Severity.OK
            privacy = hardening = 1
            rec = "OK."
        ctx.add(Finding(
            category="system",
            key="home.permissions",
            title=title,
            status=status,
            privacy=privacy,
            hardening=hardening,
            evidence=f"{home} mode {oct(mode)}; autres_utilisateurs={real_users or 'aucun'}",
            recommendation=rec,
            confidence="high",
        ))
    except Exception:
        pass
