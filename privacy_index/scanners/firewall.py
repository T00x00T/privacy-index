from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from typing import Any

from privacy_index.core.models import Finding, ScanContext, Severity
from privacy_index.core.utils import command_exists, run_cmd


def scan_firewall(ctx: ScanContext) -> None:
    evidence = []
    active = False
    if command_exists("ufw"):
        rc, out, _ = run_cmd(["ufw", "status"], timeout=2)
        if rc == 0:
            evidence.append(out.splitlines()[0] if out else "ufw")
            active = active or "Status: active" in out
    if command_exists("nft"):
                                                                                    
        cmd = ["nft", "list", "ruleset"]
        if _sudo_cached_or_root() and shutil.which("sudo") and os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        rc, out, _ = run_cmd(cmd, timeout=3)
        if rc == 0 and out.strip():
            evidence.append("nftables ruleset présent")
            active = True
    if command_exists("iptables"):
        cmd = ["iptables", "-S"]
        if _sudo_cached_or_root() and shutil.which("sudo") and os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        rc, out, _ = run_cmd(cmd, timeout=3)
        if rc == 0 and len(out.splitlines()) > 3:
            evidence.append("iptables rules présentes")
            active = True

    ctx.add(Finding(
        category="firewall",
        key="firewall.active",
        title="Pare-feu actif ou règles présentes" if active else "Pare-feu non détecté ou règles absentes",
        status=Severity.OK if active else Severity.WARN,
        privacy=0,
        hardening=3 if active else -1,
        evidence="; ".join(evidence) if evidence else "ufw/nft/iptables non actifs ou non lisibles",
        recommendation="Activer au minimum ufw/nftables avec politique entrante restrictive sur un poste client.",
        confidence="medium",
    ))


SENSITIVE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 445: "smb", 631: "cups",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "dev-http",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

LAN_DISCOVERY_PORTS = {
    5353: "mDNS",
    1900: "SSDP/UPnP",
    3702: "WS-Discovery",
    67: "DHCP",
    68: "DHCP",
    546: "DHCPv6",
    547: "DHCPv6",
}

VPN_OR_TUNNEL_PROCESSES = {
    "nordvpnd", "nordvpn", "mullvad-daemon", "mullvad", "openvpn", "openvpn3",
    "wg-quick", "wireguard-go", "tailscaled", "xray", "v2ray", "sing-box",
    "amnezia", "amneziawg", "awg-quick", "nym-vpnd", "nymvpn", "protonvpn",
    "protonvpn-app", "protonvpn-cli", "expressvpn", "surfshark", "ivpn", "windscribe",
}

BROWSER_OR_USER_PROCESSES = {
    "chromium", "chrome", "brave", "brave-browser", "firefox", "librewolf",
    "mullvad-browser", "tor-browser", "python3", "python",
}


def _sudo_cached_or_root() -> bool:
    if os.geteuid() == 0:
        return True
    if not shutil.which("sudo"):
        return False
    try:
        proc = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _run_ss() -> tuple[str, str]:
    base = ["ss", "-H", "-tulpn"]
    if os.geteuid() == 0:
        rc, out, _ = run_cmd(base, timeout=4)
        return (out if rc == 0 else "", "root")
    if shutil.which("sudo") and _sudo_cached_or_root():
        rc, out, _ = run_cmd(["sudo", "-n"] + base, timeout=4)
        if rc == 0 and out.strip():
            return out, "sudo"
    rc, out, _ = run_cmd(base, timeout=4)
    return (out if rc == 0 else "", "user")


def _process_names(line: str) -> list[str]:
                                                                   
    names = re.findall(r'"([^"/]+)",pid=', line or "")
    return list(dict.fromkeys(names))


def _cgroup_path(line: str) -> str:
    m = re.search(r"\bcgroup:([^\s]+)", line or "")
    return m.group(1) if m else ""


def _process_from_cgroup(path: str) -> str:
                                                             
    if not path:
        return ""
    base = path.rstrip("/").split("/")[-1]
    if base.endswith(".service"):
        return base[:-8]
    if base.endswith(".scope"):
        return base[:-6]
                                                                
    if base.startswith("user@"):
        return ""
    return base


def _extract_local(parts: list[str]) -> str:
    if len(parts) >= 5:
        return parts[4]
                                                                                                    
    for tok in parts:
        if re.search(r":\d+$", tok) and not tok.endswith(":*"):
            return tok
    return ""


def _split_addr_port(local: str) -> tuple[str, int] | None:
                                                             
    m = re.search(r":(\d+)$", local)
    if not m:
        return None
    port = int(m.group(1))
    addr = local[: local.rfind(":")]
    return addr, port


def _is_local_only(addr: str) -> bool:
    a = addr.strip("[]")
    return a.startswith("127.") or a == "::1" or a == "localhost"


def _is_wildcard(addr: str) -> bool:
    a = addr.strip("[]")
    return a in {"0.0.0.0", "::", "*", ""}


def _is_multicast(addr: str) -> bool:
    a = addr.strip("[]")
    if a.startswith("239.") or a.startswith("224."):
        return True
    return a.lower().startswith("ff")


def _service_name(port: int, proto: str) -> str:
    if port in SENSITIVE_PORTS:
        return SENSITIVE_PORTS[port]
    if port in LAN_DISCOVERY_PORTS:
        return LAN_DISCOVERY_PORTS[port]
    try:
        return socket.getservbyport(port, "udp" if proto.startswith("udp") else "tcp")
    except Exception:
        return "dynamic/unknown"


def _extract_listener(line: str) -> dict[str, Any] | None:
    parts = line.split()
    if len(parts) < 5:
        return None
    proto = parts[0].lower()
    local = _extract_local(parts)
    if not local:
        return None
    split = _split_addr_port(local)
    if not split:
        return None
    addr, port = split
    processes = _process_names(line)
    cg = _cgroup_path(line)
    cg_proc = _process_from_cgroup(cg)
    if not processes and cg_proc:
        processes = [cg_proc]
    process = "/".join(processes) if processes else "unknown"
    return {
        "proto": proto,
        "local": local,
        "addr": addr,
        "port": int(port),
        "processes": processes,
        "process": process,
        "cgroup": cg,
        "service": _service_name(int(port), proto),
        "local_only": _is_local_only(addr),
        "wildcard": _is_wildcard(addr),
        "multicast": _is_multicast(addr),
    }


def _run_ss_probe(proto: str) -> tuple[str, str]:
    p = "udp" if str(proto).startswith("udp") else "tcp"
    flags = ["-u"] if p == "udp" else ["-t"]
    commands = [
        ["ss", "-H", *flags, "-a", "-n", "-p", "-e"],
        ["ss", "-H", *flags, "-l", "-n", "-p", "-e"],
    ]
    output_parts = []
    mode = "user"
    for cmd in commands:
        run = cmd
        if os.geteuid() == 0:
            mode = "root"
        elif shutil.which("sudo") and _sudo_cached_or_root():
            run = ["sudo", "-n"] + cmd
            mode = "sudo"
        rc, out, _ = run_cmd(run, timeout=4)
        if rc == 0 and out.strip():
            output_parts.append(out)
    return "\n".join(output_parts), mode


def _extract_probe_listener(line: str, proto_hint: str, port_hint: int | None = None) -> dict[str, Any] | None:
                                                                           
                                                                            
                                                                         
    parts = line.split()
    local = ""
    for tok in parts:
        if re.search(r":\d+$", tok) and not tok.endswith(":*"):
            if port_hint is None or tok.endswith(f":{port_hint}"):
                local = tok
                break
    if not local:
        return None
    split = _split_addr_port(local)
    if not split:
        return None
    addr, port = split
    processes = _process_names(line)
    cg = _cgroup_path(line)
    cg_proc = _process_from_cgroup(cg)
    if not processes and cg_proc:
        processes = [cg_proc]
    process = "/".join(processes) if processes else "unknown"
    return {
        "proto": "udp" if str(proto_hint).startswith("udp") else "tcp",
        "local": local,
        "addr": addr,
        "port": int(port),
        "processes": processes,
        "process": process,
        "cgroup": cg,
        "service": _service_name(int(port), proto_hint),
        "local_only": _is_local_only(addr),
        "wildcard": _is_wildcard(addr),
        "multicast": _is_multicast(addr),
        "probe_line": line.strip(),
    }


def _enrich_unresolved_listeners(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, str]:
    unresolved = [x for x in items if x.get("process") == "unknown" and x.get("class") == "review"]
    if not unresolved:
        return items, 0, "not-needed"

    enriched = 0
    mode_seen = "not-run"
    by_key = {(x["proto"], x["local"], int(x["port"])): x for x in items}
    for x in unresolved:
        out, mode = _run_ss_probe(str(x["proto"]))
        mode_seen = mode
        for line in out.splitlines():
            candidate = _extract_probe_listener(line, str(x["proto"]), int(x["port"]))
            if not candidate:
                continue
            if candidate.get("local") != x.get("local"):
                                                                                 
                continue
            if candidate.get("process") and candidate["process"] != "unknown":
                key = (x["proto"], x["local"], int(x["port"]))
                target = by_key.get(key, x)
                target.update({
                    "processes": candidate.get("processes", []),
                    "process": candidate.get("process", "unknown"),
                    "cgroup": candidate.get("cgroup", ""),
                    "probe_source": "ss -a/-l -e cgroup",
                })
                target["class"] = _classify(target)
                enriched += 1
                break
    return items, enriched, mode_seen


def investigate_port(port: int, proto: str = "udp") -> str:
    out, mode = _run_ss_probe(proto)
    rows = []
    for line in out.splitlines():
        item = _extract_probe_listener(line, proto, int(port))
        if item:
            item["class"] = _classify(item)
            rows.append(item)
    rows = _dedupe(rows)
    if not rows:
        return f"No {proto.upper()} socket found for port {port} with extended ss probe. source=ss -a/-l -n -p -e; privilege={mode}"
    return f"{_table(rows, limit=30)}\nsource=ss -a/-l -n -p -e; privilege={mode}"


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for x in items:
        key = (x["proto"], x["local"], int(x["port"]), x["process"])
        out[key] = x
    return sorted(out.values(), key=lambda x: (str(x["class"]), str(x["proto"]), int(x["port"]), str(x["local"])))


def _classify(x: dict[str, Any]) -> str:
    proc_names = set(x.get("processes") or [])
    port = int(x["port"])
    proto = str(x["proto"])
    if x.get("local_only"):
        return "local-only"
    if proc_names & VPN_OR_TUNNEL_PROCESSES:
        return "vpn/tunnel"
    if port in LAN_DISCOVERY_PORTS or x.get("multicast"):
        return "lan/discovery"
    if port in SENSITIVE_PORTS:
        return "sensitive"
    if proto.startswith("udp") and port >= 32768 and proc_names & BROWSER_OR_USER_PROCESSES:
        return "client/dynamic"
    return "review"


def _risk_label(x: dict[str, Any]) -> str:
                                                                                   
                             
    c = str(x.get("class", "review"))
    if c == "sensitive":
        return "sensitive"
    if c == "review":
        return "review"
    if c == "vpn/tunnel":
        return "vpn/tunnel"
    if c == "lan/discovery":
        return "lan"
    if c == "local-only":
        return "local"
    if c == "client/dynamic":
        return "client"
    return c


def _table(items: list[dict[str, Any]], *, limit: int = 18) -> str:
    rows = []
    for x in items[:limit]:
        rows.append([
            str(x["proto"]),
            str(x["local"]),
            str(x.get("process") or "unknown"),
            str(x.get("service") or "dynamic/unknown"),
            _risk_label(x),
        ])
    if not rows:
        return "none"
    headers = ["proto", "listen", "process", "service", "class"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(cell)), 34)

    def cut(s: str, w: int) -> str:
        return s if len(s) <= w else s[: max(0, w - 1)] + "…"

    lines = []
    lines.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    lines.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        lines.append("  ".join(cut(row[i], widths[i]).ljust(widths[i]) for i in range(len(headers))))
    if len(items) > limit:
        lines.append(f"... +{len(items) - limit} more")
    return "\n".join(lines)


def _all_network_visible(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [x for x in items if x["class"] != "local-only"]


def scan_listening_services(ctx: ScanContext) -> None:
    out, privilege_mode = _run_ss()
    if not out.strip():
        ctx.add(Finding(
            category="firewall",
            key="services.listen.unknown",
            title="Services exposés non vérifiables",
            status=Severity.UNKNOWN,
            evidence="ss indisponible ou erreur",
            recommendation="Installer iproute2 ou lancer ss -tulpn manuellement.",
            confidence="low",
        ))
        return

    listeners = []
    for line in out.splitlines():
        item = _extract_listener(line)
        if item:
            item["class"] = _classify(item)
            listeners.append(item)
    listeners = _dedupe(listeners)
    listeners, enriched_count, enrich_mode = _enrich_unresolved_listeners(listeners)
    listeners = _dedupe(listeners)

    local_only = [x for x in listeners if x["class"] == "local-only"]
    sensitive = [x for x in listeners if x["class"] == "sensitive"]
    review = [x for x in listeners if x["class"] == "review"]
    client_udp = [x for x in listeners if x["class"] == "client/dynamic"]
    lan = [x for x in listeners if x["class"] == "lan/discovery"]
    vpn = [x for x in listeners if x["class"] == "vpn/tunnel"]
    visible = _all_network_visible(listeners)

    ctx.fact("firewall.listening_ports", {
        "privilege_mode": privilege_mode,
        "all_network_visible": visible,
        "local_only_count": len(local_only),
        "sensitive_count": len(sensitive),
        "review_count": len(review),
        "lan_discovery_count": len(lan),
        "vpn_tunnel_count": len(vpn),
        "client_dynamic_count": len(client_udp),
        "enriched_unknown_count": enriched_count,
        "enrichment_privilege_mode": enrich_mode,
    })

    enrich_txt = f"; unresolved-probe=ss -a/-l -e; enriched={enriched_count}; probe-privilege={enrich_mode}" if enriched_count else ""
    mode_txt = f"source=ss -tulpn; privilege={privilege_mode}{enrich_txt}"

    if sensitive:
        ctx.add(Finding(
            category="firewall",
            key="services.exposed",
            title="Ports sensibles en écoute sur le réseau",
            status=Severity.BAD,
            privacy=-1,
            hardening=-3,
            evidence=f"{_table(sensitive)}\n{mode_txt}",
            recommendation="Désactiver les services non sollicités, les lier à 127.0.0.1, ou limiter strictement par pare-feu aux machines autorisées.",
            confidence="high",
        ))
    elif review:
        ctx.add(Finding(
            category="firewall",
            key="services.open_ports_review",
            title="Ports ouverts à vérifier",
            status=Severity.WARN,
            privacy=0,
            hardening=-1,
            evidence=f"{_table(review)}\n{mode_txt}",
            recommendation="Vérifier que chaque ligne correspond à une application volontairement utilisée. Si ce n'est pas le cas: désactiver le service ou filtrer par pare-feu.",
            confidence="high",
        ))
    else:
        ctx.add(Finding(
            category="firewall",
            key="services.no_risky_exposed",
            title="Aucun port réseau sensible ou inattendu évident",
            status=Severity.OK,
            privacy=1,
            hardening=2,
            evidence=(
                f"network-visible={len(visible)}, local-only={len(local_only)}, "
                f"lan/discovery={len(lan)}, vpn/tunnel={len(vpn)}, client/dynamic={len(client_udp)}; {mode_txt}"
            ),
            recommendation="Continuer à vérifier après installation de nouveaux services: ss -tulpn.",
            confidence="medium",
        ))

    if vpn:
        ctx.add(Finding(
            category="firewall",
            key="services.vpn_owned_udp",
            title="Sockets VPN ou tunnel détectés",
            status=Severity.INFO,
            privacy=0,
            hardening=0,
            evidence=f"{_table(vpn)}\n{mode_txt}",
            recommendation="Ces sockets appartiennent à un client VPN/tunnel connu. Vérifier surtout que le processus correspond bien au VPN attendu.",
            confidence="high" if privilege_mode in {"sudo", "root"} else "medium",
        ))

    if lan:
        ctx.add(Finding(
            category="firewall",
            key="services.lan_discovery",
            title="Services LAN ou découverte locale détectés",
            status=Severity.INFO,
            privacy=0,
            hardening=0,
            evidence=f"{_table(lan)}\n{mode_txt}",
            recommendation="mDNS/SSDP/WS-Discovery/DHCP sont courants sur un poste client. Les désactiver seulement si le profil recherché est très discret sur le LAN.",
            confidence="high",
        ))

    if client_udp:
        ctx.add(Finding(
            category="firewall",
            key="services.client_udp",
            title="Sockets UDP client ou dynamiques détectés",
            status=Severity.INFO,
            privacy=0,
            hardening=0,
            evidence=f"{_table(client_udp)}\n{mode_txt}",
            recommendation="Ces ports UDP élevés sont souvent temporaires. Ils ne sont pas notés négativement sauf s'ils correspondent à un service inattendu.",
            confidence="medium",
        ))


def scan(ctx: ScanContext) -> None:
    scan_firewall(ctx)
    scan_listening_services(ctx)
