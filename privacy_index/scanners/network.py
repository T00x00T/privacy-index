from __future__ import annotations

import ipaddress
import json
import re
from importlib import resources
from pathlib import Path
from privacy_index.core.models import Finding, ScanContext, Severity
from privacy_index.core.utils import command_exists, run_cmd, read_text_safe, desktop_app_exists

VPN_IFACE_PATTERNS = ("tun", "tap", "wg", "awg", "amnezia", "nordlynx", "proton", "mullvad", "ivpn", "nym", "nymvpn", "tailscale", "zt")

                                                                               
                                                                                 
                                                                             
                                                  
DNS_PROVIDER_DB = {
                                          
    "9.9.9.9": {"name": "Quad9", "class": "privacy_public"},
    "149.112.112.112": {"name": "Quad9", "class": "privacy_public"},
    "2620:fe::fe": {"name": "Quad9", "class": "privacy_public"},
    "2620:fe::9": {"name": "Quad9", "class": "privacy_public"},
    "194.242.2.2": {"name": "Mullvad DNS", "class": "privacy_public_vpn"},
    "2a07:e340::2": {"name": "Mullvad DNS", "class": "privacy_public_vpn"},
    "94.140.14.14": {"name": "AdGuard DNS", "class": "privacy_filtering"},
    "94.140.15.15": {"name": "AdGuard DNS", "class": "privacy_filtering"},
    "94.140.14.15": {"name": "AdGuard DNS Family", "class": "privacy_filtering"},
    "94.140.15.16": {"name": "AdGuard DNS Family", "class": "privacy_filtering"},
    "94.140.14.140": {"name": "AdGuard DNS non-filtering", "class": "privacy_public"},
    "94.140.15.140": {"name": "AdGuard DNS non-filtering", "class": "privacy_public"},
    "45.90.28.0": {"name": "NextDNS", "class": "privacy_configurable"},
    "45.90.30.0": {"name": "NextDNS", "class": "privacy_configurable"},
    "2a07:a8c0::": {"name": "NextDNS", "class": "privacy_configurable"},
    "2a07:a8c1::": {"name": "NextDNS", "class": "privacy_configurable"},
    "86.54.11.1": {"name": "DNS4EU", "class": "privacy_public"},
    "86.54.11.100": {"name": "DNS4EU", "class": "privacy_public"},

                                                                      
    "1.1.1.1": {"name": "Cloudflare", "class": "mixed_public"},
    "1.0.0.1": {"name": "Cloudflare", "class": "mixed_public"},
    "2606:4700:4700::1111": {"name": "Cloudflare", "class": "mixed_public"},
    "2606:4700:4700::1001": {"name": "Cloudflare", "class": "mixed_public"},
    "208.67.222.222": {"name": "OpenDNS/Cisco", "class": "mixed_public"},
    "208.67.220.220": {"name": "OpenDNS/Cisco", "class": "mixed_public"},
    "2620:119:35::35": {"name": "OpenDNS/Cisco", "class": "mixed_public"},
    "2620:119:53::53": {"name": "OpenDNS/Cisco", "class": "mixed_public"},

                                              
    "8.8.8.8": {"name": "Google Public DNS", "class": "avoid_public"},
    "8.8.4.4": {"name": "Google Public DNS", "class": "avoid_public"},
    "2001:4860:4860::8888": {"name": "Google Public DNS", "class": "avoid_public"},
    "2001:4860:4860::8844": {"name": "Google Public DNS", "class": "avoid_public"},

                                         
    "193.110.81.0": {"name": "dns0.eu discontinued", "class": "deprecated"},
    "185.253.5.0": {"name": "dns0.eu discontinued", "class": "deprecated"},

                                       
    "103.86.96.100": {"name": "NordVPN DNS", "class": "vpn_provider_dns"},
    "103.86.99.100": {"name": "NordVPN DNS", "class": "vpn_provider_dns"},
    "172.16.0.1": {"name": "IVPN WireGuard DNS", "class": "vpn_provider_dns"},
    "10.0.254.1": {"name": "IVPN OpenVPN DNS", "class": "vpn_provider_dns"},
}

VPN_DNS_PRIVATE_RANGES = [
    (ipaddress.ip_network("10.255.255.0/24"), "Windscribe internal DNS", "vpn_provider_dns"),
]
DNS_INTERFACE_HINTS: dict[str, str] = {}
DNS_DB_META: dict[str, object] = {}


def _load_dns_database() -> tuple[dict[str, dict[str, str]], list[tuple[ipaddress._BaseNetwork, str, str]], dict[str, str], dict[str, object]]:
    try:
        text = resources.files("privacy_index.data").joinpath("dns_providers.json").read_text(encoding="utf-8")
        data = json.loads(text)
    except Exception:
        return DNS_PROVIDER_DB, VPN_DNS_PRIVATE_RANGES, {}, {}

    def canon(raw: str) -> str | None:
        try:
            return str(ipaddress.ip_address(str(raw).strip().strip("[]"))).lower()
        except Exception:
            return None

    exact: dict[str, dict[str, str]] = {}
    for raw_ip, meta in (data.get("exact") or {}).items():
        ip = canon(raw_ip)
        if not ip or not isinstance(meta, dict):
            continue
        exact[ip] = {
            "name": str(meta.get("name") or "unknown"),
            "class": str(meta.get("class") or "unknown"),
        }

    ranges: list[tuple[ipaddress._BaseNetwork, str, str]] = []
    for item in (data.get("private_ranges") or []):
        if not isinstance(item, dict):
            continue
        try:
            net = ipaddress.ip_network(str(item.get("cidr")), strict=False)
        except Exception:
            continue
        ranges.append((net, str(item.get("name") or "private/VPN/local DNS"), str(item.get("class") or "vpn_or_private")))

    hints = {str(k).lower(): str(v) for k, v in (data.get("interface_hints") or {}).items()}
    return (exact or DNS_PROVIDER_DB), (ranges or VPN_DNS_PRIVATE_RANGES), hints, data


                                                                                    
DNS_PROVIDER_DB, VPN_DNS_PRIVATE_RANGES, DNS_INTERFACE_HINTS, DNS_DB_META = _load_dns_database()


def _ip_links() -> list[str]:
    rc, out, _ = run_cmd(["ip", "-o", "link", "show", "up"], timeout=2)
    if rc != 0:
        return []
    names = []
    for line in out.splitlines():
        m = re.match(r"\d+:\s+([^:@]+)", line)
        if m:
            names.append(m.group(1))
    return names


def _canonical_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]"))).lower()
    except Exception:
        return None


def _dns_entries() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []

    rc, out, err = run_cmd(["resolvectl", "dns"], timeout=2)
    if rc == 0 and out:
        current_link = "global"
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            m = re.match(r"Link\s+\d+\s+\(([^)]+)\):\s*(.*)$", stripped)
            if m:
                current_link = m.group(1)
                rest = m.group(2)
            elif stripped.startswith("Global:"):
                current_link = "global"
                rest = stripped.split(":", 1)[1]
            else:
                rest = stripped
            for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+", rest):
                ip = _canonical_ip(token)
                if ip:
                    entries.append({"ip": ip, "source": "resolvectl", "link": current_link})
    else:
                                                                                                         
        if rc == 127:
            entries.append({"ip": "", "source": "resolvectl-missing", "link": ""})

    text = read_text_safe(Path("/etc/resolv.conf"))
    for line in text.splitlines():
        if line.strip().startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                ip = _canonical_ip(parts[1])
                if ip:
                    entries.append({"ip": ip, "source": "/etc/resolv.conf", "link": "resolv.conf"})

                                                                
    out_entries: dict[str, dict[str, str]] = {}
    for e in entries:
        ip = e.get("ip") or ""
        if not ip:
            continue
        if ip not in out_entries:
            out_entries[ip] = e
        else:
            prev = out_entries[ip]
            if e.get("link") and e.get("link") not in {"resolv.conf", prev.get("link", "")}:
                prev["link"] = e["link"]
            if e.get("source") and e.get("source") not in prev.get("source", ""):
                prev["source"] = prev.get("source", "") + "+" + e["source"]
    return list(out_entries.values())


def _dns_servers() -> list[str]:
    return [e["ip"] for e in _dns_entries()]


def _vpn_dns_range_name(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return ""
    for net, name, _cls in VPN_DNS_PRIVATE_RANGES:
        if obj in net:
            return name
                                                                                 
                                                                                
    if obj.is_private and not obj.is_loopback:
        return "private/VPN/local DNS"
    return ""


def _vpn_like_links(ifaces: list[str]) -> set[str]:
    return {i for i in ifaces if i.lower().startswith(VPN_IFACE_PATTERNS) or any(p in i.lower() for p in VPN_IFACE_PATTERNS)}


def _dns_provider_from_interface(link: str) -> str:
    low = (link or "").lower()
    for needle, label in DNS_INTERFACE_HINTS.items():
        if needle and needle in low:
            return label
    if any(p in low for p in VPN_IFACE_PATTERNS):
        return "VPN internal DNS"
    return ""


def _dns_range_class(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return ""
    for net, _name, cls in VPN_DNS_PRIVATE_RANGES:
        if obj in net:
            return cls
    return ""


def _classify_dns_entries(entries: list[dict[str, str]], ifaces: list[str]) -> tuple[str, str, int, str, str]:
    if not entries:
        return ("unknown", "DNS non détecté", 0, "resolvectl/resolv.conf", "Impossible d'évaluer le DNS. Installer iproute2/systemd-resolved ou vérifier /etc/resolv.conf.")

    vpn_links = _vpn_like_links(ifaces)
    classified = []
    classes: set[str] = set()
    for e in entries:
        ip = e["ip"]
        meta = DNS_PROVIDER_DB.get(ip)
        provider = meta["name"] if meta else ""
        cls = meta["class"] if meta else ""
        private_name = _vpn_dns_range_name(ip)
        range_cls = _dns_range_class(ip)
        link = e.get("link") or ""
        source = e.get("source") or ""
        link_l = link.lower()
        via_vpn_link = bool(link and (link in vpn_links or any(p in link_l for p in VPN_IFACE_PATTERNS)))
        interface_provider = _dns_provider_from_interface(link) if via_vpn_link else ""

        if not cls and private_name:
            provider = interface_provider or private_name
            cls = range_cls or ("vpn_or_private" if via_vpn_link else "private_local")
        elif not cls and interface_provider:
            provider = interface_provider
            cls = "vpn_or_private"
        elif cls and via_vpn_link and cls not in {"avoid_public", "deprecated"}:
                                                                                      
            cls = "vpn_provider_dns" if cls.startswith("vpn") or "mullvad" in provider.lower() else cls

        classes.add(cls or "unknown")
        label = provider or "unclassified"
        link_txt = f" via {link}" if link else ""
        classified.append(f"{ip} -> {label}{link_txt} [{source}]")

    evidence = "; ".join(classified)
    if any(c == "avoid_public" for c in classes):
        return ("avoid", "DNS peu favorable à la vie privée détecté", -1, evidence, "Remplacer Google DNS ou équivalent par Quad9, Mullvad DNS, DNS4EU, AdGuard, NextDNS, Unbound local ou le DNS du VPN selon le modèle de menace.")
    if any(c == "deprecated" for c in classes):
        return ("deprecated", "DNS obsolète ou abandonné détecté", -1, evidence, "Ce fournisseur semble obsolète/abandonné. Migrer vers un résolveur maintenu comme DNS4EU, Quad9, Mullvad DNS, AdGuard, NextDNS ou un résolveur local.")
    if any(c == "vpn_provider_dns" for c in classes):
        return ("vpn", "DNS fourni par un VPN ou fournisseur privacy détecté", 2, evidence, "Bon signal si le DNS suit réellement le tunnel VPN. Vérifier l'absence de fuite DNS avec un test externe seulement si nécessaire et consenti.")
    if any(c in {"privacy_public", "privacy_filtering", "privacy_configurable"} for c in classes):
        return ("privacy", "DNS public favorable à la vie privée détecté", 1, evidence, "Bon point. Pour renforcer encore: utiliser DoT/DoH, DNSCrypt, DNS via VPN ou résolveur local Unbound selon le modèle de menace.")
    if any(c == "mixed_public" for c in classes):
        return ("mixed", "DNS public acceptable mais à nuancer détecté", 0, evidence, "Correct techniquement, mais pas forcément idéal en posture privacy stricte. Préférer Quad9, Mullvad DNS, DNS4EU, AdGuard, NextDNS ou DNS VPN si l'objectif est la réduction maximale des métadonnées.")
    if any(c == "vpn_or_private" for c in classes):
        return ("private_vpn", "DNS privé ou VPN probable détecté", 1, evidence, "Adresse privée: classification publique impossible. Si elle vient de l'interface VPN, c'est généralement attendu; sinon vérifier le routeur/résolveur amont.")
    if any(c == "private_local" for c in classes):
        return ("private_local", "DNS du réseau local ou routeur détecté", 0, evidence, "Souvent la box/routeur du FAI. Vérifier le résolveur amont et envisager DNS chiffré, DNS VPN ou résolveur local contrôlé.")
    return ("unknown", "DNS détecté mais non classé", 0, evidence, "L'IP n'est pas dans la base locale et aucun indice fiable ne permet de la classer. Un PTR peut aider à l'affichage, mais ne doit pas décider la notation.")


def _process_lines(pattern: str) -> list[str]:
    rc, out, _ = run_cmd(["pgrep", "-af", pattern], timeout=2)
    if rc != 0 or not out:
        return []
    lines = []
    for line in out.splitlines():
        low = line.lower()
        if "privacy_index" in low or "pgrep" in low:
            continue
        lines.append(line[:220])
    return lines[:8]


def _service_active(*names: str) -> list[str]:
    active = []
    if not command_exists("systemctl"):
        return active
    for name in names:
        unit = name if name.endswith(".service") else f"{name}.service"
        rc, out, _ = run_cmd(["systemctl", "is-active", unit], timeout=1.5)
        if rc == 0 and out.strip() == "active":
            active.append(unit)
    return active


def _detect_vpn_protocols(ifaces: list[str], wg_peers: int) -> list[tuple[str, str, bool]]:
    results: list[tuple[str, str, bool]] = []
    low_ifaces = [i.lower() for i in ifaces]

    def add(key: str, evidence: str, active: bool) -> None:
        if not any(k == key for k, _, _ in results):
            results.append((key, evidence, active))

                                                                          
    wg_ifaces = [i for i in ifaces if i.lower().startswith(("wg", "wireguard", "nordlynx"))]
    if wg_ifaces or wg_peers:
        add("wireguard", f"interfaces={wg_ifaces}, wg_peers={wg_peers}", True)
    elif command_exists("wg") or command_exists("wg-quick"):
        add("wireguard", "wg/wg-quick command present, no active peer detected", False)

                                                                  
    awg_ifaces = [i for i in ifaces if i.lower().startswith(("awg", "amnezia"))]
    awg_active = bool(awg_ifaces) or bool(_process_lines(r"(amnezia|awg-quick|\bawg\b)")) or bool(_service_active("awg-quick@awg0", "amneziawg", "amnezia", "amneziavpn", "amnezia-vpn", "amnezia-vpn-service"))
    if awg_active:
        ev_parts = []
        if awg_ifaces:
            ev_parts.append(f"interfaces={awg_ifaces}")
        if command_exists("awg") or command_exists("awg-quick"):
            ev_parts.append("awg/awg-quick present")
        add("amneziawg", ", ".join(ev_parts) or "AmneziaWG/awg process or service detected", True)
    elif any(command_exists(c) for c in ["awg", "awg-quick", "amneziawg", "amnezia", "amnezia-vpn", "AmneziaVPN"]):
        add("amneziawg", "Amnezia/AmneziaWG command present, active tunnel not confirmed", False)

                                                                                  
    xray_procs = _process_lines(r"(\bxray\b|\bv2ray\b|sing-box|hysteria|trojan|shadowsocks|mihomo|clash)")
    xray_services = _service_active("xray", "v2ray", "sing-box", "hysteria", "mihomo", "clash")
    if xray_procs or xray_services:
        ev = []
        if xray_services:
            ev.append(f"services={xray_services}")
        if xray_procs:
            ev.append("process=" + " | ".join(xray_procs[:2]))
        add("xray", "; ".join(ev), True)
    elif any(command_exists(c) for c in ["xray", "v2ray", "sing-box", "hysteria", "mihomo", "clash"]):
        cmds = [c for c in ["xray", "v2ray", "sing-box", "hysteria", "mihomo", "clash"] if command_exists(c)]
        add("xray", f"commands={cmds}, active process not confirmed", False)

                                                                       
    nym_ifaces = [i for i in ifaces if i.lower().startswith(("nym", "nymvpn"))]
    nym_procs = _process_lines(r"(nym-vpn|nymvpn|nym-client|nym-connect|\bnym\b)")
    nym_services = _service_active("nym-vpn", "nymvpn", "nym-client")
    if nym_ifaces or nym_procs or nym_services:
        ev = []
        if nym_ifaces:
            ev.append(f"interfaces={nym_ifaces}")
        if nym_services:
            ev.append(f"services={nym_services}")
        if nym_procs:
            ev.append("process=" + " | ".join(nym_procs[:2]))
        add("nym", "; ".join(ev), True)
    elif any(command_exists(c) for c in ["nym-vpn", "nymvpn", "nym-client", "nym-connect"]):
        cmds = [c for c in ["nym-vpn", "nymvpn", "nym-client", "nym-connect"] if command_exists(c)]
        add("nym", f"commands={cmds}, active process not confirmed", False)

                              
    openvpn_active = bool([i for i in low_ifaces if i.startswith(("tun", "tap"))]) or bool(_process_lines(r"\bopenvpn\b")) or bool(_service_active("openvpn", "openvpn-client@client"))
    if openvpn_active and not any(k in {"wireguard", "amneziawg", "xray", "nym"} and active for k, _, active in results):
        add("openvpn", "tun/tap interface or OpenVPN process/service detected", True)
    elif command_exists("openvpn"):
        add("openvpn", "openvpn command present, active tunnel not confirmed", False)

    if any(i.startswith("tailscale") for i in low_ifaces) or _process_lines(r"\btailscaled\b"):
        add("tailscale", "tailscale interface/process detected", True)

    return results


def _detect_privacy_vpn_providers(ifaces: list[str]) -> list[tuple[str, str, bool]]:
    results: list[tuple[str, str, bool]] = []

    def add(key: str, evidence: str, active: bool) -> None:
        if not any(k == key for k, _, _ in results):
            results.append((key, evidence, active))

    low_ifaces = [i.lower() for i in ifaces]

    amnezia_ifaces = [i for i in ifaces if any(x in i.lower() for x in ["amnezia", "awg"])]
    amnezia_procs = _process_lines(r"(amneziavpn|amnezia-vpn|amnezia|amneziawg|awg-quick|\bawg\b)")
    amnezia_services = _service_active("amnezia", "amneziavpn", "amnezia-vpn", "amnezia-vpn-service", "amneziawg", "awg-quick@awg0")
    amnezia_cmds = [c for c in ["amnezia", "amnezia-vpn", "AmneziaVPN", "amneziawg", "awg", "awg-quick"] if command_exists(c)]
    amnezia_desktop = desktop_app_exists("amnezia")
    if amnezia_ifaces or amnezia_procs or amnezia_services:
        ev = []
        if amnezia_ifaces: ev.append(f"interfaces={amnezia_ifaces}")
        if amnezia_services: ev.append(f"services={amnezia_services}")
        if amnezia_procs: ev.append("process=" + " | ".join(amnezia_procs[:2]))
        if amnezia_cmds: ev.append(f"commands={amnezia_cmds}")
        if amnezia_desktop: ev.append("desktop=Amnezia")
        add("amnezia", "; ".join(ev), True)
    elif amnezia_cmds or amnezia_desktop:
        ev = []
        if amnezia_cmds: ev.append(f"commands={amnezia_cmds}")
        if amnezia_desktop: ev.append("desktop=Amnezia")
        add("amnezia", "; ".join(ev) + ", active tunnel not confirmed", False)

    nym_ifaces = [i for i in ifaces if any(x in i.lower() for x in ["nym", "nymvpn"])]
    nym_procs = _process_lines(r"(nym-vpnd|nym-vpn|nymvpn|nym-client|nym-connect|\bnym\b)")
    nym_services = _service_active("nym-vpnd", "nym-vpn", "nymvpn", "nym-client")
    nym_cmds = [c for c in ["nym-vpn", "nymvpn", "nym-vpnd", "nym-client", "nym-connect"] if command_exists(c)]
    nym_desktop = desktop_app_exists("nymvpn", "nym-vpn", "nym vpn")
    if nym_ifaces or nym_procs or nym_services:
        ev = []
        if nym_ifaces: ev.append(f"interfaces={nym_ifaces}")
        if nym_services: ev.append(f"services={nym_services}")
        if nym_procs: ev.append("process=" + " | ".join(nym_procs[:2]))
        if nym_cmds: ev.append(f"commands={nym_cmds}")
        if nym_desktop: ev.append("desktop=NymVPN")
        add("nym", "; ".join(ev), True)
    elif nym_cmds or nym_desktop:
        ev = []
        if nym_cmds: ev.append(f"commands={nym_cmds}")
        if nym_desktop: ev.append("desktop=NymVPN")
        add("nym", "; ".join(ev) + ", active tunnel not confirmed", False)

    return results


def scan(ctx: ScanContext) -> None:
    ifaces = _ip_links()
    ctx.fact("network.up_interfaces", ifaces)
    vpn_ifaces = [i for i in ifaces if i.lower().startswith(VPN_IFACE_PATTERNS) or any(p in i.lower() for p in VPN_IFACE_PATTERNS)]

                                    
    wg_peers = 0
    if command_exists("wg"):
        rc, out, _ = run_cmd(["wg", "show"], timeout=2)
        if rc == 0:
            wg_peers = out.count("peer:")

    if vpn_ifaces or wg_peers:
        ctx.add(Finding(
            category="network",
            key="vpn.active",
            title="Interface VPN/tunnel active détectée",
            status=Severity.OK,
            privacy=2,
            anonymity=0,
            evidence=f"interfaces={vpn_ifaces}, wg_peers={wg_peers}",
            recommendation="Un VPN aide contre le FAI, mais ne garantit pas l'anonymat. Pour anonymat: Tor Browser et cloisonnement.",
            confidence="medium",
        ))
    else:
        ctx.add(Finding(
            category="network",
            key="vpn.inactive",
            title="Aucun VPN/tunnel actif détecté",
            status=Severity.WARN,
            privacy=-1,
            anonymity=0,
            evidence=f"interfaces_up={ifaces}",
            recommendation="À corriger si le modèle de menace inclut le FAI, Wi-Fi publics ou corrélation IP.",
            confidence="medium",
        ))

    providers = _detect_privacy_vpn_providers(ifaces)
    ctx.fact("network.privacy_vpn_providers", providers)
    for provider_key, provider_evidence, provider_active in providers:
        if provider_key == "amnezia":
            ctx.add(Finding(
                category="network",
                key="vpn.provider.amnezia",
                title="Fournisseur VPN Amnezia détecté",
                status=Severity.OK if provider_active else Severity.INFO,
                privacy=1 if provider_active else 0,
                anonymity=1 if provider_active else 0,
                evidence=provider_evidence,
                recommendation="Amnezia/AmneziaWG est un choix judicieux pour un usage privacy avec résistance accrue au filtrage de WireGuard. Vérifier que le tunnel actif et le DNS passent bien par le client.",
                confidence="medium" if provider_active else "low",
            ))
        elif provider_key == "nym":
            ctx.add(Finding(
                category="network",
                key="vpn.provider.nym",
                title="Fournisseur VPN Nym détecté",
                status=Severity.OK if provider_active else Severity.INFO,
                privacy=1 if provider_active else 0,
                anonymity=1 if provider_active else 0,
                evidence=provider_evidence,
                recommendation="Nym/NymVPN est un choix intéressant pour réduire certaines corrélations réseau grâce à son approche décentralisée/mixnet. À évaluer selon les performances et le modèle de menace.",
                confidence="medium" if provider_active else "low",
            ))

    protocols = _detect_vpn_protocols(ifaces, wg_peers)
    ctx.fact("network.vpn_protocols", protocols)
    active_protocols = [p for p in protocols if p[2]]
    installed_protocols = [p for p in protocols if not p[2]]

    if active_protocols:
        for proto_key, proto_evidence, _active in active_protocols:
            if proto_key == "wireguard":
                ctx.add(Finding(
                    category="network",
                    key="vpn.protocol.wireguard",
                    title="Protocole VPN WireGuard détecté",
                    status=Severity.OK,
                    privacy=1,
                    anonymity=0,
                    evidence=proto_evidence,
                    recommendation="WireGuard est une solution moderne, rapide et saine, mais standard: en environnement censuré, prévoir une couche d'obfuscation ou un transport plus discret.",
                    confidence="high",
                ))
            elif proto_key == "amneziawg":
                ctx.add(Finding(
                    category="network",
                    key="vpn.protocol.amneziawg",
                    title="Protocole VPN AmneziaWG détecté",
                    status=Severity.OK,
                    privacy=2,
                    anonymity=1,
                    evidence=proto_evidence,
                    recommendation="Très bon choix si l'objectif inclut la résistance à certaines formes de blocage de WireGuard. Moins camouflé qu'un bon XRay/Reality, mais plus discret que WireGuard brut.",
                    confidence="medium",
                ))
            elif proto_key == "xray":
                ctx.add(Finding(
                    category="network",
                    key="vpn.protocol.xray",
                    title="Transport XRay/V2Ray/sing-box détecté",
                    status=Severity.OK,
                    privacy=2,
                    anonymity=1,
                    evidence=proto_evidence,
                    recommendation="Excellent choix pour contourner des filtrages ou censures réseau, surtout avec des transports modernes comme Reality/gRPC/WebSocket bien configurés. Ce n'est pas une preuve d'anonymat: l'usage et le serveur comptent toujours.",
                    confidence="medium",
                ))
            elif proto_key == "nym":
                ctx.add(Finding(
                    category="network",
                    key="vpn.protocol.nym",
                    title="Solution Nym/NymVPN détectée",
                    status=Severity.INFO,
                    privacy=1,
                    anonymity=1,
                    evidence=proto_evidence,
                    recommendation="Choix intéressant pour réduire la corrélation réseau, mais technologie encore à surveiller selon l'usage réel, les performances et le modèle de menace.",
                    confidence="low",
                ))
            elif proto_key == "openvpn":
                ctx.add(Finding(
                    category="network",
                    key="vpn.protocol.openvpn",
                    title="Protocole VPN OpenVPN détecté",
                    status=Severity.INFO,
                    privacy=1,
                    anonymity=0,
                    evidence=proto_evidence,
                    recommendation="OpenVPN reste solide mais plus ancien et souvent plus visible. WireGuard est souvent plus simple/rapide; XRay/AmneziaWG sont plus adaptés en contexte de censure.",
                    confidence="medium",
                ))
            elif proto_key == "tailscale":
                ctx.add(Finding(
                    category="network",
                    key="vpn.protocol.tailscale",
                    title="Tunnel Tailscale/mesh détecté",
                    status=Severity.INFO,
                    privacy=0,
                    anonymity=0,
                    evidence=proto_evidence,
                    recommendation="Tailscale est excellent pour relier des machines privées, mais ce n'est pas un VPN d'anonymat ou anti-tracking web classique.",
                    confidence="medium",
                ))
    elif installed_protocols and (vpn_ifaces or wg_peers):
        ctx.add(Finding(
            category="network",
            key="vpn.protocol.installed_only",
            title="Protocoles VPN installés mais protocole actif incertain",
            status=Severity.UNKNOWN,
            privacy=0,
            anonymity=0,
            evidence="; ".join(f"{k}: {ev}" for k, ev, _ in installed_protocols),
            recommendation="Le scanner a trouvé des outils VPN, mais pas assez d'indices pour affirmer quel protocole transporte la session active.",
            confidence="low",
        ))

    dns_entries = _dns_entries()
    dns = [e["ip"] for e in dns_entries]
    ctx.fact("network.dns_servers", dns)
    ctx.fact("network.dns_entries", dns_entries)
    ctx.fact("network.dns_database", {
        "source": "bundled privacy_index/data/dns_providers.json",
        "schema_version": DNS_DB_META.get("schema_version", "fallback"),
        "entries": len(DNS_PROVIDER_DB),
        "ranges": len(VPN_DNS_PRIVATE_RANGES),
    })

    dns_kind, title, privacy, evidence, rec = _classify_dns_entries(dns_entries, ifaces)
    if dns_kind in {"privacy", "vpn", "private_vpn"}:
        status = Severity.OK
    elif dns_kind in {"mixed", "private_local"}:
        status = Severity.WARN
    elif dns_kind in {"avoid", "deprecated"}:
        status = Severity.BAD if dns_kind == "avoid" else Severity.WARN
    else:
        status = Severity.UNKNOWN

    ctx.add(Finding(
        category="network",
        key="dns.servers",
        title=title,
        status=status,
        privacy=privacy,
        anonymity=0,
        evidence=evidence,
        recommendation=rec,
        confidence="high" if dns_kind not in {"unknown", "private_vpn", "private_local"} else "medium",
    ))

                         
    tor_tools = [name for name in ["tor", "torsocks", "torify"] if command_exists(name)]
    if tor_tools:
        ctx.add(Finding(
            category="network",
            key="tor.tools",
            title="Outils Tor locaux détectés",
            status=Severity.OK,
            privacy=1,
            anonymity=2,
            evidence=", ".join(tor_tools),
            recommendation="Bien, mais l'anonymat web doit passer par Tor Browser, pas seulement torsocks.",
            confidence="high",
        ))
