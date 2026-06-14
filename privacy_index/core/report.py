from __future__ import annotations

import csv
import json
from pathlib import Path
from .models import Finding, ScanContext, Severity
from .scoring import ScoreBundle
from .i18n import ui, status as i18n_status, text as i18n_text, normalize_lang


COLORS = {
    Severity.OK: "\033[32m",
    Severity.INFO: "\033[36m",
    Severity.WARN: "\033[33m",
    Severity.BAD: "\033[31m",
    Severity.UNKNOWN: "\033[90m",
}
RESET = "\033[0m"


def _notes() -> dict[str, dict[str, tuple[str, str, str]]]:
    return {
        "fr": {
            "updates.status": (
                "Des paquets non mis à jour peuvent contenir des failles connues. Les paquets volontairement placés en hold doivent être distingués d'un vrai oubli.",
                "Vérifier avec: apt list --upgradable puis apt-mark showhold. Mettre à jour ce qui n'est pas volontairement bloqué.",
                "https://wiki.debian.org/UnattendedUpgrades",
            ),
            "home.permissions": (
                "Un HOME lisible par d'autres utilisateurs locaux peut exposer documents, profils navigateur, clés SSH ou historiques. Si aucun autre utilisateur humain n'existe, le risque pratique est plus faible.",
                "Lister les utilisateurs humains puis, si besoin: chmod 700 $HOME. Attention aux dossiers partagés volontairement.",
                "https://wiki.archlinux.org/title/File_permissions_and_attributes",
            ),
            "disk.root_encrypted": (
                "Le chiffrement de la racine protège surtout les données au repos: vol, perte, accès physique hors session ouverte.",
                "Conserver une sauvegarde sûre de la phrase de passe et vérifier que le swap et les sauvegardes suivent la même logique.",
                "https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system",
            ),
            "disk.root_unencrypted": (
                "Sans chiffrement système, une personne ayant accès physiquement au disque peut lire beaucoup de données hors session.",
                "Prévoir une réinstallation avec LUKS/dm-crypt ou une migration contrôlée. Sauvegarder avant toute opération disque.",
                "https://wiki.debian.org/Cryptsetup",
            ),
            "swap.encryption": (
                "Le swap peut contenir des fragments de mémoire: documents, clés temporaires, pages navigateur. Non chiffré, il affaiblit un disque racine chiffré.",
                "Vérifier swapon --show et lsblk -f. Idéalement, placer le swap dans le volume LUKS ou utiliser un swap chiffré.",
                "https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption",
            ),
            "vpn.active": (
                "Un VPN masque le trafic au FAI et change l'IP visible, mais il ne rend pas anonyme à lui seul.",
                "Pour l'anonymat web, utiliser Tor Browser et éviter les comptes personnels. Pour la vie privée quotidienne, vérifier aussi les fuites DNS/WebRTC.",
                "https://www.privacyguides.org/en/vpn/",
            ),
            "vpn.inactive": (
                "Sans VPN ni Tor, le FAI ou le réseau local peuvent voir les domaines contactés, sauf protections DNS/TLS partielles.",
                "Activer un VPN fiable si le modèle de menace inclut le FAI ou le Wi-Fi public. Pour anonymat fort: Tor Browser.",
                "https://www.privacyguides.org/en/basics/vpn-overview/",
            ),
            "vpn.protocol.wireguard": (
                "WireGuard est moderne, rapide et sain, mais son trafic est assez reconnaissable sans couche d\'obfuscation.",
                "Très bon pour un VPN standard. En contexte de censure ou filtrage actif, envisager AmneziaWG ou XRay/Reality selon le modèle de menace.",
                "https://www.wireguard.com/",
            ),
            "vpn.protocol.amneziawg": (
                "AmneziaWG modifie WireGuard pour le rendre moins trivial à bloquer ou identifier dans certains environnements.",
                "Choix judicieux si WireGuard brut est filtré. Garder une configuration propre et vérifier régulièrement les fuites DNS/WebRTC.",
                "https://docs.amnezia.org/",
            ),
            "vpn.protocol.xray": (
                "XRay/V2Ray/sing-box peuvent camoufler le transport et mieux résister à diverses formes de censure réseau quand ils sont bien configurés.",
                "Excellent choix en contexte hostile, surtout avec Reality/gRPC/WebSocket selon le besoin. Attention: cela ne remplace pas Tor Browser pour l\'anonymat web.",
                "https://xtls.github.io/",
            ),
            "vpn.protocol.nym": (
                "Nym/NymVPN vise une protection par mixnet ou approche hybride, intéressante pour réduire certaines corrélations réseau.",
                "Solution prometteuse, mais à évaluer selon maturité, performance et modèle de menace. Le scanner la marque comme intéressante plutôt que définitivement supérieure.",
                "https://nym.com/",
            ),
            "vpn.protocol.openvpn": (
                "OpenVPN reste robuste mais plus ancien et souvent plus visible qu\'un transport spécialisé anti-censure.",
                "Correct pour un VPN classique. Pour résistance à la censure, comparer avec WireGuard obfusqué, AmneziaWG ou XRay.",
                "https://openvpn.net/",
            ),
            "vpn.protocol.tailscale": (
                "Tailscale est surtout un réseau mesh privé entre machines, pas un VPN d\'anonymat web.",
                "Très utile pour l\'administration privée; ne pas le compter comme protection principale contre tracking web ou corrélation d\'identité.",
                "https://tailscale.com/kb/",
            ),
            "vpn.protocol.installed_only": (
                "Des outils VPN sont présents, mais le scanner ne peut pas confirmer quel protocole transporte réellement la session active.",
                "Vérifier le client VPN, les services systemd et les interfaces actives avec ip link, wg show, systemctl et les journaux du client.",
                "",
            ),
            "dns.servers": (
                "Le DNS révèle les domaines demandés. Un DNS chiffré ou maîtrisé réduit les fuites vers le FAI ou le réseau local.",
                "Vérifier resolvectl status. Préférer DNS chiffré, DNS du VPN, Unbound local ou un fournisseur cohérent avec le modèle de menace.",
                "https://www.privacyguides.org/en/dns/",
            ),
            "tor.tools": (
                "tor/torsocks permettent de torrifier certaines applications, mais ce n'est pas équivalent à Tor Browser pour le web.",
                "Utiliser Tor Browser pour naviguer anonymement. Réserver torsocks aux outils CLI compatibles et testés.",
                "https://support.torproject.org/",
            ),
            "tor-browser.detected": (
                "Tor Browser est la brique la plus importante pour l'anonymat web grâce à Tor et à son anti-fingerprinting uniforme.",
                "Ne pas ajouter d'extensions, éviter le plein écran distinctif, ne pas se connecter à des comptes personnels si l'objectif est l'anonymat.",
                "https://tb-manual.torproject.org/",
            ),
            "mullvad-browser.detected": (
                "Mullvad Browser reprend l'idée d'un fingerprint standardisé, mais sans réseau Tor par défaut. Très bon pour réduire le tracking web courant.",
                "Le garder proche de sa configuration d'origine. Trop d'extensions ou de réglages exotiques peuvent casser l'uniformité du profil.",
                "https://mullvad.net/browser",
            ),
            "firewall.active": (
                "Un pare-feu entrant réduit l'exposition accidentelle de services locaux.",
                "Sur poste client: politique entrante restrictive. Vérifier avec ufw status, nft list ruleset ou équivalent.",
                "https://wiki.debian.org/nftables",
            ),
            "services.exposed": (
                "Un service qui écoute sur 0.0.0.0 ou :: peut être joignable depuis le réseau selon le pare-feu et la topologie.",
                "Désactiver les services inutiles, limiter à 127.0.0.1, ou filtrer strictement par pare-feu.",
                "https://wiki.archlinux.org/title/Systemd#Using_units",
            ),
            "services.no_risky_exposed": (
                "Aucun service réseau risqué exposé n'a été repéré par le scan local, ce qui réduit la surface d'attaque.",
                "Continuer à vérifier après installation de nouveaux services: ss -tulpen.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),

            "services.open_ports_review": (
                "Des ports en écoute sur le réseau augmentent la surface d'attaque si l'application ou le service n'est pas explicitement voulu.",
                "Identifier chaque port avec ss -tulpn, désactiver le service inutile ou limiter l'écoute à 127.0.0.1 / au LAN attendu.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "services.lan_discovery": (
                "Certains services LAN comme mDNS ou DHCP sont normaux sur un poste client, mais ils rendent la machine plus visible sur le réseau local.",
                "Les garder si nécessaires. Les désactiver seulement pour un profil très discret ou en réseau hostile.",
                "https://wiki.archlinux.org/title/Avahi",
            ),
            "services.vpn_owned_udp": (
                "Certains clients VPN/tunnel ouvrent des sockets UDP locaux ou dynamiques. Ce n'est pas forcément un service exposé au sens serveur.",
                "Vérifier que le processus est bien celui du VPN attendu. Si oui, c'est informatif; sinon, contrôler avec ss -tulpen et systemctl.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "services.client_udp": (
                "Des ports UDP élevés peuvent apparaître lorsqu'un navigateur, un client réseau ou un outil local communique vers l'extérieur. Ce n'est pas automatiquement un service serveur exposé.",
                "Vérifier le nom du processus. Si c'est le navigateur, le VPN ou une application volontairement utilisée, c'est généralement informatif.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "search_engine.privacy_strong": (
                "Le moteur de recherche est un point privacy important: les requêtes révèlent beaucoup d'intentions, de centres d'intérêt et parfois d'informations personnelles.",
                "Mojeek ou SearXNG sont de très bons choix. Vérifier aussi le moteur en navigation privée et sur chaque profil navigateur.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.privacy_good": (
                "Un moteur plus respectueux limite généralement la collecte et la corrélation des recherches par rapport aux grands moteurs publicitaires.",
                "Brave Search, DuckDuckGo, StartPage ou Qwant sont préférables à Google/Bing/Yandex/Baidu/Yahoo/Ecosia selon ton modèle de menace.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.mixed": (
                "Plusieurs moteurs semblent présents: cela peut être normal si plusieurs navigateurs/profils coexistent, mais le moteur par défaut compte beaucoup.",
                "Vérifier navigateur par navigateur le moteur par défaut, le moteur en navigation privée et les éventuelles recherches depuis la barre d'adresse.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.avoid": (
                "Les moteurs publicitaires dominants peuvent corréler les requêtes, l'identité, l'IP, les cookies et d'autres métadonnées.",
                "Remplacer le moteur par défaut par Mojeek, SearXNG, Brave Search, DuckDuckGo, StartPage ou Qwant selon l'objectif.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.unknown": (
                "Le scanner n'a pas pu déterminer localement le moteur par défaut. Ce n'est pas rare: certains navigateurs stockent ce réglage en base verrouillée ou format compressé.",
                "Vérifier manuellement dans les paramètres du navigateur. Aucun test réseau n'est lancé pour cette vérification.",
                "",
            ),


            "password.manager": (
                "Un gestionnaire de mots de passe local évite la réutilisation de mots de passe et facilite les secrets forts.",
                "KeePassXC/pass sont de bons choix locaux. Une application volontairement hors PATH est acceptable si elle est installée et contrôlée par l'utilisateur.",
                "https://keepassxc.org/docs/",
            ),
            "encryption.tools": (
                "Des outils de chiffrement fichier/volume complètent le chiffrement système pour les échanges, archives et supports externes.",
                "VeraCrypt pour volumes multi-OS, LUKS pour Linux système, age/GPG pour fichiers selon le besoin.",
                "https://www.veracrypt.fr/en/Documentation.html",
            ),
            "messaging.secure": (
                "Une messagerie chiffrée limite l'exposition du contenu des échanges, mais la protection dépend aussi des métadonnées, sauvegardes et contacts.",
                "Vérifier les sauvegardes cloud, les notifications, la synchronisation des contacts et l'identifiant téléphone selon l'application.",
                "https://www.privacyguides.org/en/real-time-communication/",
            ),
            "sandbox.tools": (
                "Le cloisonnement réduit les dégâts si une application est compromise ou trop curieuse.",
                "Vérifier les permissions Flatpak avec Flatseal ou flatpak permission-show. Firejail/Bubblewrap doivent être testés au cas par cas.",
                "https://wiki.archlinux.org/title/Bubblewrap",
            ),
        },
        "en": {
            "updates.status": (
                "Outdated packages may contain known vulnerabilities. Packages intentionally held back must be separated from real update neglect.",
                "Check: apt list --upgradable and apt-mark showhold. Update everything that is not intentionally held.",
                "https://wiki.debian.org/UnattendedUpgrades",
            ),
            "home.permissions": (
                "A home directory readable by other local users may expose documents, browser profiles, SSH keys or shell history. If there are no other human users, the practical risk is lower.",
                "List human users, then use chmod 700 $HOME if needed. Be careful with intentionally shared folders.",
                "https://wiki.archlinux.org/title/File_permissions_and_attributes",
            ),
            "disk.root_encrypted": (
                "Root disk encryption mostly protects data at rest: theft, loss, or physical access while the session is closed.",
                "Keep a safe backup of the passphrase and make sure swap and backups follow the same protection model.",
                "https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system",
            ),
            "disk.root_unencrypted": (
                "Without system disk encryption, someone with physical access to the drive can read a lot of data outside your session.",
                "Plan a controlled migration or reinstall with LUKS/dm-crypt. Back up before any disk operation.",
                "https://wiki.debian.org/Cryptsetup",
            ),
            "swap.encryption": (
                "Swap can contain memory fragments: documents, temporary keys, browser pages. If it is not encrypted, it weakens an encrypted root disk setup.",
                "Check swapon --show and lsblk -f. Ideally keep swap inside the LUKS volume or use encrypted swap.",
                "https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption",
            ),
            "vpn.active": (
                "A VPN hides traffic from the ISP and changes the visible IP address, but it does not provide anonymity by itself.",
                "For web anonymity, use Tor Browser and avoid personal accounts. For daily privacy, also check DNS and WebRTC leaks.",
                "https://www.privacyguides.org/en/vpn/",
            ),
            "vpn.inactive": (
                "Without a VPN or Tor, the ISP or local network can often see contacted domains, except for partial DNS/TLS protections.",
                "Enable a trustworthy VPN if your threat model includes the ISP or public Wi-Fi. For strong anonymity, use Tor Browser.",
                "https://www.privacyguides.org/en/basics/vpn-overview/",
            ),
            "vpn.protocol.wireguard": (
                "WireGuard is modern, fast and technically clean, but its traffic is fairly recognizable without an obfuscation layer.",
                "Very good for a standard VPN. Under active censorship or filtering, consider AmneziaWG or XRay/Reality depending on the threat model.",
                "https://www.wireguard.com/",
            ),
            "vpn.protocol.amneziawg": (
                "AmneziaWG modifies WireGuard to make it less trivial to identify or block in some environments.",
                "A wise choice when raw WireGuard is filtered. Keep the configuration clean and keep checking DNS/WebRTC leaks.",
                "https://docs.amnezia.org/",
            ),
            "vpn.protocol.xray": (
                "XRay/V2Ray/sing-box can camouflage transport and resist several forms of network censorship when configured properly.",
                "Excellent in hostile networks, especially with Reality/gRPC/WebSocket depending on the need. It does not replace Tor Browser for web anonymity.",
                "https://xtls.github.io/",
            ),
            "vpn.protocol.nym": (
                "Nym/NymVPN aims at mixnet or hybrid-style protection, which is interesting for reducing some network correlation.",
                "Promising, but evaluate maturity, performance and threat model. The scanner marks it as interesting rather than definitively superior.",
                "https://nym.com/",
            ),
            "vpn.protocol.openvpn": (
                "OpenVPN remains robust, but it is older and often more visible than specialized anti-censorship transports.",
                "Fine for a classic VPN. For censorship resistance, compare it with obfuscated WireGuard, AmneziaWG or XRay.",
                "https://openvpn.net/",
            ),
            "vpn.protocol.tailscale": (
                "Tailscale is mainly a private mesh network between machines, not a web-anonymity VPN.",
                "Very useful for private administration; do not count it as the main protection against web tracking or identity correlation.",
                "https://tailscale.com/kb/",
            ),
            "vpn.protocol.installed_only": (
                "VPN tools are present, but the scanner cannot confirm which protocol actually carries the active session.",
                "Check the VPN client, systemd services and active interfaces with ip link, wg show, systemctl and the client logs.",
                "",
            ),
            "dns.servers": (
                "DNS reveals requested domains. Encrypted or controlled DNS reduces leaks to the ISP or local network.",
                "Check resolvectl status. Prefer encrypted DNS, VPN DNS, local Unbound, or a provider that fits your threat model.",
                "https://www.privacyguides.org/en/dns/",
            ),
            "tor.tools": (
                "tor/torsocks can route some applications through Tor, but this is not equivalent to Tor Browser for web browsing.",
                "Use Tor Browser for anonymous browsing. Keep torsocks for compatible and tested CLI tools.",
                "https://support.torproject.org/",
            ),
            "tor-browser.detected": (
                "Tor Browser is the key component for web anonymity thanks to Tor routing and a uniform anti-fingerprinting profile.",
                "Do not add extensions, avoid distinctive full-screen behavior, and avoid logging into personal accounts when anonymity is the goal.",
                "https://tb-manual.torproject.org/",
            ),
            "mullvad-browser.detected": (
                "Mullvad Browser uses a standardized fingerprint approach without the Tor network by default. It is very good for reducing common web tracking.",
                "Keep it close to its default configuration. Too many extensions or exotic tweaks can break fingerprint uniformity.",
                "https://mullvad.net/browser",
            ),
            "firewall.active": (
                "An inbound firewall reduces accidental exposure of local services.",
                "On a workstation, keep a restrictive inbound policy. Check with ufw status, nft list ruleset, or equivalent tools.",
                "https://wiki.debian.org/nftables",
            ),
            "services.exposed": (
                "A service listening on 0.0.0.0 or :: may be reachable from the network depending on firewall and topology.",
                "Disable unnecessary services, bind them to 127.0.0.1, or filter them strictly with the firewall.",
                "https://wiki.archlinux.org/title/Systemd#Using_units",
            ),
            "services.no_risky_exposed": (
                "No risky exposed network service was found by the local scan, reducing the attack surface.",
                "Keep checking after installing new services: ss -tulpen.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),

            "services.open_ports_review": (
                "Network-listening ports increase attack surface when the application or service was not explicitly intended.",
                "Identify each port with ss -tulpn, disable unnecessary services, or bind them to 127.0.0.1 / the expected LAN only.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "services.lan_discovery": (
                "LAN discovery services such as mDNS or DHCP are common on workstations, but they make the machine more visible on the local network.",
                "Keep them if needed. Disable them only for a very quiet profile or a hostile local network.",
                "https://wiki.archlinux.org/title/Avahi",
            ),
            "services.vpn_owned_udp": (
                "Some VPN/tunnel clients open local or dynamic UDP sockets. This is not necessarily an exposed server-like service.",
                "Check that the process is the expected VPN client. If it is, treat this as informational; otherwise inspect with ss -tulpen and systemctl.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "search_engine.privacy_strong": (
                "The search engine is an important privacy point: search queries reveal intentions, interests and sometimes personal information.",
                "Mojeek or SearXNG are very good choices. Also check private browsing search and every browser profile.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.privacy_good": (
                "A more privacy-friendly search engine generally reduces collection and correlation compared with large advertising search engines.",
                "Brave Search, DuckDuckGo, StartPage or Qwant are preferable to Google/Bing/Yandex/Baidu/Yahoo/Ecosia depending on your threat model.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.mixed": (
                "Several engines appear to be present. This can be normal with multiple browsers/profiles, but the actual default engine matters most.",
                "Check each browser's default engine, private-browsing engine and address-bar search behavior.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.avoid": (
                "Dominant advertising search engines can correlate queries, identity, IP address, cookies and other metadata.",
                "Replace the default engine with Mojeek, SearXNG, Brave Search, DuckDuckGo, StartPage or Qwant depending on your goal.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.unknown": (
                "The scanner could not determine the default engine locally. This is common: some browsers store it in a locked database or compressed profile format.",
                "Check the browser settings manually. No network test is launched for this check.",
                "",
            ),
            "password.manager": (
                "A local password manager prevents password reuse and makes strong secrets practical.",
                "KeePassXC/pass are good local choices. Keeping a sensitive app outside PATH is acceptable if the desktop launcher is present and controlled by the user.",
                "https://keepassxc.org/docs/",
            ),
            "encryption.tools": (
                "File and volume encryption tools complement system disk encryption for exchanges, archives and removable drives.",
                "Use VeraCrypt for cross-platform volumes, LUKS for Linux system disks, and age/GPG for files depending on the need.",
                "https://www.veracrypt.fr/en/Documentation.html",
            ),
            "messaging.secure": (
                "Encrypted messaging limits content exposure, but protection also depends on metadata, backups and contact discovery.",
                "Check cloud backups, notifications, contact sync and phone-number identity depending on the application.",
                "https://www.privacyguides.org/en/real-time-communication/",
            ),
            "sandbox.tools": (
                "Compartmentalization reduces damage if an application is compromised or too curious.",
                "Check Flatpak permissions with Flatseal or flatpak permission-show. Firejail/Bubblewrap profiles should be tested case by case.",
                "https://wiki.archlinux.org/title/Bubblewrap",
            ),
        },
        "de": {
            "updates.status": (
                "Veraltete Pakete können bekannte Schwachstellen enthalten. Absichtlich zurückgehaltene Pakete müssen von echten Update-Versäumnissen getrennt werden.",
                "Prüfen mit: apt list --upgradable und apt-mark showhold. Alles aktualisieren, was nicht bewusst gehalten wird.",
                "https://wiki.debian.org/UnattendedUpgrades",
            ),
            "home.permissions": (
                "Ein für andere lokale Benutzer lesbares Home-Verzeichnis kann Dokumente, Browserprofile, SSH-Schlüssel oder Shell-History offenlegen. Ohne weitere menschliche Benutzer ist das praktische Risiko geringer.",
                "Menschliche Benutzer auflisten und bei Bedarf chmod 700 $HOME setzen. Vorsicht bei absichtlich geteilten Ordnern.",
                "https://wiki.archlinux.org/title/File_permissions_and_attributes",
            ),
            "disk.root_encrypted": (
                "Die Verschlüsselung des Root-Laufwerks schützt vor allem ruhende Daten: Diebstahl, Verlust oder physischer Zugriff bei geschlossener Sitzung.",
                "Passphrase sicher sichern und prüfen, ob Swap und Backups demselben Schutzmodell folgen.",
                "https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system",
            ),
            "disk.root_unencrypted": (
                "Ohne Systemverschlüsselung kann jemand mit physischem Zugriff auf das Laufwerk viele Daten außerhalb der Sitzung lesen.",
                "Eine kontrollierte Migration oder Neuinstallation mit LUKS/dm-crypt planen. Vor jeder Datenträgeroperation sichern.",
                "https://wiki.debian.org/Cryptsetup",
            ),
            "swap.encryption": (
                "Swap kann Speicherfragmente enthalten: Dokumente, temporäre Schlüssel, Browserseiten. Unverschlüsselter Swap schwächt ein verschlüsseltes Root-Setup.",
                "swapon --show und lsblk -f prüfen. Idealerweise liegt Swap im LUKS-Volume oder ist separat verschlüsselt.",
                "https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption",
            ),
            "vpn.active": (
                "Ein VPN verbirgt Verkehr vor dem ISP und ändert die sichtbare IP-Adresse, macht aber allein nicht anonym.",
                "Für Web-Anonymität Tor Browser nutzen und persönliche Konten vermeiden. Für Alltagsschutz auch DNS- und WebRTC-Leaks prüfen.",
                "https://www.privacyguides.org/en/vpn/",
            ),
            "vpn.inactive": (
                "Ohne VPN oder Tor kann der ISP oder das lokale Netzwerk oft kontaktierte Domains sehen, abgesehen von teilweisem DNS/TLS-Schutz.",
                "Ein vertrauenswürdiges VPN aktivieren, wenn ISP oder öffentliches WLAN Teil des Bedrohungsmodells sind. Für starke Anonymität Tor Browser nutzen.",
                "https://www.privacyguides.org/en/basics/vpn-overview/",
            ),
            "dns.servers": (
                "DNS zeigt angefragte Domains. Verschlüsseltes oder kontrolliertes DNS reduziert Leaks an ISP oder lokales Netzwerk.",
                "resolvectl status prüfen. Verschlüsseltes DNS, VPN-DNS, lokales Unbound oder einen passenden Anbieter bevorzugen.",
                "https://www.privacyguides.org/en/dns/",
            ),
            "tor.tools": (
                "tor/torsocks können manche Anwendungen über Tor leiten, sind aber für Web-Browsing nicht gleichwertig mit Tor Browser.",
                "Tor Browser für anonymes Surfen nutzen. torsocks nur für kompatible und getestete CLI-Werkzeuge verwenden.",
                "https://support.torproject.org/",
            ),
            "tor-browser.detected": (
                "Tor Browser ist die wichtigste Komponente für Web-Anonymität dank Tor-Routing und einheitlichem Anti-Fingerprinting-Profil.",
                "Keine Erweiterungen hinzufügen, auffälligen Vollbildmodus vermeiden und bei Anonymitätsziel keine persönlichen Konten verwenden.",
                "https://tb-manual.torproject.org/",
            ),
            "mullvad-browser.detected": (
                "Mullvad Browser nutzt einen standardisierten Fingerprint-Ansatz, standardmäßig ohne Tor-Netzwerk. Sehr gut gegen übliches Web-Tracking.",
                "Nahe an der Standardkonfiguration halten. Zu viele Erweiterungen oder exotische Änderungen können die Einheitlichkeit brechen.",
                "https://mullvad.net/browser",
            ),
            "firewall.active": (
                "Eine eingehende Firewall reduziert die versehentliche Offenlegung lokaler Dienste.",
                "Auf einem Arbeitsplatzrechner eine restriktive Eingangsrichtlinie verwenden. Mit ufw status, nft list ruleset oder Ähnlichem prüfen.",
                "https://wiki.debian.org/nftables",
            ),
            "services.exposed": (
                "Ein Dienst auf 0.0.0.0 oder :: kann je nach Firewall und Netzwerktopologie erreichbar sein.",
                "Unnötige Dienste deaktivieren, an 127.0.0.1 binden oder strikt per Firewall filtern.",
                "https://wiki.archlinux.org/title/Systemd#Using_units",
            ),
            "services.no_risky_exposed": (
                "Der lokale Scan hat keinen riskant offengelegten Netzwerkdienst gefunden; das reduziert die Angriffsfläche.",
                "Nach Installation neuer Dienste weiter prüfen: ss -tulpen.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),

            "services.open_ports_review": (
                "Netzwerk-Ports im LISTEN-Zustand erhöhen die Angriffsfläche, wenn Anwendung oder Dienst nicht ausdrücklich gewollt sind.",
                "Jeden Port mit ss -tulpn identifizieren, unnötige Dienste deaktivieren oder nur an 127.0.0.1 / das erwartete LAN binden.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "services.lan_discovery": (
                "LAN-Erkennungsdienste wie mDNS oder DHCP sind auf Arbeitsstationen üblich, machen die Maschine aber im lokalen Netz sichtbarer.",
                "Behalten, wenn nötig. Nur für ein sehr stilles Profil oder in feindlichen lokalen Netzen deaktivieren.",
                "https://wiki.archlinux.org/title/Avahi",
            ),
            "services.vpn_owned_udp": (
                "Einige VPN-/Tunnel-Clients öffnen lokale oder dynamische UDP-Sockets. Das ist nicht automatisch ein exponierter Serverdienst.",
                "Prüfen, ob der Prozess der erwartete VPN-Client ist. Falls ja: informativ behandeln; sonst mit ss -tulpen und systemctl prüfen.",
                "https://man7.org/linux/man-pages/man8/ss.8.html",
            ),
            "search_engine.privacy_strong": (
                "Die Suchmaschine ist wichtig für Datenschutz: Suchanfragen verraten Absichten, Interessen und manchmal persönliche Informationen.",
                "Mojeek oder SearXNG sind sehr gute Optionen. Auch die Suche im privaten Modus und jedes Browserprofil prüfen.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.privacy_good": (
                "Eine datenschutzfreundlichere Suchmaschine reduziert meist Sammlung und Korrelation gegenüber großen Werbe-Suchmaschinen.",
                "Brave Search, DuckDuckGo, StartPage oder Qwant sind je nach Bedrohungsmodell besser als Google/Bing/Yandex/Baidu/Yahoo/Ecosia.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.mixed": (
                "Mehrere Suchmaschinen scheinen vorhanden zu sein. Das kann bei mehreren Browsern/Profilen normal sein, entscheidend ist aber die Standardsuche.",
                "In jedem Browser Standardsuche, private Suche und Suche über die Adressleiste prüfen.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.avoid": (
                "Dominante Werbe-Suchmaschinen können Suchanfragen, Identität, IP-Adresse, Cookies und andere Metadaten korrelieren.",
                "Die Standardsuche durch Mojeek, SearXNG, Brave Search, DuckDuckGo, StartPage oder Qwant ersetzen, je nach Ziel.",
                "https://www.privacyguides.org/en/search-engines/",
            ),
            "search_engine.unknown": (
                "Der Scanner konnte die Standardsuchmaschine lokal nicht bestimmen. Das ist häufig: manche Browser speichern sie in einer gesperrten Datenbank oder einem komprimierten Profilformat.",
                "Die Browser-Einstellungen manuell prüfen. Für diese Prüfung wird kein Netzwerktest gestartet.",
                "",
            ),
            "password.manager": (
                "Ein lokaler Passwortmanager verhindert Passwortwiederverwendung und erleichtert starke Geheimnisse.",
                "KeePassXC/pass sind gute lokale Optionen. Eine sensible App außerhalb von PATH ist akzeptabel, wenn der Desktop-Starter vorhanden und kontrolliert ist.",
                "https://keepassxc.org/docs/",
            ),
            "encryption.tools": (
                "Datei- und Volume-Verschlüsselung ergänzt Systemverschlüsselung für Austausch, Archive und externe Datenträger.",
                "VeraCrypt für plattformübergreifende Volumes, LUKS für Linux-Systemdatenträger und age/GPG je nach Bedarf für Dateien nutzen.",
                "https://www.veracrypt.fr/en/Documentation.html",
            ),
            "messaging.secure": (
                "Verschlüsselte Messenger begrenzen die Offenlegung von Inhalten, aber Schutz hängt auch von Metadaten, Backups und Kontaktsuche ab.",
                "Cloud-Backups, Benachrichtigungen, Kontaktsynchronisierung und Telefonnummer-Identität je nach Anwendung prüfen.",
                "https://www.privacyguides.org/en/real-time-communication/",
            ),
            "sandbox.tools": (
                "Abschottung reduziert Schäden, wenn eine Anwendung kompromittiert oder zu neugierig ist.",
                "Flatpak-Berechtigungen mit Flatseal oder flatpak permission-show prüfen. Firejail/Bubblewrap-Profile einzeln testen.",
                "https://wiki.archlinux.org/title/Bubblewrap",
            ),
        },
    }


def didactic_for(f: Finding, lang: str = "fr") -> tuple[str, str, str]:
    lang = normalize_lang(lang)
    notes = _notes()
    if f.key in notes.get(lang, {}):
        return notes[lang][f.key]
    if f.key.startswith("browser.inventory."):
        browser_id = f.key.rsplit(".", 1)[-1]
        notes = {
            "fr": {
                "brave": (
                    "Brave est orienté vie privée par défaut, mais ses protections dépendent aussi de Shields, WebRTC, cookies tiers, sync, extensions et moteur de recherche.",
                    "Vérifier Shields, désactiver sync si inutile, contrôler WebRTC et garder peu d'extensions.",
                    "https://support.brave.com/hc/en-us/categories/360001053072-Desktop-Browser",
                ),
                "firefox": (
                    "Firefox est une bonne base open source, mais il n'est pas aussi durci qu'un Tor Browser ou Mullvad Browser sans réglages complémentaires.",
                    "Vérifier télémétrie, WebRTC, RFP/anti-fingerprinting, cookies, DNS/DoH, extensions et moteur de recherche.",
                    "https://support.mozilla.org/kb/privacy-and-security-settings",
                ),
                "chromium": (
                    "Chromium est une base open source, mais la configuration par défaut peut rester trop permissive pour un objectif privacy strict.",
                    "Vérifier Safe Browsing, WebRTC, cookies tiers, sync, extensions, moteur de recherche et éventuelles politiques d'entreprise.",
                    "https://www.chromium.org/user-experience/user-data-directory/",
                ),
                "chrome": (
                    "Chrome est très intégré à l'écosystème Google et moins cohérent avec un objectif de réduction des métadonnées.",
                    "Éviter comme navigateur principal pour les usages sensibles. Préférer Tor Browser, Mullvad Browser, LibreWolf ou Brave selon l'objectif.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "edge": (
                    "Edge est très intégré à l'écosystème Microsoft et peut multiplier les points de synchronisation et télémétrie.",
                    "Éviter comme navigateur principal pour les usages sensibles ou vérifier strictement sync, télémétrie, moteur de recherche et extensions.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "opera": (
                    "Opera est moins transparent côté privacy et son VPN intégré ne doit pas être confondu avec un VPN système fiable.",
                    "Éviter comme navigateur principal pour les usages sensibles. Vérifier sync, télémétrie, extensions et moteur de recherche.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "vivaldi": (
                    "Vivaldi est personnalisable, mais cette personnalisation peut créer un profil plus distinctif si elle est excessive.",
                    "Vérifier sync, télémétrie, WebRTC, extensions, moteur de recherche et protections anti-tracking.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
            },
            "en": {
                "brave": (
                    "Brave is privacy-oriented by default, but protection still depends on Shields, WebRTC, third-party cookies, sync, extensions and the search engine.",
                    "Check Shields, disable sync if unnecessary, control WebRTC and keep extensions limited.",
                    "https://support.brave.com/hc/en-us/categories/360001053072-Desktop-Browser",
                ),
                "firefox": (
                    "Firefox is a good open-source base, but it is not as hardened as Tor Browser or Mullvad Browser without additional settings.",
                    "Check telemetry, WebRTC, RFP/anti-fingerprinting, cookies, DNS/DoH, extensions and the search engine.",
                    "https://support.mozilla.org/kb/privacy-and-security-settings",
                ),
                "chromium": (
                    "Chromium is an open-source base, but its default configuration can remain too permissive for a strict privacy goal.",
                    "Check Safe Browsing, WebRTC, third-party cookies, sync, extensions, the search engine and any enterprise policies.",
                    "https://www.chromium.org/user-experience/user-data-directory/",
                ),
                "chrome": (
                    "Chrome is tightly integrated with Google's ecosystem and is less consistent with metadata minimization.",
                    "Avoid it as the main browser for sensitive use. Prefer Tor Browser, Mullvad Browser, LibreWolf or Brave depending on the goal.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "edge": (
                    "Edge is tightly integrated with Microsoft's ecosystem and may add sync and telemetry points.",
                    "Avoid it as the main browser for sensitive use, or strictly check sync, telemetry, search engine and extensions.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "opera": (
                    "Opera is less transparent from a privacy perspective and its built-in VPN should not be confused with a reliable system VPN.",
                    "Avoid it as the main browser for sensitive use. Check sync, telemetry, extensions and the search engine.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "vivaldi": (
                    "Vivaldi is customizable, but too much customization can make the profile more distinctive.",
                    "Check sync, telemetry, WebRTC, extensions, search engine and anti-tracking protections.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
            },
            "de": {
                "brave": (
                    "Brave ist standardmäßig datenschutzorientiert, aber der Schutz hängt auch von Shields, WebRTC, Drittanbieter-Cookies, Sync, Erweiterungen und Suchmaschine ab.",
                    "Shields prüfen, Sync bei Bedarf deaktivieren, WebRTC kontrollieren und nur wenige Erweiterungen behalten.",
                    "https://support.brave.com/hc/en-us/categories/360001053072-Desktop-Browser",
                ),
                "firefox": (
                    "Firefox ist eine gute Open-Source-Basis, aber ohne zusätzliche Einstellungen nicht so gehärtet wie Tor Browser oder Mullvad Browser.",
                    "Telemetrie, WebRTC, RFP/Anti-Fingerprinting, Cookies, DNS/DoH, Erweiterungen und Suchmaschine prüfen.",
                    "https://support.mozilla.org/kb/privacy-and-security-settings",
                ),
                "chromium": (
                    "Chromium ist eine Open-Source-Basis, kann aber standardmäßig für ein striktes Privacy-Ziel zu permissiv bleiben.",
                    "Safe Browsing, WebRTC, Drittanbieter-Cookies, Sync, Erweiterungen, Suchmaschine und Richtlinien prüfen.",
                    "https://www.chromium.org/user-experience/user-data-directory/",
                ),
                "chrome": (
                    "Chrome ist eng in das Google-Ökosystem integriert und passt weniger gut zu Metadaten-Minimierung.",
                    "Nicht als Hauptbrowser für sensible Nutzung verwenden. Je nach Ziel Tor Browser, Mullvad Browser, LibreWolf oder Brave bevorzugen.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "edge": (
                    "Edge ist eng in das Microsoft-Ökosystem integriert und kann zusätzliche Sync- und Telemetriepunkte erzeugen.",
                    "Nicht als Hauptbrowser für sensible Nutzung verwenden oder Sync, Telemetrie, Suchmaschine und Erweiterungen streng prüfen.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "opera": (
                    "Opera ist aus Privacy-Sicht weniger transparent und das integrierte VPN ist kein Ersatz für ein verlässliches System-VPN.",
                    "Nicht als Hauptbrowser für sensible Nutzung verwenden. Sync, Telemetrie, Erweiterungen und Suchmaschine prüfen.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
                "vivaldi": (
                    "Vivaldi ist anpassbar, aber zu viele Anpassungen können das Profil unterscheidbarer machen.",
                    "Sync, Telemetrie, WebRTC, Erweiterungen, Suchmaschine und Anti-Tracking-Schutz prüfen.",
                    "https://www.privacyguides.org/en/desktop-browsers/",
                ),
            },
        }
        return notes.get(lang, notes["fr"]).get(browser_id, notes[lang]["firefox"])
    if f.key == "browser.residual_profiles":
        return {
            "fr": (
                "Des profils navigateurs peuvent rester après une désinstallation ou un déplacement manuel. Ils ne prouvent pas que le navigateur est encore installé, mais peuvent conserver cookies, cache, stockage local, extensions, sessions, favoris et anciens réglages.",
                "Si le navigateur n'est plus utilisé, le supprimer proprement puis retirer les profils restants après sauvegarde. Exemples Debian/Ubuntu: apt purge brave-browser firefox-esr firefox chromium; Flatpak: flatpak uninstall <app-id>; tarball Tor/Mullvad: supprimer le dossier extrait après sauvegarde des données utiles.",
                "https://support.mozilla.org/kb/profiles-where-firefox-stores-user-data",
            ),
            "en": (
                "Browser profiles may remain after uninstalling or manually moving a browser. They do not prove the browser is still installed, but they may keep cookies, cache, local storage, extensions, sessions, bookmarks and old settings.",
                "If the browser is no longer used, uninstall it cleanly, then remove leftover profiles after backup. Debian/Ubuntu examples: apt purge brave-browser firefox-esr firefox chromium; Flatpak: flatpak uninstall <app-id>; Tor/Mullvad tarball: remove the extracted folder after saving useful data.",
                "https://support.mozilla.org/kb/profiles-where-firefox-stores-user-data",
            ),
            "de": (
                "Browser-Profile können nach einer Deinstallation oder manuellem Verschieben zurückbleiben. Sie beweisen nicht, dass der Browser noch installiert ist, können aber Cookies, Cache, lokalen Speicher, Erweiterungen, Sitzungen, Lesezeichen und alte Einstellungen enthalten.",
                "Wenn der Browser nicht mehr genutzt wird, sauber deinstallieren und Restprofile nach Sicherung löschen. Debian/Ubuntu-Beispiele: apt purge brave-browser firefox-esr firefox chromium; Flatpak: flatpak uninstall <app-id>; Tor/Mullvad-Tarball: entpackten Ordner nach Sicherung nützlicher Daten entfernen.",
                "https://support.mozilla.org/kb/profiles-where-firefox-stores-user-data",
            ),
        }[lang]
    if f.key.endswith('.prefs') or 'firefox' in f.key or 'chromium' in f.key or 'browser' in f.key:
        return {
            "fr": (
                "Les réglages navigateur influencent fortement le tracking, le fingerprinting, WebRTC, la télémétrie et les cookies.",
                "Vérifier dans l'interface du navigateur et, pour Firefox/LibreWolf, dans about:config: privacy.resistFingerprinting, media.peerconnection.enabled, télémétrie et DNS/DoH.",
                "https://support.mozilla.org/kb/privacy-and-security-settings",
            ),
            "en": (
                "Browser settings strongly affect tracking, fingerprinting, WebRTC, telemetry and cookies.",
                "Check the browser UI and, for Firefox/LibreWolf, about:config: privacy.resistFingerprinting, media.peerconnection.enabled, telemetry and DNS/DoH.",
                "https://support.mozilla.org/kb/privacy-and-security-settings",
            ),
            "de": (
                "Browser-Einstellungen beeinflussen Tracking, Fingerprinting, WebRTC, Telemetrie und Cookies stark.",
                "Im Browser und bei Firefox/LibreWolf in about:config prüfen: privacy.resistFingerprinting, media.peerconnection.enabled, Telemetrie und DNS/DoH.",
                "https://support.mozilla.org/kb/privacy-and-security-settings",
            ),
        }[lang]
    if f.key.startswith('extensions.'):
        return {
            "fr": (
                "Les extensions peuvent protéger, mais elles augmentent aussi la surface d'attaque et rendent parfois le profil plus unique.",
                "Garder peu d'extensions, préférer uBlock Origin/NoScript selon usage, et éviter les extensions qui lisent toutes les pages sans nécessité.",
                "https://support.mozilla.org/kb/tips-assessing-safety-extension",
            ),
            "en": (
                "Extensions can protect you, but they also increase attack surface and may make the browser profile more unique.",
                "Keep few extensions, prefer uBlock Origin/NoScript depending on usage, and avoid extensions that read every page without a real need.",
                "https://support.mozilla.org/kb/tips-assessing-safety-extension",
            ),
            "de": (
                "Erweiterungen können schützen, erhöhen aber auch die Angriffsfläche und können das Profil eindeutiger machen.",
                "Wenige Erweiterungen behalten, je nach Nutzung uBlock Origin/NoScript bevorzugen und Erweiterungen vermeiden, die unnötig alle Seiten lesen.",
                "https://support.mozilla.org/kb/tips-assessing-safety-extension",
            ),
        }[lang]
    if f.key == "scanner.commands_missing":
        return {
            "fr": (
                "Certaines commandes système améliorent la précision du scan, mais leur absence ne doit jamais faire planter l'application.",
                "Installer les paquets utiles selon la distribution. Sur Debian/Ubuntu: iproute2 pour ip/ss, util-linux pour lsblk/findmnt/swapon.",
                "",
            ),
            "en": (
                "Some system commands improve scan accuracy, but their absence should never crash the application.",
                "Install useful packages for your distribution. On Debian/Ubuntu: iproute2 for ip/ss, util-linux for lsblk/findmnt/swapon.",
                "",
            ),
            "de": (
                "Einige Systembefehle verbessern die Genauigkeit des Scans, aber ihr Fehlen darf die Anwendung nie abstürzen lassen.",
                "Nützliche Pakete passend zur Distribution installieren. Unter Debian/Ubuntu: iproute2 für ip/ss, util-linux für lsblk/findmnt/swapon.",
                "",
            ),
        }[lang]
    if lang == "fr":
        return ("", f.recommendation or "", "")
    return ("", "", "")


def render_title(f: Finding, lang: str = "fr") -> str:
    lang = normalize_lang(lang)
    if lang == "fr":
        return f.title
                                                                   
    if f.key == "updates.status":
        ev = f.evidence or ""
        if "effective_upgradable=0" in ev and "held_upgradable=" in ev and "held_upgradable=0" not in ev:
            return "Pending packages are held intentionally" if lang == "en" else "Ausstehende Pakete werden absichtlich gehalten"
        if f.status == Severity.OK:
            return "No clear pending package update" if lang == "en" else "Keine eindeutig ausstehenden Paketupdates"
        if f.status == Severity.WARN:
            return "Packages pending update detected" if lang == "en" else "Ausstehende Paketupdates erkannt"
        return "Update status could not be checked" if lang == "en" else "Update-Status konnte nicht geprüft werden"
    if f.key == "home.permissions":
        if f.status == Severity.OK:
            return "Home directory permissions look correct" if lang == "en" else "Berechtigungen des Home-Verzeichnisses wirken korrekt"
        if f.status == Severity.INFO:
            return "Home directory is open, but no other human user was detected" if lang == "en" else "Home-Verzeichnis ist offen, aber kein weiterer menschlicher Benutzer wurde erkannt"
        return "Home directory is readable by other local users" if lang == "en" else "Home-Verzeichnis ist für andere lokale Benutzer lesbar"
    if f.key == "dns.servers":
        mapping = {
            "DNS local détecté": ("Local DNS detected", "Lokales DNS erkannt"),
            "DNS public plutôt favorable détecté": ("Rather privacy-friendly public DNS detected", "Eher datenschutzfreundliches öffentliches DNS erkannt"),
            "DNS public favorable à la vie privée détecté": ("Privacy-friendly public DNS detected", "Datenschutzfreundliches öffentliches DNS erkannt"),
            "DNS fourni par un VPN ou fournisseur privacy détecté": ("VPN or privacy provider DNS detected", "VPN- oder Privacy-DNS erkannt"),
            "DNS privé ou VPN probable détecté": ("Private or likely VPN DNS detected", "Privates oder wahrscheinliches VPN-DNS erkannt"),
            "DNS public acceptable mais à nuancer détecté": ("Acceptable public DNS detected, with caveats", "Akzeptables öffentliches DNS erkannt, mit Einschränkungen"),
            "DNS peu favorable à la vie privée détecté": ("Less privacy-friendly DNS detected", "Weniger datenschutzfreundliches DNS erkannt"),
            "DNS obsolète ou abandonné détecté": ("Deprecated or discontinued DNS detected", "Veraltetes oder eingestelltes DNS erkannt"),
            "DNS Google détecté": ("Google DNS detected", "Google-DNS erkannt"),
            "DNS du réseau local/routeur détecté": ("Local network/router DNS detected", "DNS des lokalen Netzwerks/Routers erkannt"),
            "DNS détecté mais non classé": ("DNS detected but not classified", "DNS erkannt, aber nicht klassifiziert"),
            "DNS non détecté": ("DNS not detected", "DNS nicht erkannt"),
        }
        if f.title in mapping:
            return mapping[f.title][0 if lang == "en" else 1]
    if f.key == "vpn.provider.amnezia":
        return "Amnezia VPN provider detected" if lang == "en" else "Amnezia-VPN-Anbieter erkannt"
    if f.key == "vpn.provider.nym":
        return "Nym VPN provider detected" if lang == "en" else "Nym-VPN-Anbieter erkannt"
    if f.key == "librewolf.detected":
        return "LibreWolf browser detected" if lang == "en" else "LibreWolf-Browser erkannt"
    if f.key.startswith("browser.inventory."):
        browser_id = f.key.rsplit(".", 1)[-1]
        labels_en = {
            "brave": "Brave browser detected",
            "firefox": "Firefox browser detected",
            "chromium": "Chromium browser detected",
            "chrome": "Google Chrome browser detected",
            "edge": "Microsoft Edge browser detected",
            "opera": "Opera browser detected",
            "vivaldi": "Vivaldi browser detected",
        }
        labels_de = {
            "brave": "Brave-Browser erkannt",
            "firefox": "Firefox-Browser erkannt",
            "chromium": "Chromium-Browser erkannt",
            "chrome": "Google-Chrome-Browser erkannt",
            "edge": "Microsoft-Edge-Browser erkannt",
            "opera": "Opera-Browser erkannt",
            "vivaldi": "Vivaldi-Browser erkannt",
        }
        return labels_en.get(browser_id, "Browser detected") if lang == "en" else labels_de.get(browser_id, "Browser erkannt")
    if f.key == "scanner.commands_missing":
        return "Useful system commands are missing" if lang == "en" else "Nützliche Systembefehle fehlen"
    if f.key.endswith(".prefs"):
        product = f.key.removesuffix(".prefs").replace("-", " ").title()
        if "standard" in f.title.lower() or f.status == Severity.INFO:
            return f"Standard {product} settings observed" if lang == "en" else f"Standard-Einstellungen von {product} erkannt"
        if f.status == Severity.OK:
            return f"{product} settings look favorable" if lang == "en" else f"{product}-Einstellungen wirken günstig"
        return f"{product} settings should be checked" if lang == "en" else f"{product}-Einstellungen sollten geprüft werden"
    if f.key in {"brave.prefs", "chromium.prefs", "chrome.prefs", "edge.prefs", "vivaldi.prefs", "opera.prefs"}:
        product = f.key.split(".", 1)[0].title()
        return f"{product} profile detected" if lang == "en" else f"{product}-Profil erkannt"
    if f.key == "services.open_ports_review":
        return "Open ports should be reviewed" if lang == "en" else "Offene Ports sollten geprüft werden"
    if f.key == "services.lan_discovery":
        return "LAN/local discovery services detected" if lang == "en" else "LAN-/lokale Erkennungsdienste erkannt"
    if f.key == "services.no_risky_exposed":
        return "No obvious sensitive or unexpected network port" if lang == "en" else "Kein offensichtlich sensibler oder unerwarteter Netzwerk-Port"
    if f.key == "services.exposed":
        return "Sensitive ports listening on the network" if lang == "en" else "Sensible Ports lauschen im Netzwerk"
    if f.key == "services.vpn_owned_udp":
        return "Ports linked to VPN or tunnel detected" if lang == "en" else "Ports mit VPN oder Tunnel erkannt"
    if f.key == "services.client_udp":
        return "Client or dynamic UDP sockets detected" if lang == "en" else "Client- oder dynamische UDP-Sockets erkannt"
    if f.key == "search_engine.privacy_strong":
        return "Very privacy-friendly search engine detected" if lang == "en" else "Sehr datenschutzfreundliche Suchmaschine erkannt"
    if f.key == "search_engine.privacy_good":
        return "Rather privacy-friendly search engine detected" if lang == "en" else "Eher datenschutzfreundliche Suchmaschine erkannt"
    if f.key == "search_engine.mixed":
        return "Mixed search engines detected" if lang == "en" else "Gemischte Suchmaschinen erkannt"
    if f.key == "search_engine.avoid":
        return "Less privacy-friendly search engine detected" if lang == "en" else "Weniger datenschutzfreundliche Suchmaschine erkannt"
    if f.key == "search_engine.unknown":
        return "Default search engine could not be determined locally" if lang == "en" else "Standardsuchmaschine konnte lokal nicht bestimmt werden"
                                  
    translated = i18n_text(lang, f.title)
    if translated != f.title:
        return translated
                                                                         
    return f.key.replace(".", " / ").replace("_", " ").title()


def translate_evidence(value: str, lang: str = "fr") -> str:
    lang = normalize_lang(lang)
    if lang == "fr" or not value:
        return value
    import re

    phrase_replacements = {
        "en": {
            "keepassxc/pass/bitwarden absents du PATH, des lanceurs .desktop et de Flatpak": "keepassxc/pass/bitwarden absent from PATH, desktop launchers and Flatpak",
            "ufw/nft/iptables non actifs ou non lisibles": "ufw/nft/iptables not active or not readable",
            "swapon --show vide": "swapon --show empty",
            "commande/desktop/profil": "command/desktop/profile",
            "commande/desktop": "command/desktop",
            "profil Tor Browser détecté": "Tor Browser profile detected",
            "profil Mullvad Browser détecté": "Mullvad Browser profile detected",
            "non lisible": "not readable",
            "non concluants": "not conclusive",
            "checkupdates indisponible": "checkupdates unavailable",
            "aucune": "none",
            "aucun": "none", "autres": "others", "en écoute": "listening",
        },
        "de": {
            "keepassxc/pass/bitwarden absents du PATH, des lanceurs .desktop et de Flatpak": "keepassxc/pass/bitwarden fehlen in PATH, Desktop-Startern und Flatpak",
            "ufw/nft/iptables non actifs ou non lisibles": "ufw/nft/iptables nicht aktiv oder nicht lesbar",
            "swapon --show vide": "swapon --show leer",
            "commande/desktop/profil": "Befehl/Desktop/Profil",
            "commande/desktop": "Befehl/Desktop",
            "profil Tor Browser détecté": "Tor-Browser-Profil erkannt",
            "profil Mullvad Browser détecté": "Mullvad-Browser-Profil erkannt",
            "non lisible": "nicht lesbar",
            "non concluants": "nicht schlüssig",
            "checkupdates indisponible": "checkupdates nicht verfügbar",
            "aucune": "keine",
            "aucun": "keine", "autres": "andere", "en écoute": "lauscht",
        },
    }
    out = value
    for src, dst in phrase_replacements[lang].items():
        out = out.replace(src, dst)
    word_replacements = {
        "en": {"oui": "yes", "non": "no", "inconnu": "unknown", "autres_utilisateurs": "other_users"},
        "de": {"oui": "ja", "non": "nein", "inconnu": "unbekannt", "autres_utilisateurs": "andere_benutzer"},
    }
    for src, dst in word_replacements[lang].items():
        out = re.sub(rf"(?<![A-Za-zÀ-ÿ_]){re.escape(src)}(?![A-Za-zÀ-ÿ_])", dst, out)
    return out


def status_label(status: Severity, lang: str = "fr") -> str:
    return i18n_status(lang, status.value)


def paint(text: str, status: Severity, color: bool) -> str:
    if not color:
        return text
    return f"{COLORS.get(status, '')}{text}{RESET}"




def _terminal_width(default: int = 112) -> int:
    try:
        import shutil
        return max(88, min(140, shutil.get_terminal_size((default, 24)).columns))
    except Exception:
        return default


GRID_COLOR = "\033[32m"


def _grid_part(text: str, *, color: bool) -> str:
    if not color:
        return text
    return f"{GRID_COLOR}{text}{RESET}"


def _wrap_lines(text: str, width: int) -> list[str]:
    import textwrap
    if text is None:
        return []
    raw = str(text)
    if not raw:
        return []
    out: list[str] = []
    for para in raw.splitlines() or [raw]:
        if not para:
            out.append("")
            continue
        wrapped = textwrap.wrap(
            para,
            width=width,
            break_long_words=False,
            break_on_hyphens=False,
            replace_whitespace=False,
        )
        out.extend(wrapped or [para])
    return out


def _finding_information_lines(f: Finding, scores_txt: str, *, verbose: bool, lang: str, info_width: int) -> list[str]:
    title = render_title(f, lang).upper()
    if scores_txt:
        title = f"{title} ({scores_txt})"
    lines = _wrap_lines(title, info_width)

    def add_field(label: str, value: str) -> None:
        if not value:
            return
        translated = str(value)
        prefix = f"{label} : "
        value_width = max(20, info_width - len(prefix))
        parts: list[str] = []
        for idx, raw_line in enumerate(translated.splitlines() or [translated]):
            wrapped = _wrap_lines(raw_line, value_width)
            if not wrapped:
                wrapped = [""]
            for j, w in enumerate(wrapped):
                if idx == 0 and j == 0:
                    parts.append(prefix + w)
                else:
                    parts.append(" " * len(prefix) + w)
        lines.extend(parts)

    if f.evidence:
        add_field(ui(lang, 'evidence'), translate_evidence(f.evidence, lang))
    if verbose:
        why, solution, link = didactic_for(f, lang)
        add_field(ui(lang, 'why'), why)
        add_field(ui(lang, 'solution'), solution)
        add_field(ui(lang, 'learn_more'), link)
    return lines or [""]


def _print_grid_row(left: str, right_lines: list[str], *, left_width: int, right_width: int, status: Severity | None, color: bool) -> None:
    if not right_lines:
        right_lines = [""]
    for i, right in enumerate(right_lines):
        raw_left = left if i == 0 else ""
        shown_left = raw_left[:left_width].ljust(left_width)
        if i == 0 and status is not None:
            shown_left = paint(shown_left, status, color)
        shown_right = right[:right_width].ljust(right_width)
        print(
            _grid_part("┃ ", color=color)
            + shown_left
            + _grid_part(" ┃ ", color=color)
            + shown_right
            + _grid_part(" ┃", color=color)
        )


def _print_grid_rule(kind: str, *, left_width: int, right_width: int, color: bool) -> None:
    chars = {
        "top": ("┏", "┳", "┓", "━"),
        "header": ("┡", "╇", "┩", "━"),
        "row": ("┣", "╋", "┫", "━"),
        "category": ("╠", "╬", "╣", "═"),
        "bottom": ("┗", "┻", "┛", "━"),
    }[kind]
    l, m, r, h = chars
    print(_grid_part(l + h * (left_width + 2) + m + h * (right_width + 2) + r, color=color))


def _print_category_row(category: str, *, left_width: int, right_width: int, color: bool) -> None:
    label = f"[{category}]"
    content = ""
    _print_grid_row(label, [content], left_width=left_width, right_width=right_width, status=None, color=color)


def print_report(ctx: ScanContext, scores: ScoreBundle, *, color: bool = True, verbose: bool = False, lang: str = "fr") -> None:
    lang = normalize_lang(lang)
    print(f"\n{ui(lang, 'title')}")
    print("=" * 28)
    print(f"{ui(lang, 'os_detected'):16}: {ctx.distro_pretty_name}")
    print(f"{ui(lang, 'pkg_manager'):16}: {ctx.package_manager}")
    print()
    print(f"{ui(lang, 'privacy_index'):16}: {scores.privacy}/20")
    print(f"{ui(lang, 'anonymity_index'):16}: {scores.anonymity}/20")
    print(f"{ui(lang, 'hardening_index'):16}: {scores.hardening}/20")
    print(f"{ui(lang, 'global_index'):16}: {scores.global_score}/20")
    print(f"{ui(lang, 'scan_confidence'):16}: {scores.confidence}")
    print()

    term_width = _terminal_width()
    left_width = 12
    right_width = max(54, term_width - left_width - 9)

    _print_grid_rule("top", left_width=left_width, right_width=right_width, color=color)
    _print_grid_row(ui(lang, 'status') if ui(lang, 'status') != 'status' else 'STATUS', [ui(lang, 'information') if ui(lang, 'information') != 'information' else 'INFORMATION'], left_width=left_width, right_width=right_width, status=None, color=color)
    _print_grid_rule("header", left_width=left_width, right_width=right_width, color=color)

    categories = sorted({f.category for f in ctx.findings})
    first_category = True
    for category in categories:
        if not first_category:
            _print_grid_rule("category", left_width=left_width, right_width=right_width, color=color)
        first_category = False
        _print_category_row(category, left_width=left_width, right_width=right_width, color=color)
        _print_grid_rule("row", left_width=left_width, right_width=right_width, color=color)
        items = [x for x in ctx.findings if x.category == category]
        for idx, f in enumerate(items):
            score_bits = []
            if f.privacy:
                score_bits.append(f"P{f.privacy:+d}")
            if f.anonymity:
                score_bits.append(f"A{f.anonymity:+d}")
            if f.hardening:
                score_bits.append(f"H{f.hardening:+d}")
            scores_txt = " ".join(score_bits)
            label = status_label(f.status, lang).upper()
            info_lines = _finding_information_lines(f, scores_txt, verbose=verbose, lang=lang, info_width=right_width)
            _print_grid_row(label, info_lines, left_width=left_width, right_width=right_width, status=f.status, color=color)
            if idx != len(items) - 1:
                _print_grid_rule("row", left_width=left_width, right_width=right_width, color=color)
    _print_grid_rule("bottom", left_width=left_width, right_width=right_width, color=color)
    print()


def _finding_to_translated_dict(f: Finding, lang: str) -> dict[str, object]:
    data = f.to_dict()
    data["status_label"] = status_label(f.status, lang)
    data["title"] = render_title(f, lang)
    data["evidence"] = translate_evidence(f.evidence, lang)
    why, solution, link = didactic_for(f, lang)
    data["why"] = why
    data["solution"] = solution
    data["learn_more"] = link
    return data


def export_json(path: Path, ctx: ScanContext, scores: ScoreBundle, lang: str = "en") -> None:
    lang = normalize_lang(lang)
    data = {
        "version": "2.9",
        "language": lang,
        "os": {
            "id": ctx.os_id,
            "like": ctx.os_like,
            "pretty_name": ctx.distro_pretty_name,
            "package_manager": ctx.package_manager,
        },
        "scores": scores.to_dict(),
        "facts": ctx.facts,
        "findings": [_finding_to_translated_dict(f, lang) for f in ctx.findings],
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def export_csv(path: Path, findings: list[Finding], lang: str = "en") -> None:
    lang = normalize_lang(lang)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "key", "status", "privacy", "anonymity", "hardening", "title", "evidence", "why", "solution", "learn_more", "confidence"])
        for item in findings:
            why, solution, link = didactic_for(item, lang)
            w.writerow([
                item.category,
                item.key,
                status_label(item.status, lang),
                item.privacy,
                item.anonymity,
                item.hardening,
                render_title(item, lang),
                translate_evidence(item.evidence, lang),
                why,
                solution,
                link,
                item.confidence,
            ])
