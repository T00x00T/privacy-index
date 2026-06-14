from __future__ import annotations

import json
from pathlib import Path
from privacy_index.core.models import Finding, ScanContext, Severity
from privacy_index.core.utils import run_cmd, read_text_safe


def _lsblk_json() -> dict:
    rc, out, _ = run_cmd(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS,PKNAME"], timeout=3)
    if rc != 0 or not out:
        return {}
    try:
        return json.loads(out)
    except Exception:
        return {}


def _walk(devices: list[dict]):
    for d in devices:
        yield d
        yield from _walk(d.get("children", []) or [])


def scan(ctx: ScanContext) -> None:
    rc, root_src, _ = run_cmd(["findmnt", "-n", "-o", "SOURCE", "/"], timeout=2)
    root_src = root_src.strip() if rc == 0 else ""
    data = _lsblk_json()
    devices = list(_walk(data.get("blockdevices", []) or []))
    luks_devices = [d for d in devices if str(d.get("fstype", "")).lower() == "crypto_luks"]
    crypt_mappers = [d for d in devices if str(d.get("type", "")).lower() == "crypt"]
    root_encrypted = False
    evidence = f"root={root_src}; luks={[d.get('name') for d in luks_devices]}; crypt={[d.get('name') for d in crypt_mappers]}"

    if root_src.startswith("/dev/mapper/") or crypt_mappers:
        root_encrypted = True
    if luks_devices and any(d.get("mountpoints") and "/" in d.get("mountpoints") for d in crypt_mappers):
        root_encrypted = True

    ctx.fact("disk.root_source", root_src)
    ctx.fact("disk.luks_devices", [d.get("name") for d in luks_devices])
    ctx.fact("disk.crypt_mappers", [d.get("name") for d in crypt_mappers])

    if root_encrypted:
        ctx.add(Finding(
            category="disk",
            key="disk.root_encrypted",
            title="Chiffrement du disque système détecté",
            status=Severity.OK,
            privacy=3,
            hardening=5,
            evidence=evidence,
            recommendation="Bien. Vérifier aussi le chiffrement du swap et les sauvegardes.",
            confidence="medium",
        ))
    else:
        ctx.add(Finding(
            category="disk",
            key="disk.root_unencrypted",
            title="Aucun chiffrement clair du disque système détecté",
            status=Severity.BAD,
            privacy=-3,
            hardening=-3,
            evidence=evidence,
            recommendation="Sur Linux: préférer LUKS/dm-crypt pour la racine. VeraCrypt est utile pour conteneurs/volumes, LUKS reste le standard Linux pour le système.",
            confidence="medium",
        ))

    rc, swap_out, _ = run_cmd(["swapon", "--show=NAME,TYPE"], timeout=2)
    swaps = [line.split()[0] for line in swap_out.splitlines()[1:] if line.strip()] if rc == 0 else []
    if not swaps:
        ctx.add(Finding(
            category="disk",
            key="swap.none",
            title="Aucun swap actif détecté",
            status=Severity.INFO,
            privacy=0,
            hardening=0,
            evidence="swapon --show vide",
            recommendation="Pas forcément un problème. Si swap actif, il devrait être chiffré.",
            confidence="high",
        ))
    else:
        crypttab = read_text_safe(Path("/etc/crypttab"))
        encrypted_swap = any("swap" in line.lower() for line in crypttab.splitlines()) or any(s.startswith("/dev/mapper/") for s in swaps)
        ctx.add(Finding(
            category="disk",
            key="swap.encryption",
            title="Swap probablement chiffré" if encrypted_swap else "Swap actif sans chiffrement évident",
            status=Severity.OK if encrypted_swap else Severity.WARN,
            privacy=1 if encrypted_swap else 0,
            hardening=2 if encrypted_swap else 0,
            evidence=f"swap={swaps}; crypttab_swap={encrypted_swap}",
            recommendation="Un swap non chiffré peut contenir des fragments de mémoire sensibles. Avec une racine LUKS, le risque dépend de la topologie exacte: à vérifier manuellement si le swap est inclus dans le volume chiffré.",
            confidence="medium",
        ))
