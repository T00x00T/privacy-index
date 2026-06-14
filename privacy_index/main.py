from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

                                                          
                                                     
                                                                                
if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from privacy_index.core.models import ScanContext
from privacy_index.core.report import print_report, export_csv, export_json
from privacy_index.core.scoring import compute_scores
from privacy_index.scanners import apps, browsers, disk, firewall, network, system
from privacy_index.browser_tests import run_browser_tests
from privacy_index.core.i18n import normalize_lang, ui


def run_scan() -> ScanContext:
    ctx = ScanContext()
                                                                    
    for scanner in [system, disk, network, firewall, browsers, apps]:
        try:
            scanner.scan(ctx)
        except Exception as exc:
                                                         
            from privacy_index.core.models import Finding, Severity
            ctx.add(Finding(
                category="scanner",
                key=f"scanner.{scanner.__name__}",
                title=f"Erreur dans le scanner {scanner.__name__}",
                status=Severity.UNKNOWN,
                evidence=str(exc),
                recommendation="Relancer avec --verbose ou corriger le scanner concerné.",
                confidence="low",
            ))
    return ctx


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="privacy-index",
        description="Local Linux privacy, anonymity and hardening audit.",
    )
    parser.add_argument("--json", dest="json_path", type=Path, help="Export the JSON report to this file")
    parser.add_argument("--csv", dest="csv_path", type=Path, help="Export CSV results to this file")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed explanations and remediation hints")
    parser.add_argument("--debug-facts", action="store_true", help="Show raw detected facts to debug false positives")
    parser.add_argument("--browser-tests", action="store_true", help="Offer optional browser tests. External tests require confirmation.")
    parser.add_argument("--test-browser", help="Browser to use for tests: firefox, librewolf, mullvad, brave, chromium, default, etc.")
    parser.add_argument("--yes", action="store_true", help="Answer yes to optional browser-test confirmations.")
    parser.add_argument("--lang", choices=["fr", "en", "de"], help="Interface language: fr, en or de. If omitted, the app asks in English.")
    parser.add_argument("--no-lang-prompt", action="store_true", help="Use English without asking for the interface language.")
    parser.add_argument("--no-sudo", action="store_true", help="Do not ask for sudo. Some root-owned listening processes may remain unknown.")
    parser.add_argument("--investigate-port", type=int, help="Run a focused extended ss investigation for one listening port, then exit.")
    parser.add_argument("--investigate-proto", choices=["udp", "tcp"], default="udp", help="Protocol for --investigate-port. Default: udp.")
    args = parser.parse_args()

    if args.lang:
        lang = normalize_lang(args.lang)
    elif args.no_lang_prompt:
        lang = "en"
    else:
                                                                       
        lang = normalize_lang(input(ui("en", "choose_language")).strip() or "en")

    if not args.no_sudo and os.geteuid() != 0 and shutil.which("sudo"):
                                                                                        
        print(ui(lang, "sudo_notice"))
        try:
            subprocess.run(["sudo", "-v"], timeout=90)
        except Exception:
            print(ui(lang, "sudo_failed"))

    if args.investigate_port:
        from privacy_index.scanners.firewall import investigate_port
        print(investigate_port(args.investigate_port, args.investigate_proto))
        return 0

    ctx = run_scan()
    scores = compute_scores(ctx.findings)
    print_report(ctx, scores, color=not args.no_color, verbose=args.verbose, lang=lang)

    if args.debug_facts:
        import json
        print(f"[debug:{ui(lang, 'debug_facts')}]")
        print(json.dumps(ctx.facts, ensure_ascii=False, indent=2, default=str))

    if args.browser_tests:
        run_browser_tests(assume_yes=args.yes, target=args.test_browser, lang=lang)

    if args.json_path:
        export_json(args.json_path, ctx, scores, lang=lang)
        print(f"{ui(lang, 'json_written')}: {args.json_path}")
    if args.csv_path:
        export_csv(args.csv_path, ctx.findings, lang=lang)
        print(f"{ui(lang, 'csv_written')}: {args.csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
