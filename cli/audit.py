#!/usr/bin/env python3
"""
cli/audit.py — Unified audit CLI for all firewall formats.

Usage:
    python -m cli.audit firewalld.xml [--admin-cidr 10.0.0.0/8]
    python -m cli.audit rules.nft --format nftables
    python -m cli.audit ufw.status --format ufw
"""

import argparse
import sys

sys.stdout.reconfigure(encoding="utf-8")

from firewall_analyzer.parsers import load_rules
from firewall_analyzer.analyzer import run_audit


def main():
    ap = argparse.ArgumentParser(description="Firewall security audit (10-point checklist).")
    ap.add_argument("file", help="Firewall ruleset file")
    ap.add_argument(
        "--format",
        choices=["auto", "iptables", "nftables", "firewalld", "ufw"],
        default="auto",
        help="Firewall format (default: auto-detect)",
    )
    ap.add_argument(
        "--admin-cidr",
        dest="admin_cidr",
        nargs="+",
        default=None,
        help="Trusted admin network(s). E.g. --admin-cidr 10.0.0.0/8 192.168.1.0/24",
    )
    args = ap.parse_args()

    # Load
    try:
        chains = load_rules(args.file, format=args.format)
    except Exception as e:
        print(f"[LOI] Khong the parse {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    if not chains:
        print(f"[LOI] Khong tim thay chain nao trong {args.file}", file=sys.stderr)
        sys.exit(1)

    # Audit
    result = run_audit(chains, admin_cidrs=args.admin_cidr)

    # Print report
    sep = "=" * 70
    fmt = "auto" if args.format == "auto" else args.format
    print(f"\nAudit: {args.file}  [{fmt}]\n")

    print(sep)
    print("1.  DEFAULT POLICY (INPUT/OUTPUT)")
    print(sep)
    status = "PASS" if result.default_policy[0] else "FAIL"
    print(f"[{status}] {result.default_policy[1]}")

    print()
    print(sep)
    print("1c. THIEU RULE ESTABLISHED,RELATED CATCH-ALL")
    print("   (ghi chu, khong phai loi bao mat)")
    print(sep)
    if result.missing_estab:
        for chain in result.missing_estab:
            print(f"[CANH BAO] Chain {chain} khong co rule ACCEPT ESTABLISHED/RELATED")
    else:
        print("[PASS] Tat ca chain deu co rule ESTABLISHED,RELATED (hoac khong can)")

    def print_section(title, findings):
        print()
        print(sep)
        print(title)
        print(sep)
        if findings:
            for r in findings:
                print(f"[FAIL] {r}")
        else:
            print("[PASS] Khong co loi nao")

    print_section("2a. RULE SSH THIEU COMMENT", result.ssh_no_comment)
    print_section("2b. RULE SSH MO KHONG GIOI HAN SOURCE", result.ssh_open_source)
    print_section("3a. RULE INPUT KHONG GIOI HAN PORT DICH", result.input_no_port)
    print_section("3b. RULE OUTPUT KHONG GIOI HAN PORT DICH", result.output_no_port)
    print_section("4a. RULE INPUT MO HOA (UNRESTRICTED SOURCE + NEW)", result.input_fully_open)
    print_section("4b. RULE OUTPUT MO HOA (UNRESTRICTED DEST + NEW)", result.output_fully_open)

    print()
    print(sep)
    print("5.  RULE SSH CO SOURCE NAM NGOAI DAI QUAN TRI (--admin-cidr)")
    print(sep)
    if not args.admin_cidr:
        print("[BO QUA] Khong truyen --admin-cidr")
    elif result.ssh_outside_admin:
        print(f"Dai quan tri: {', '.join(args.admin_cidr)}")
        for r in result.ssh_outside_admin:
            print(f"[FAIL] {r}")
    else:
        nets = ", ".join(args.admin_cidr)
        print(f"[PASS] Tat ca rule SSH chi trong dai: {nets}")

    print_section("6.  RULE INPUT CHI DUNG --sport (SPOOFABLE)", result.sport_spoofable)

    sys.exit(1 if result.has_failures() else 0)


if __name__ == "__main__":
    main()
