#!/usr/bin/env python3
"""
nftables_audit.py — 10-point security audit for nftables rulesets.

Usage:
    python nftables_audit.py <file> [--admin-cidr CIDR [CIDR ...]]

Checks (mirrors iptables_audit.py exactly):

  1.   Default INPUT/OUPUT policy — PASS if DROP/REJECT or explicit DROP/REJECT rule.
  1c.  Missing ESTABLISHED,RELATED catch-all (WARN, not FAIL).
  2a.  SSH rule missing comment (FAIL unless source in --admin-cidr).
  2b.  SSH rule open source 0.0.0.0/0 (FAIL).
  3a.  INPUT ACCEPT rule with no destination port restriction (FAIL).
  3b.  OUTPUT ACCEPT rule with no destination port restriction (FAIL).
  4a.  INPUT ACCEPT rule with unrestricted source + NEW state (FAIL).
  4b.  OUTPUT ACCEPT rule with unrestricted dest + NEW state (FAIL).
  5.   SSH source outside --admin-cidr (FAIL when --admin-cidr provided).
  6.   INPUT sport-only rule without ESTABLISHED,RELATED state (FAIL).
"""

import argparse
import ipaddress
import sys

from audit_predicates import (
    has_dest_port_restriction,
    has_source_restriction,
    has_established_related_catch_all,
    is_fully_open_input,
    is_fully_open_output,
    is_loopback_interface,
    is_spoofable_sport_only_input,
    is_ssh_relevant,
    is_state_new_or_unrestricted,
    protocol_has_no_ports,
    source_within_admin_range,
    check_default_policy,
)
from nftables_parser import load_rules


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Audit nftables ruleset — 10-point security checklist."
    )
    ap.add_argument("file", help="nftables ruleset file")
    ap.add_argument(
        "--admin-cidr",
        dest="admin_cidr",
        nargs="+",
        default=None,
        help="Trusted admin network(s) for SSH. E.g. --admin-cidr 10.0.0.0/8 192.168.1.0/24",
    )
    args = ap.parse_args()

    # Parse admin networks
    admin_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if args.admin_cidr:
        for cidr in args.admin_cidr:
            try:
                admin_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                print(f"[LOI] --admin-cidr khong hop le: {cidr} ({e})")
                sys.exit(1)

    def in_any_admin_range(r: dict) -> bool:
        return any(
            source_within_admin_range(r, net) for net in admin_networks
        )

    # Load rules
    policies, rules_by_chain, all_rules = load_rules(args.file)

    # ------------------------------------------------------------------ #
    #  Section 1 — Default policy
    # ------------------------------------------------------------------ #
    explicit_drop: dict[str, bool] = {}
    for chain in ("INPUT", "OUTPUT"):
        chain_rules = rules_by_chain.get(chain, [])
        explicit_drop[chain] = any(
            r["target"] in ("DROP", "REJECT") for r in chain_rules
        )

    policy_ok, policy_reason = check_default_policy(policies, explicit_drop)

    # ------------------------------------------------------------------ #
    #  Section 1c — Missing ESTABLISHED,RELATED catch-all
    # ------------------------------------------------------------------ #
    missing_estab: list[str] = []
    for chain in ("INPUT", "OUTPUT"):
        chain_policy = policies.get(chain)
        chain_rules = rules_by_chain.get(chain, [])
        if not chain_rules and not chain_policy:
            continue
        if chain_policy == "ACCEPT" and not explicit_drop.get(chain):
            continue
        if not has_established_related_catch_all(chain_rules):
            missing_estab.append(chain)

    # ------------------------------------------------------------------ #
    #  Section 2a — SSH rule missing comment
    # ------------------------------------------------------------------ #
    ssh_fail_no_comment: list[str] = []
    for r in all_rules:
        if is_ssh_relevant(r):
            if not r["has_comment"]:
                if not admin_networks or not in_any_admin_range(r):
                    ssh_fail_no_comment.append(r["raw"])

    # ------------------------------------------------------------------ #
    #  Section 2b — SSH rule open source
    # ------------------------------------------------------------------ #
    ssh_fail_open_source: list[str] = []
    for r in all_rules:
        if is_ssh_relevant(r):
            if not has_source_restriction(r):
                ssh_fail_open_source.append(r["raw"])

    # ------------------------------------------------------------------ #
    #  Section 3a — INPUT without destination port restriction
    # ------------------------------------------------------------------ #
    input_fail_no_port: list[str] = []
    for r in rules_by_chain.get("INPUT", []):
        if r.get("target") != "ACCEPT":
            continue
        if is_loopback_interface(r):
            continue
        if protocol_has_no_ports(r):
            continue
        if not is_state_new_or_unrestricted(r):
            continue
        if not has_dest_port_restriction(r):
            if is_spoofable_sport_only_input(r):
                continue   # reported in section 6
            input_fail_no_port.append(r["raw"])

    # ------------------------------------------------------------------ #
    #  Section 3b — OUTPUT without destination port restriction
    # ------------------------------------------------------------------ #
    output_fail_no_port: list[str] = []
    for r in rules_by_chain.get("OUTPUT", []):
        if r.get("target") != "ACCEPT":
            continue
        if is_loopback_interface(r):
            continue
        if protocol_has_no_ports(r):
            continue
        if not is_state_new_or_unrestricted(r):
            continue
        if not has_dest_port_restriction(r):
            output_fail_no_port.append(r["raw"])

    # ------------------------------------------------------------------ #
    #  Section 4a — INPUT fully open source
    # ------------------------------------------------------------------ #
    input_fully_open: list[str] = [
        r["raw"] for r in rules_by_chain.get("INPUT", [])
        if is_fully_open_input(r)
    ]

    # ------------------------------------------------------------------ #
    #  Section 4b — OUTPUT fully open dest
    # ------------------------------------------------------------------ #
    output_fully_open: list[str] = [
        r["raw"] for r in rules_by_chain.get("OUTPUT", [])
        if is_fully_open_output(r)
    ]

    # ------------------------------------------------------------------ #
    #  Section 5 — SSH outside admin range
    # ------------------------------------------------------------------ #
    ssh_fail_outside_admin: list[str] = []
    if admin_networks:
        for r in all_rules:
            if is_ssh_relevant(r) and not in_any_admin_range(r):
                ssh_fail_outside_admin.append(r["raw"])

    # ------------------------------------------------------------------ #
    #  Section 6 — INPUT sport-only spoofable rule
    # ------------------------------------------------------------------ #
    sport_spoofable: list[str] = [
        r["raw"] for r in rules_by_chain.get("INPUT", [])
        if is_spoofable_sport_only_input(r)
    ]

    # =================================================================== #
    #  Report
    # =================================================================== #
    sep = "=" * 70

    print(sep)
    print("1.  KIEM TRA DEFAULT POLICY (INPUT/OUTPUT)")
    print(sep)
    status = "PASS" if policy_ok else "FAIL"
    print(f"[{status}] {policy_reason}")

    print()
    print(sep)
    print("1c. THIEU RULE ESTABLISHED,RELATED CATCH-ALL")
    print("   (ghi chu, khong phai loi bao mat)")
    print(sep)
    if missing_estab:
        for chain in missing_estab:
            print(
                f"[CANH BAO] Chain {chain} (policy DROP/REJECT) khong co rule "
                f"ACCEPT match ESTABLISHED/RELATED -&gt; co the chan luon traffic tra ve hop le"
            )
    else:
        print("[PASS] Cac chain co policy chan deu co rule ESTABLISHED,RELATED "
              "catch-all (hoac khong can, vi policy la ACCEPT)")

    print()
    print(sep)
    print("2a. RULE SSH THIEU COMMENT")
    print(sep)
    if ssh_fail_no_comment:
        for rule in ssh_fail_no_comment:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule SSH deu co comment (hoac da trong dai quan tri)")

    print()
    print(sep)
    print("2b. RULE SSH MO KHONG GIOI HAN SOURCE (khong co -s)")
    print(sep)
    if ssh_fail_open_source:
        for rule in ssh_fail_open_source:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule SSH deu gioi han source IP")

    print()
    print(sep)
    print("3a. RULE CHAIN INPUT KHONG GIOI HAN PORT DICH")
    print("   (list de soat thu cong)")
    print(sep)
    if input_fail_no_port:
        for rule in input_fail_no_port:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule trong INPUT deu co gioi han port")

    print()
    print(sep)
    print("3b. RULE CHAIN OUTPUT KHONG GIOI HAN PORT DICH")
    print("   (list de soat thu cong)")
    print(sep)
    if output_fail_no_port:
        for rule in output_fail_no_port:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule trong OUTPUT deu co gioi han port")

    print()
    print(sep)
    print("4a. RULE INPUT CO DIA CHI NGUON KHONG GIOI HAN")
    print("    (bat ky port/protocol nao, state NEW/khong gioi han)")
    print(sep)
    if input_fully_open:
        for rule in input_fully_open:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Khong co rule INPUT nao mo hoan toan")

    print()
    print(sep)
    print("4b. RULE OUTPUT CO DIA CHI DICH KHONG GIOI HAN")
    print("    (bat ky port/protocol nao, state NEW/khong gioi han)")
    print(sep)
    if output_fully_open:
        for rule in output_fully_open:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Khong co rule OUTPUT nao mo hoan toan")

    print()
    print(sep)
    print("5.  RULE SSH CO SOURCE NAM NGOAI DAI QUAN TRI (--admin-cidr)")
    print(sep)
    if not admin_networks:
        print("[BO QUA] Khong truyen --admin-cidr nen khong check muc nay")
    elif ssh_fail_outside_admin:
        nets_str = ", ".join(str(n) for n in admin_networks)
        print(f"Dai quan tri duoc phep: {nets_str}")
        for rule in ssh_fail_outside_admin:
            print(f"[FAIL] {rule}")
    else:
        nets_str = ", ".join(str(n) for n in admin_networks)
        print(f"[PASS] Tat ca rule SSH deu chi cho phep tu dai quan tri: {nets_str}")

    print()
    print(sep)
    print("6.  RULE INPUT CHI DUNG --sport (KHONG --dport, KHONG state")
    print("    ESTABLISHED/RELATED) -&gt; co the bi gia mao source port de")
    print("    truy cap MOI port dich tren host nay")
    print(sep)
    if sport_spoofable:
        for rule in sport_spoofable:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Khong co rule nao thuoc dang nay")

    # Exit with non-zero if any hard FAIL sections (not WARN)
    has_fail = (
        not policy_ok
        or bool(ssh_fail_no_comment)
        or bool(ssh_fail_open_source)
        or bool(input_fail_no_port)
        or bool(output_fail_no_port)
        or bool(input_fully_open)
        or bool(output_fully_open)
        or bool(ssh_fail_outside_admin)
        or bool(sport_spoofable)
    )
    sys.exit(1 if has_fail else 0)


if __name__ == "__main__":
    main()
