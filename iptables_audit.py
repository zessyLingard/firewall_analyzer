#!/usr/bin/env python3
"""
iptables_audit.py

Audit file iptables (dinh dang iptables-save) theo checklist bao mat, dua
tren cac ham parse/predicate dung chung trong iptables_parser.py.

Checklist:

  1. DEFAULT POLICY (INPUT/OUTPUT)
     PASS neu thoa 1 trong 2:
       a) -P INPUT DROP  VA  -P OUTPUT DROP
       b) Policy la ACCEPT (hoac bat ky) nhung co rule tuong minh
          "-A INPUT -j DROP/REJECT" VA "-A OUTPUT -j DROP/REJECT"
     Neu khong thoa dieu kien nao -> FAIL.

  1c. THIEU RULE ESTABLISHED,RELATED catch-all: neu default policy la DROP
      (hoac tuong duong) va chain khong co rule ACCEPT nao match state
      ESTABLISHED/RELATED, host se khong nhan duoc traffic tra ve cua chinh
      cac ket noi outbound hop le no da khoi tao - day la ghi chu canh bao,
      khong phai loi bao mat, nhung thuong la dau hieu cau hinh sai/thieu sot.
      Ap dung cho INPUT, OUTPUT (khong check FORWARD).

  2. RULE LIEN QUAN SSH trong chain INPUT, target ACCEPT, KHONG phai loopback
     (-i lo), protocol tuong thich TCP (khong phai icmp/udp/esp...), trang thai
     la NEW hoac khong gioi han (rule chi ESTABLISHED,RELATED thi loai tru), gom
     2 truong hop:
       a) Match tuong minh port 22 (qua --dport/--sport/--dports/--sports
          hoac ten service "ssh")
       b) KHONG gioi han port nao ca -> mac nhien cho qua CA port 22
     Voi tap rule nay:
       - FAIL neu khong co "-m comment --comment ...", TRU KHI co truyen
         --admin-cidr VA source cua rule nam gon trong 1 trong cac dai quan tri do
       - FAIL neu khong co "-s <source>" (nghia la mo cho moi nguon 0.0.0.0/0)

  3. RULE CHAIN INPUT (3a) / OUTPUT (3b) khong gioi han port dich (list de soat
     thu cong, KHONG suy doan rule nao la SSH). Loai tru: loopback, protocol
     khong co khai niem port, rule chi ESTABLISHED,RELATED. Chi xet target
     ACCEPT. Dung has_dest_port_restriction (--dport/--dports), KHONG dung
     --sport (xem muc 6).
       - FAIL neu rule khong co --dport/--dports nao

  4. RULE CO DIA CHI KHONG GIOI HAN - source o INPUT / dest o OUTPUT khong
     gioi han (0.0.0.0/0 hoac tuong duong), AP DUNG CHO BAT KY PORT NAO, BAT KY
     PROTOCOL NAO (co gioi han hay khong deu tinh), voi trang thai la NEW hoac
     khong gioi han trang thai.

  5. (TUY CHON, can --admin-cidr) RULE SSH CO SOURCE NAM NGOAI TAT CA DAI QUAN
     TRI duoc khai bao. Ho tro NHIEU dai cung luc (--admin-cidr A B C ...),
     source chi can nam gon trong BAT KY 1 dai nao la PASS.

  6. RULE INPUT CHI DUNG --sport (KHONG --dport, KHONG state ESTABLISHED/
     RELATED) -> co the bi gia mao source port de truy cap MOI port dich.

Cach dung:
    python3 iptables_audit.py iptables.txt
    python3 iptables_audit.py iptables.txt --admin-cidr 10.0.0.0/24
    python3 iptables_audit.py iptables.txt --admin-cidr 10.0.0.0/24 192.168.1.0/24
"""

import sys
import argparse
import ipaddress

from iptables_parser import (
    load_rules,
    has_dest_port_restriction,
    has_source_restriction,
    is_loopback_interface,
    protocol_has_no_ports,
    is_state_new_or_unrestricted,
    is_fully_open_input,
    is_fully_open_output,
    is_ssh_relevant,
    is_spoofable_sport_only_input,
    source_within_admin_range,
    check_default_policy,
    has_established_related_catch_all,
)


def main():
    parser = argparse.ArgumentParser(
        description="Audit file iptables (dinh dang iptables-save)."
    )
    parser.add_argument("file", help="Duong dan file iptables can kiem tra")
    parser.add_argument(
        "--admin-cidr",
        dest="admin_cidr",
        nargs="+",
        default=None,
        help=(
            "1 hoac nhieu dai IP quan tri duoc phep SSH, vi du: "
            "--admin-cidr 10.0.0.0/24 192.168.1.0/24. "
            "Neu bo qua, se khong check muc 5."
        ),
    )
    args = parser.parse_args()

    admin_networks = []
    if args.admin_cidr:
        for cidr in args.admin_cidr:
            try:
                admin_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                print(f"[LOI] --admin-cidr khong hop le: {cidr} ({e})")
                sys.exit(1)

    def in_any_admin_range(r):
        return any(source_within_admin_range(r, net) for net in admin_networks)

    policies, rules_by_chain, all_rules = load_rules(args.file)

    # ---------- 1. Default policy ----------
    explicit_drop = {}
    for chain in ("INPUT", "OUTPUT"):
        chain_rules = rules_by_chain.get(chain, [])
        explicit_drop[chain] = any(r["target"] in ("DROP", "REJECT") for r in chain_rules)

    policy_ok, policy_reason = check_default_policy(policies, explicit_drop)

    # ---------- 1c. Thieu rule ESTABLISHED,RELATED catch-all ----------
    missing_estab = []
    for chain in ("INPUT", "OUTPUT"):
        chain_policy = policies.get(chain)
        chain_rules = rules_by_chain.get(chain, [])
        if not chain_rules and not chain_policy:
            continue  # chain khong xuat hien trong file, bo qua
        if chain_policy == "ACCEPT" and not explicit_drop.get(chain):
            continue  # policy la ACCEPT thuc su, khong can rule ESTABLISHED rieng
        if not has_established_related_catch_all(chain_rules):
            missing_estab.append(chain)

    # ---------- 2. SSH rules (thieu comment / mo source) ----------
    ssh_fail_no_comment = []
    ssh_fail_open_source = []

    for r in all_rules:
        if is_ssh_relevant(r):
            if not r["has_comment"]:
                if not admin_networks or not in_any_admin_range(r):
                    ssh_fail_no_comment.append(r["raw"])
            if not has_source_restriction(r):
                ssh_fail_open_source.append(r["raw"])

    # ---------- 3a. INPUT rules (target ACCEPT) khong gioi han port dich ----------
    # Rule chi co --sport (khong --dport) duoc tach rieng ra muc 6 (canh bao
    # spoofing cu the hon), khong lap lai o day.
    input_fail_no_port = []
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
                continue  # se duoc bao cao rieng o muc 6
            input_fail_no_port.append(r["raw"])

    # ---------- 3b. OUTPUT rules (target ACCEPT) khong gioi han port dich ----------
    output_fail_no_port = []
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

    # ---------- 4. Rule co dia chi khong gioi han (INPUT/OUTPUT) ----------
    input_fully_open = [
        r["raw"] for r in rules_by_chain.get("INPUT", []) if is_fully_open_input(r)
    ]
    output_fully_open = [
        r["raw"] for r in rules_by_chain.get("OUTPUT", []) if is_fully_open_output(r)
    ]

    # ---------- 5. SSH rule co source nam ngoai TAT CA dai quan tri ----------
    ssh_fail_outside_admin = []
    if admin_networks:
        for r in all_rules:
            if is_ssh_relevant(r) and not in_any_admin_range(r):
                ssh_fail_outside_admin.append(r["raw"])

    # ---------- 6. INPUT rule chi dung --sport, khong --dport, khong state ----------
    sport_spoofable = [
        r["raw"] for r in rules_by_chain.get("INPUT", []) if is_spoofable_sport_only_input(r)
    ]

    # ================= In ket qua =================
    print("=" * 70)
    print("1. KIEM TRA DEFAULT POLICY (INPUT/OUTPUT)")
    print("=" * 70)
    status = "PASS" if policy_ok else "FAIL"
    print(f"[{status}] {policy_reason}")

    print()
    print("=" * 70)
    print("1c. THIEU RULE ESTABLISHED,RELATED CATCH-ALL (ghi chu, khong phai loi bao mat)")
    print("=" * 70)
    if missing_estab:
        for chain in missing_estab:
            print(f"[CANH BAO] Chain {chain} (policy DROP/REJECT hoac tuong duong) khong co rule ACCEPT nao match ESTABLISHED/RELATED -> co the chan luon traffic tra ve hop le")
    else:
        print("[PASS] Cac chain co policy chan deu co rule ESTABLISHED,RELATED catch-all (hoac khong can, vi policy la ACCEPT)")

    print()
    print("=" * 70)
    print("2a. RULE SSH THIEU COMMENT")
    print("=" * 70)
    if ssh_fail_no_comment:
        for rule in ssh_fail_no_comment:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule SSH deu co comment (hoac da trong dai quan tri)")

    print()
    print("=" * 70)
    print("2b. RULE SSH MO KHONG GIOI HAN SOURCE (khong co -s)")
    print("=" * 70)
    if ssh_fail_open_source:
        for rule in ssh_fail_open_source:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule SSH deu gioi han source IP")

    print()
    print("=" * 70)
    print("3a. RULE CHAIN INPUT KHONG GIOI HAN PORT (list de soat thu cong)")
    print("=" * 70)
    if input_fail_no_port:
        for rule in input_fail_no_port:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule trong INPUT deu co gioi han port")

    print()
    print("=" * 70)
    print("3b. RULE CHAIN OUTPUT KHONG GIOI HAN PORT (list de soat thu cong)")
    print("=" * 70)
    if output_fail_no_port:
        for rule in output_fail_no_port:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Tat ca rule trong OUTPUT deu co gioi han port")

    print()
    print("=" * 70)
    print("4a. RULE INPUT CO DIA CHI NGUON KHONG GIOI HAN")
    print("    (bat ky port/protocol nao, state NEW/khong gioi han)")
    print("=" * 70)
    if input_fully_open:
        for rule in input_fully_open:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Khong co rule INPUT nao mo hoan toan")

    print()
    print("=" * 70)
    print("4b. RULE OUTPUT CO DIA CHI DICH KHONG GIOI HAN")
    print("    (bat ky port/protocol nao, state NEW/khong gioi han)")
    print("=" * 70)
    if output_fully_open:
        for rule in output_fully_open:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Khong co rule OUTPUT nao mo hoan toan")

    print()
    print("=" * 70)
    print("5. RULE SSH CO SOURCE NAM NGOAI DAI QUAN TRI (--admin-cidr)")
    print("=" * 70)
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
    print("=" * 70)
    print("6. RULE INPUT CHI DUNG --sport (KHONG --dport, KHONG state")
    print("   ESTABLISHED/RELATED) -> co the bi gia mao source port de")
    print("   truy cap MOI port dich tren host nay")
    print("=" * 70)
    if sport_spoofable:
        for rule in sport_spoofable:
            print(f"[FAIL] {rule}")
    else:
        print("[PASS] Khong co rule nao thuoc dang nay")

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