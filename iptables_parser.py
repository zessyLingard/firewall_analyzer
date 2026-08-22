#!/usr/bin/env python3
"""
iptables_parser.py

Module dung chung: parse rule iptables-save thanh dict co cau truc, va cung
cap cac ham/predicate de nhan dien cac pattern rule theo checklist bao mat
(SSH lien quan, rule mo hoan toan, rule trong dai quan tri, v.v.)

Duoc dung boi:
  - iptables_audit.py     (audit 1 file theo checklist)
  - iptables_compare.py   (so sanh block *filter giua nhieu file)

Khong tu chay truc tiep; import cac ham can dung.
"""

import re
import shlex
import ipaddress


# =====================================================================
# 1. PARSE 1 DONG RULE
# =====================================================================

def parse_line(line):
    """Parse 1 dong rule '-A CHAIN ...' hoac '-I CHAIN ...' thanh dict tham so.
    Tra ve None neu dong khong phai rule -A/-I hop le."""
    tokens = shlex.split(line)
    parsed = {
        "raw": line.strip(),
        "chain": None,
        "target": None,
        "proto": None,
        "sport": None,
        "dport": None,
        "dports": None,
        "sports": None,
        "source": None,
        "dest": None,
        "src_range": None,
        "dst_range": None,
        "comment": None,
        "has_comment": False,
        "state": None,
        "in_interface": None,
        "out_interface": None,
        "is_negated": False,
    }

    if not tokens:
        return None

    if tokens[0] == "-A":
        parsed["chain"] = tokens[1]
        i = 2
    elif tokens[0] == "-I":
        parsed["chain"] = tokens[1]
        i = 2
        # -I CHAIN [rulenum] co the co so thu tu ngay sau
        if i < len(tokens) and tokens[i].isdigit():
            i += 1
    else:
        return None

    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-p", "--protocol"):
            parsed["proto"] = tokens[i + 1]
            i += 2
        elif tok == "!":
            # Negation applies to the next flag (e.g., "! -s 10.0.0.0/8")
            parsed["is_negated"] = True
            i += 1
        elif tok in ("-s", "--source"):
            parsed["source"] = tokens[i + 1]
            i += 2
        elif tok in ("-d", "--destination"):
            parsed["dest"] = tokens[i + 1]
            i += 2
        elif tok == "--dport":
            parsed["dport"] = tokens[i + 1]
            i += 2
        elif tok == "--sport":
            parsed["sport"] = tokens[i + 1]
            i += 2
        elif tok == "--dports":
            parsed["dports"] = tokens[i + 1]
            i += 2
        elif tok == "--sports":
            parsed["sports"] = tokens[i + 1]
            i += 2
        elif tok == "--src-range":
            parsed["src_range"] = tokens[i + 1]
            i += 2
        elif tok == "--dst-range":
            parsed["dst_range"] = tokens[i + 1]
            i += 2
        elif tok in ("-i", "--in-interface"):
            parsed["in_interface"] = tokens[i + 1]
            i += 2
        elif tok in ("-o", "--out-interface"):
            parsed["out_interface"] = tokens[i + 1]
            i += 2
        elif tok in ("--state", "--ctstate"):
            parsed["state"] = tokens[i + 1]
            i += 2
        elif tok == "--comment":
            parsed["comment"] = tokens[i + 1]
            parsed["has_comment"] = True
            i += 2
        elif tok in ("-j", "--jump"):
            parsed["target"] = tokens[i + 1]
            i += 2
        else:
            i += 1

    return parsed


def load_rules(filepath):
    """
    Doc file iptables-save, tra ve (policies, rules_by_chain, all_rules):
      - policies: dict {chain: policy} tu cac dong -P
      - rules_by_chain: dict {chain: [rule_dict, ...]}
      - all_rules: list phang toan bo rule_dict, giu nguyen thu tu trong file
    Chi doc trong pham vi block *filter (bo qua *nat/*mangle/*raw/...).
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    policies = {}
    rules_by_chain = {}
    all_rules = []
    in_filter = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("*"):
            in_filter = (line == "*filter")
            continue

        if not in_filter:
            continue

        if line == "COMMIT":
            in_filter = False
            continue

        if line.startswith("#"):
            continue

        if line.startswith(":"):
            # Dinh dang THAT cua iptables-save: ':CHAIN POLICY [pkts:bytes]'
            # Vi du: ':INPUT ACCEPT [0:0]'  hoac ':LOGGING - [0:0]' (chain
            # nguoi dung tu tao thi policy la '-', khong tinh la default policy).
            parts = line.split()
            if len(parts) >= 2:
                chain_name = parts[0][1:]  # bo dau ':'
                policy = parts[1]
                if policy != "-":
                    policies[chain_name] = policy
            continue

        if line.startswith("-P"):
            # Dinh dang dong lenh 'iptables -P CHAIN POLICY' (it gap trong
            # file export that, nhung van ho tro de tuong thich).
            parts = line.split()
            if len(parts) >= 3:
                policies[parts[1]] = parts[2]
            continue

        if line.startswith("-A") or line.startswith("-I"):
            parsed = parse_line(line)
            if parsed is None:
                continue
            rules_by_chain.setdefault(parsed["chain"], []).append(parsed)
            all_rules.append(parsed)

    return policies, rules_by_chain, all_rules


# =====================================================================
# 2. TRICH XUAT BLOCK *filter DANG THO (dung cho so sanh line-by-line)
# =====================================================================

def extract_filter_block(filepath):
    """
    Doc file, tra ve list cac dong tho (da normalize) thuoc block *filter,
    tinh tu dong '*filter' den dong 'COMMIT' tiep theo (khong bao gom
    chinh 2 dong do). Bo qua dong comment '#' va dong trong.
    Neu file khong co block *filter nao, tra ve list rong.
    Dung cho muc dich so sanh text line-by-line (khac voi load_rules() la
    parse thanh dict co cau truc de check semantic).
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw_lines = f.readlines()

    in_filter = False
    result = []
    found_filter = False

    for raw in raw_lines:
        line = raw.rstrip("\n").strip()

        if not line:
            continue

        if line.startswith("*"):
            in_filter = (line == "*filter")
            if in_filter:
                found_filter = True
            continue

        if not in_filter:
            continue

        if line == "COMMIT":
            in_filter = False
            continue

        if line.startswith("#"):
            continue

        result.append(normalize_line(line))

    if not found_filter:
        import sys
        print(f"[CANH BAO] Khong tim thay block '*filter' trong file: {filepath}",
              file=sys.stderr)

    return result


def normalize_line(line):
    """
    Chuan hoa 1 dong de so sanh, bo qua cac gia tri counter (packet/byte)
    thay doi giua cac lan export, khong lien quan toi config:
      - Dong chain declaration:  ':INPUT ACCEPT [307828:17543295]'
        -> ':INPUT ACCEPT [0:0]'
      - Dong rule co counter prefix (dinh dang -c): '[12:345] -A INPUT ...'
        -> '-A INPUT ...' (bo prefix counter)
    """
    m = re.match(r"^(:\S+\s+\S+)\s*\[\d+:\d+\]\s*$", line)
    if m:
        return f"{m.group(1)} [0:0]"

    m = re.match(r"^\[\d+:\d+\]\s*(-[AI]\s+.*)$", line)
    if m:
        return m.group(1)

    return line


# =====================================================================
# 3. CAC HANG SO / PREDICATE DUNG CHUNG CHO CHECKLIST
# =====================================================================

# Cac cach viet pho bien de the hien "moi dia chi" (khong gioi han), ngoai
# 0.0.0.0/0 con co the viet duoi dang netmask cu, dang rut gon, hay IPv6 any.
UNRESTRICTED_ADDR_PATTERNS = (
    "0.0.0.0/0",
    "0.0.0.0/0.0.0.0",
    "0/0",
    "0.0.0.0",  # mot so noi ghi tat khong kem /0, van hieu la khong gioi han
    "::/0",
    "::",
    "any",
    "all",
)

# Protocol khong co khai niem "port" (icmp, esp, ah, gre, vrrp...). Voi cac
# protocol nay, "khong gioi han port" la vo nghia, can loai khoi check port.
PORTLESS_PROTOCOLS = {"icmp", "icmpv6", "ipv6-icmp", "esp", "ah", "gre", "vrrp"}


def has_port_restriction(rule):
    """
    True neu rule co bat ky gioi han port nao (dport HOAC sport). Dung cho
    cac muc dich chung (vd is_ssh_relevant) noi chi can biet 'rule co nhac
    toi port 22 o dau do khong'.

    CANH BAO: KHONG dung ham nay de danh gia 'port dich (o chinh host nay)
    co bi gioi han hay khong' - vi --sport la port phia REMOTE tu khai bao,
    hoan toan co the gia mao, khong lien quan gi toi viec gioi han truy cap
    vao port nao cua host nay. Dung has_dest_port_restriction() cho muc dich do.
    """
    return any(rule.get(k) for k in ("dport", "sport", "dports", "sports"))


def has_dest_port_restriction(rule):
    """
    True neu rule gioi han PORT DICH (--dport/--dports) - tuc port dang bi
    truy cap tren chinh host nay (voi INPUT) hoac port dich tren remote
    (voi OUTPUT). Day moi la dieu kien thuc su co y nghia bao mat khi xet
    'port co bi gioi han hay khong', khac voi has_port_restriction() o tren.
    """
    return bool(rule.get("dport")) or bool(rule.get("dports"))


def is_spoofable_sport_only_input(rule):
    """
    Rule INPUT nguy hiem: chi dung --sport/--sports (khong co --dport), VA
    khong dung -m state/--ctstate ESTABLISHED/RELATED de xac thuc qua
    conntrack. Vi --sport la gia tri remote tu khai bao (de dang gia mao),
    rule dang thuc chat cho phep ket noi toi TAT CA port dich tren host nay,
    tu bat ky ai co the dat source port trung gia tri yeu cau - khong thuc
    su gioi han duoc gi ca du 'trong nhin' co ve da co port restriction.

    Rule an toan ("--sport X -m state --state ESTABLISHED,RELATED") thi
    KHONG bi tinh, vi conntrack da xac thuc day la traffic tra ve that su.
    """
    if rule.get("chain") != "INPUT":
        return False
    if rule.get("target") != "ACCEPT":
        return False
    has_sport = bool(rule.get("sport")) or bool(rule.get("sports"))
    if not has_sport:
        return False
    if has_dest_port_restriction(rule):
        return False  # da co --dport rieng, --sport chi la dieu kien phu
    state = rule.get("state")
    if state:
        states = [s.strip().upper() for s in state.split(",")]
        if "ESTABLISHED" in states or "RELATED" in states:
            return False  # dung conntrack xac thuc, an toan
    return True


def has_source_restriction(rule):
    """Rule co gioi han source khong: -s hoac -m iprange --src-range deu tinh."""
    return bool(rule.get("source")) or bool(rule.get("src_range"))


def has_dest_restriction(rule):
    """Rule co gioi han destination khong: -d hoac -m iprange --dst-range deu tinh."""
    return bool(rule.get("dest")) or bool(rule.get("dst_range"))


def is_unrestricted_address(addr):
    """
    True neu addr la None (khong khai bao -s/-d, mac dinh la moi dia chi)
    hoac la 1 trong cac cach viet pho bien cua 'moi dia chi' (khong chi rieng
    0.0.0.0/0).
    """
    if not addr:
        return True
    a = addr.strip().lower()
    return a in UNRESTRICTED_ADDR_PATTERNS


def is_protocol_unrestricted(rule):
    """True neu rule khong gioi han protocol (khong co -p, hoac -p all)."""
    proto = rule.get("proto")
    return not proto or proto.strip().lower() == "all"


def is_loopback_interface(rule):
    """True neu rule chi ap dung cho interface loopback (-i lo hoac -o lo)."""
    return rule.get("in_interface") == "lo" or rule.get("out_interface") == "lo"


def is_tcp_compatible(rule):
    """
    True neu protocol cua rule co the mang traffic SSH (TCP): khong khai bao
    -p (mac dinh moi protocol, bao gom ca tcp), hoac -p tcp/-p all tuong minh.
    False voi cac protocol khong phai TCP (icmp, udp, esp, ...) vi khong the
    mang traffic SSH thuc su.
    """
    proto = rule.get("proto")
    if not proto:
        return True
    p = proto.strip().lower()
    return p in ("tcp", "all", "6")


def protocol_has_no_ports(rule):
    """True neu protocol cua rule khong co khai niem 'port' (xem PORTLESS_PROTOCOLS)."""
    proto = rule.get("proto")
    if not proto:
        return False
    return proto.strip().lower() in PORTLESS_PROTOCOLS


def is_state_new_or_unrestricted(rule):
    """
    True neu trang thai ket noi la NEW (co the kem cac state khac) hoac
    rule khong dung -m state/--ctstate nao ca (mac nhien khop MOI trang thai,
    bao gom ca NEW).
    False neu rule chi gioi han o ESTABLISHED/RELATED (khong the tu khoi tao
    ket noi moi, nen khong tinh la nguy hiem).
    """
    state = rule.get("state")
    if not state:
        return True
    states = [s.strip().upper() for s in state.split(",")]
    return "NEW" in states


def matches_ssh_port(rule, ssh_port="22"):
    """Rule co gioi han port va port do trung/chua port 22 khong."""
    ports_to_check = []
    for key in ("dport", "sport"):
        if rule.get(key):
            ports_to_check.append(rule[key])
    for key in ("dports", "sports"):
        if rule.get(key):
            ports_to_check.extend(rule[key].split(","))

    for p in ports_to_check:
        p = p.strip()
        if p == ssh_port or p.lower() == "ssh":
            return True
        if ":" in p:
            lo, hi = p.split(":", 1)
            if lo.isdigit() and hi.isdigit() and int(lo) <= int(ssh_port) <= int(hi):
                return True
    return False


def is_ssh_relevant(rule, ssh_port="22"):
    """
    Rule duoc coi la 'lien quan SSH' (co the cho phep traffic SSH moi di qua) khi:
      - Nam trong chain INPUT VA co target ACCEPT, VA
      - KHONG phai rule chi danh cho loopback (-i lo), VA
      - Protocol tuong thich TCP (khong phai icmp/udp/esp/...), VA
      - Trang thai la NEW hoac khong gioi han trang thai (rule chi cho
        ESTABLISHED,RELATED thi KHONG tinh, vi khong the tu khoi tao SSH moi), VA
      - (match tuong minh port 22)  HOAC  (khong gioi han port nao ca)

    Rule khong gioi han port thi mac nhien cho qua CA port 22, nen van tinh
    la lien quan SSH du khong khai bao --dport 22 tuong minh.
    Rule co target DROP/REJECT thi khong xet (khong phai loi cho phep truy cap).
    """
    if rule.get("chain") != "INPUT":
        return False
    if rule.get("target") != "ACCEPT":
        return False
    if is_loopback_interface(rule):
        return False
    if not is_tcp_compatible(rule):
        return False
    if not is_state_new_or_unrestricted(rule):
        return False
    if has_port_restriction(rule):
        return matches_ssh_port(rule, ssh_port)
    return True


def is_fully_open_input(rule):
    """
    Rule INPUT co dia chi NGUON khong gioi han (0.0.0.0/0 hoac tuong duong),
    ap dung cho BAT KY port nao, BAT KY protocol nao (co gioi han hay khong
    deu tinh), voi trang thai la NEW hoac khong gioi han trang thai.

    Luu y: KHONG yeu cau port/protocol phai khong gioi han. Vi du rule
    "-A INPUT -p tcp --dport 22 -j ACCEPT" (khong co -s) van bi tinh la
    'nguon khong gioi han' du da gioi han port/protocol, vi ban chat van la
    cho phep BAT KY ai tren Internet ket noi toi port do.
    """
    if rule.get("chain") != "INPUT":
        return False
    if rule.get("target") != "ACCEPT":
        return False
    if is_loopback_interface(rule):
        return False
    if protocol_has_no_ports(rule):
        return False
    if rule.get("src_range"):
        return False
    if not is_unrestricted_address(rule.get("source")):
        return False
    return is_state_new_or_unrestricted(rule)


def is_fully_open_output(rule):
    """
    Rule OUTPUT co dia chi DICH khong gioi han (0.0.0.0/0 hoac tuong duong),
    ap dung cho BAT KY port nao, BAT KY protocol nao (co gioi han hay khong
    deu tinh), voi trang thai la NEW hoac khong gioi han trang thai.

    Luu y: KHONG yeu cau port/protocol phai khong gioi han. Vi du rule cho
    phep ket noi ra ngoai toi port 53/80/443 nhung khong gioi han -d van bi
    tinh la 'dich khong gioi han', vi ban chat van la cho phep ket noi toi
    BAT KY IP nao tren Internet o cac port do.
    """
    if rule.get("chain") != "OUTPUT":
        return False
    if rule.get("target") != "ACCEPT":
        return False
    if is_loopback_interface(rule):
        return False
    if protocol_has_no_ports(rule):
        return False
    if rule.get("dst_range"):
        return False
    if not is_unrestricted_address(rule.get("dest")):
        return False
    return is_state_new_or_unrestricted(rule)


def source_within_admin_range(rule, admin_network):
    """
    True neu source (hoac src_range) cua rule nam GON trong admin_network.
    False neu: khong co source (mo het), source khong parse duoc, source
    khac ho IP (v4 vs v6) voi admin_network, hoac source rong hon/khong
    nam gon trong admin_network.
    """
    src_range = rule.get("src_range")
    if src_range and "-" in src_range:
        start_str, end_str = src_range.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())
        except ValueError:
            return False
        try:
            return start_ip in admin_network and end_ip in admin_network
        except TypeError:
            return False

    source = rule.get("source")
    if not source:
        return False

    try:
        src_network = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return False

    try:
        return src_network.subnet_of(admin_network)
    except TypeError:
        return False


def check_default_policy(policies, explicit_drop):
    """
    policies: dict {chain: policy} tu cac dong -P
    explicit_drop: dict {chain: bool} co ton tai rule -j DROP/REJECT tuong minh khong
    Tra ve (passed: bool, ly_do: str)
    """
    input_policy = policies.get("INPUT")
    output_policy = policies.get("OUTPUT")

    if input_policy == "DROP" and output_policy == "DROP":
        return True, "Default policy INPUT/OUTPUT = DROP"

    if explicit_drop.get("INPUT") and explicit_drop.get("OUTPUT"):
        return True, "Co rule tuong minh '-j DROP'/'-j REJECT' o ca chain INPUT va OUTPUT"

    return False, (
        f"INPUT policy={input_policy}, OUTPUT policy={output_policy}, "
        f"INPUT co rule '-j DROP'/'-j REJECT' tuong minh={explicit_drop.get('INPUT', False)}, "
        f"OUTPUT co rule '-j DROP'/'-j REJECT' tuong minh={explicit_drop.get('OUTPUT', False)}"
    )


def is_broad_terminating_rule(rule):
    """
    True neu rule la 1 terminating rule (ACCEPT/DROP/REJECT) HOAN TOAN khong
    co dieu kien gi rang buoc (khong -s, khong -d, khong --dport, khong
    interface loopback, khong protocol portless, khong state restriction) -
    tuc no khop VOI MOI goi tin con lai chua bi rule truoc do xu ly, KE CA
    goi tin dau tien (NEW) cua 1 ket noi moi. Dung de phat hien loi thu tu
    rule: neu 1 rule nhu vay nam TRUOC cac rule khac trong cung chain, cac
    rule phia sau se KHONG BAO GIO duoc danh gia toi (dead rule).

    QUAN TRONG: rule co state restriction (vd chi ESTABLISHED,RELATED) KHONG
    duoc tinh la 'broad' - vi no chi khop traffic cua 1 ket noi DA co san,
    khong khop goi tin NEW dau tien, nen KHONG the lam "chet" cac rule phia
    sau doi voi ket noi moi (day la pattern chuan: ESTABLISHED,RELATED catch-all
    dung TRUOC 1 default-deny cuoi chain, hoan toan hop le, khong phai loi).
    """
    target = rule.get("target")
    if target not in ("ACCEPT", "DROP", "REJECT"):
        return False
    if is_loopback_interface(rule):
        return False
    if protocol_has_no_ports(rule):
        return False
    if rule.get("state"):
        return False  # co state restriction -> khong khop moi goi tin (vd NEW)
    if has_source_restriction(rule) or has_dest_restriction(rule):
        return False
    if has_dest_port_restriction(rule):
        return False
    return True


def find_unreachable_rules(chain_rules):
    """
    Duyet 1 chain theo dung thu tu trong file, tra ve list cac rule (dict) bi
    'chet' (khong bao gio duoc khop toi) vi co 1 broad terminating rule
    (xem is_broad_terminating_rule) xuat hien TRUOC no trong cung chain.
    Day la loi thu tu rule (rule ordering), khong phai loi tung rule rieng le.
    """
    unreachable = []
    seen_broad_terminator = False
    for r in chain_rules:
        if seen_broad_terminator:
            unreachable.append(r)
        if is_broad_terminating_rule(r):
            seen_broad_terminator = True
    return unreachable


def load_iptables(filepath):
    """
    Parse an iptables-save file and return a dict of Chain objects.

    Returns:
        dict[str, Chain] — maps chain name to Chain with default_policy and rules.
    """
    policies, rules_by_chain, _ = load_rules(filepath)
    from core_models import Chain, Rule, PortRange
    import ipaddress
    chains = {}
    for name, rule_list in rules_by_chain.items():
        c = Chain(table="filter", name=name, default_policy=policies.get(name))
        for rd in rule_list:
            src = [ipaddress.ip_network(rd["source"], strict=False)] if rd.get("source") else [ipaddress.ip_network("0.0.0.0/0")]
            dst = [ipaddress.ip_network(rd["dest"], strict=False)] if rd.get("dest") else [ipaddress.ip_network("0.0.0.0/0")]
            dports = []
            if rd.get("dport"):
                dports = [PortRange.parse(rd["dport"])]
            elif rd.get("dports"):
                dports = [PortRange.parse(p) for p in rd["dports"].split(",")]
            sports = []
            if rd.get("sport"):
                sports = [PortRange.parse(rd["sport"])]
            elif rd.get("sports"):
                sports = [PortRange.parse(p) for p in rd["sports"].split(",")]
            states = [rd["state"]] if rd.get("state") else []
            r = Rule(
                table="filter", chain=name,
                action=rd.get("target", "").upper(),
                in_interface=rd.get("in_interface"),
                out_interface=rd.get("out_interface"),
                sources=src, destinations=dst,
                ports=dports, source_ports=sports,
                states=states,
                protocol=rd.get("proto"),
                has_comment=rd.get("has_comment", False),
                raw_line=rd.get("raw", ""),
                line_number=0,
            )
            c.rules.append(r)
        chains[name] = c
    return chains


def has_established_related_catch_all(chain_rules):
    """
    True neu chain co it nhat 1 rule ACCEPT match state ESTABLISHED/RELATED
    (khong bat buoc phai la state DUY NHAT trong rule, chi can co mat trong
    danh sach state). Chain thieu rule nay se chan luon ca traffic tra ve cua
    cac ket noi outbound hop le, tru khi policy la ACCEPT (khi do khong can).
    """
    for r in chain_rules:
        if r.get("target") != "ACCEPT":
            continue
        state = r.get("state")
        if not state:
            continue
        states = [s.strip().upper() for s in state.split(",")]
        if "ESTABLISHED" in states or "RELATED" in states:
            return True
    return False