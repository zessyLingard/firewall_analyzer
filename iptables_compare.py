#!/usr/bin/env python3
"""
iptables_compare.py

So sanh block *filter giua nhieu file iptables-save, theo tung CAP file lien
tiep: (file1,file2), (file2,file3), (file3,file4), ...

Dung ham extract_filter_block() tu iptables_parser.py (module dung chung voi
iptables_audit.py) de trich xuat va chuan hoa noi dung *filter truoc khi so
sanh, dam bao ca 2 script cung mot logic doc file iptables-save.

Cach dung:
    python3 iptables_compare.py file1.txt file2.txt file3.txt ... fileN.txt

Vi du 10 file a.txt b.txt ... j.txt:
    python3 iptables_compare.py a.txt b.txt c.txt d.txt e.txt f.txt g.txt h.txt i.txt j.txt

Script se so sanh a-b, b-c, c-d, ..., i-j va in ket qua tung cap.
"""

import sys
import difflib

from iptables_parser import extract_filter_block


def compare_pair(name_a, lines_a, name_b, lines_b):
    """In ra ket qua so sanh giua 2 file (dang unified diff)."""
    if lines_a == lines_b:
        print(f"[GIONG NHAU]  {name_a}  <->  {name_b}")
        return

    print(f"[KHAC NHAU]   {name_a}  <->  {name_b}")
    diff = difflib.unified_diff(
        lines_a, lines_b,
        fromfile=name_a, tofile=name_b,
        lineterm=""
    )
    for line in diff:
        print(f"    {line}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 iptables_compare.py file1.txt file2.txt [file3.txt ...]")
        sys.exit(1)

    filepaths = sys.argv[1:]

    extracted = {}
    for fp in filepaths:
        extracted[fp] = extract_filter_block(fp)

    print("=" * 70)
    print(f"So sanh block *filter cua {len(filepaths)} file, theo tung cap lien tiep")
    print("=" * 70)
    print()

    for i in range(len(filepaths) - 1):
        a, b = filepaths[i], filepaths[i + 1]
        compare_pair(a, extracted[a], b, extracted[b])
        print()


if __name__ == "__main__":
    main()
