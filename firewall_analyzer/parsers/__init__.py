#!/usr/bin/env python3
"""
firewall_analyzer.parsers — unified parser entry point.

Auto-detects format and calls the appropriate parser.
All return dict[str, Chain].

Usage:
    from firewall_analyzer.parsers import load_rules
    chains = load_rules("rules.iptables")          # auto-detect
    chains = load_rules("rules.nft", format="nftables")  # explicit
"""

from __future__ import annotations

from firewall_analyzer.parsers import iptables, nftables, firewalld, ufw
from firewall_analyzer.models import Chain

_FORMAT_LOADERS = {
    "iptables":  iptables.load_iptables,
    "nftables":  nftables.load_nftables,
    "firewalld": firewalld.load_firewalld,
    "ufw":       ufw.load_ufw,
}


def detect_format(source) -> str:
    """
    Detect firewall format from file path or content.

    Args:
        source: file path (str) or text lines (list[str])

    Returns:
        "iptables" | "nftables" | "firewalld" | "ufw"
    """
    if isinstance(source, str):
        with open(source, encoding="utf-8", errors="ignore") as f:
            first_lines = [f.readline() for _ in range(10)]
        content = "".join(first_lines)
    else:
        content = "\n".join(source[:10])

    content_lower = content.lower()

    if "*filter" in content or "iptables-save" in content:
        return "iptables"
    if "chain {" in content or ("table " in content and "chain " in content):
        return "nftables"
    if "<zone" in content or "<direct>" in content or "<firewall-config>" in content:
        return "firewalld"
    if "status:" in content_lower and ("active" in content_lower or "inactive" in content_lower):
        return "ufw"
    if "<service" in content or "<port" in content or "<rule" in content:
        return "firewalld"

    return "unknown"


def load_rules(source, format: str = "auto") -> dict[str, Chain]:
    """
    Load firewall rules into Chain objects.

    Args:
        source: file path (str) or text lines (list[str])
        format: "auto" (detect) or one of "iptables", "nftables", "firewalld", "ufw"

    Returns:
        dict[str, Chain]

    Raises:
        ValueError: if format is unknown or not supported
    """
    if format == "auto":
        fmt = detect_format(source)
        if fmt == "unknown":
            raise ValueError(
                "Could not detect firewall format. "
                "Use load_rules(source, format='iptables'|'nftables'|'firewalld'|'ufw')"
            )
    else:
        fmt = format

    loader = _FORMAT_LOADERS.get(fmt)
    if loader is None:
        raise ValueError(f"Unknown format: {fmt!r}")

    return loader(source)


__all__ = ["load_rules", "detect_format"]
