"""
firewall_analyzer — Unified firewall security auditing toolkit.

Supports: iptables, nftables, firewalld, ufw

Usage:
    from firewall_analyzer import FirewallAnalyzer

    analyzer = FirewallAnalyzer("rules.iptables")
    analyzer.audit(admin_cidrs=["10.0.0.0/8"])
    analyzer.export("report.html", format="html")

Or for just audit:
    from firewall_analyzer.parsers import load_rules
    from firewall_analyzer.analyzer import run_audit

    chains = load_rules("rules.iptables")
    result = run_audit(chains, admin_cidrs=["10.0.0.0/8"])
"""

from __future__ import annotations

from typing import Literal

from firewall_analyzer.models import Chain, Rule, PortRange
from firewall_analyzer.export import export_html, export_sarif, export_audit_json, write_export
from firewall_analyzer.parsers import load_rules, detect_format
from firewall_analyzer.analyzer import run_audit, AuditResult


class FirewallAnalyzer:
    def __init__(self, filepath: str, format_type: str = "auto"):
        self.filepath = filepath
        self.format_type = format_type
        self.chains: dict[str, Chain] = {}
        self._audit_result: AuditResult | None = None
        self._load()

    def _load(self):
        self.chains = load_rules(self.filepath, format=self.format_type)
        if not self.chains:
            raise ValueError(f"No chains found in {self.filepath}")

    def reload(self):
        self._load()
        self._audit_result = None

    @property
    def chain_names(self) -> list[str]:
        return list(self.chains.keys())

    def get_chain(self, name: str) -> Chain | None:
        return self.chains.get(name)

    # ---- Security audit ----

    def audit(self, admin_cidrs: list[str] | None = None) -> AuditResult:
        self._audit_result = run_audit(self.chains, admin_cidrs=admin_cidrs)
        return self._audit_result

    # ---- Export ----

    def export(
        self,
        output_path: str,
        format: Literal["html", "sarif", "json"] = "html",
        include_audit: bool = True,
    ) -> str:
        audit_results = self._audit_result.to_dict() if include_audit and self._audit_result else None

        if format == "html":
            content = export_html(
                chains=self.chains,
                audit_results=audit_results,
                filepath=self.filepath,
            )
        elif format == "sarif":
            content = export_sarif(
                chains=self.chains,
                audit_results=audit_results or {},
                filepath=self.filepath,
            )
        elif format == "json":
            content = export_audit_json(
                chains=self.chains,
                filepath=self.filepath,
            )
        else:
            raise ValueError(f"Unknown format: {format}")

        write_export(content, output_path)
        return content


__all__ = [
    "FirewallAnalyzer",
    "Chain",
    "Rule",
    "PortRange",
    "AuditResult",
    "load_rules",
    "detect_format",
    "run_audit",
]
