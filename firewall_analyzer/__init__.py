"""
firewall_analyzer — Unified firewall security auditing toolkit.

Supports: iptables, nftables, firewalld, ufw

Usage:
    from firewall_analyzer import FirewallAnalyzer

    analyzer = FirewallAnalyzer("rules.iptables")
    analyzer.shadowing()
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
from firewall_analyzer.shadowing import analyze_shadowing, ShadowFinding, format_shadowing_text, format_shadowing_json
from firewall_analyzer.export import export_html, export_sarif, export_audit_json, write_export
from firewall_analyzer.parsers import load_rules, detect_format
from firewall_analyzer.analyzer import run_audit, AuditResult


class FirewallAnalyzer:
    def __init__(self, filepath: str, format_type: str = "auto"):
        self.filepath = filepath
        self.format_type = format_type
        self.chains: dict[str, Chain] = {}
        self._shadowing_findings: list[ShadowFinding] = []
        self._audit_result: AuditResult | None = None
        self._load()

    def _load(self):
        self.chains = load_rules(self.filepath, format=self.format_type)
        if not self.chains:
            raise ValueError(f"No chains found in {self.filepath}")

    def reload(self):
        self._load()
        self._shadowing_findings = []
        self._audit_result = None

    @property
    def chain_names(self) -> list[str]:
        return list(self.chains.keys())

    def get_chain(self, name: str) -> Chain | None:
        return self.chains.get(name)

    # ---- Shadowing analysis ----

    def shadowing(self) -> "ShadowingResultSet":
        self._shadowing_findings = analyze_shadowing(self.chains)
        return ShadowingResultSet(self._shadowing_findings)

    # ---- Security audit ----

    def audit(self, admin_cidrs: list[str] | None = None) -> AuditResult:
        self._audit_result = run_audit(self.chains, admin_cidrs=admin_cidrs)
        return self._audit_result

    # ---- Export ----

    def export(
        self,
        output_path: str,
        format: Literal["html", "sarif", "json"] = "html",
        include_shadowing: bool = True,
        include_audit: bool = True,
    ) -> str:
        shadowing_findings = self._shadowing_findings if include_shadowing else None
        audit_results = self._audit_result.to_dict() if include_audit and self._audit_result else None

        if format == "html":
            content = export_html(
                chains=self.chains,
                audit_results=audit_results,
                shadowing_findings=shadowing_findings,
                filepath=self.filepath,
            )
        elif format == "sarif":
            content = export_sarif(
                chains=self.chains,
                audit_results=audit_results or {},
                shadowing_findings=shadowing_findings,
                filepath=self.filepath,
            )
        elif format == "json":
            content = export_audit_json(
                chains=self.chains,
                shadowing_findings=shadowing_findings,
                filepath=self.filepath,
            )
        else:
            raise ValueError(f"Unknown format: {format}")

        write_export(content, output_path)
        return content


class ShadowingResultSet:
    def __init__(self, findings: list[ShadowFinding]):
        self.findings = findings

    @property
    def full_shadows(self) -> list[ShadowFinding]:
        return [f for f in self.findings if f.shadow_type == "FULL"]

    @property
    def partial_shadows(self) -> list[ShadowFinding]:
        return [f for f in self.findings if f.shadow_type == "PARTIAL"]

    def summary(self) -> str:
        return format_shadowing_text(self.findings)

    def to_json(self) -> str:
        return format_shadowing_json(self.findings)

    def __len__(self):
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)


__all__ = [
    "FirewallAnalyzer",
    "ShadowingResultSet",
    "Chain",
    "Rule",
    "PortRange",
    "AuditResult",
    "load_rules",
    "detect_format",
    "run_audit",
]
