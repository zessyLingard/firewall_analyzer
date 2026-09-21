#!/usr/bin/env python3
"""
export.py — Export firewall audit results to various formats (HTML, SARIF, JSON).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Optional
from dataclasses import asdict

from firewall_analyzer.models import Chain, Rule, PortRange
from firewall_analyzer.shadowing import ShadowFinding, format_shadowing_json


def export_audit_json(
    chains: Mapping[str, Chain],
    shadowing_findings: Optional[list[ShadowFinding]] = None,
    filepath: str = "",
    metadata: Optional[dict[str, object]] = None,
) -> str:
    """Export complete audit results as JSON."""
    data = {
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_file": filepath,
            **(metadata or {}),
        },
        "chains": {},
    }
    
    # Export chains
    for name, chain in chains.items():
        data["chains"][name] = {
            "table": chain.table,
            "name": chain.name,
            "default_policy": chain.default_policy,
            "rules": [_rule_to_dict(r) for r in chain.rules],
        }
    
    # Export shadowing findings
    if shadowing_findings:
        data["shadowing"] = json.loads(format_shadowing_json(shadowing_findings))
    
    return json.dumps(data, indent=2)


def _rule_to_dict(rule: Rule) -> dict:
    """Convert Rule dataclass to dictionary."""
    return {
        "table": rule.table,
        "chain": rule.chain,
        "action": rule.action,
        "in_interface": rule.in_interface,
        "out_interface": rule.out_interface,
        "sources": [str(s) for s in rule.sources],
        "destinations": [str(d) for d in rule.destinations],
        "ports": [str(p) for p in rule.ports],
        "source_ports": [str(p) for p in rule.source_ports],
        "protocol": rule.protocol,
        "states": rule.states,
        "is_negated": rule.is_negated,
        "has_comment": rule.has_comment,
        "raw_line": rule.raw_line,
        "line_number": rule.line_number,
        "src_range": rule.src_range,
        "dst_range": rule.dst_range,
    }


def export_sarif(
    chains: Mapping[str, Chain],
    audit_results: Mapping[str, object],  # From audit scripts
    shadowing_findings: Optional[list[ShadowFinding]] = None,
    filepath: str = "",
) -> str:
    """Export audit results in SARIF format for SIEM/IDE integration."""
    
    results = []
    
    # Convert audit findings to SARIF
    for check_name, check_data in audit_results.items():
        if check_name.startswith("_"):
            continue
            
        if isinstance(check_data, list):
            for item in check_data:
                if isinstance(item, str):  # Rule line
                    results.append(_make_sarif_result(
                        rule_line=item,
                        check_id=check_name,
                        filepath=filepath,
                    ))
    
    # Convert shadowing findings
    if shadowing_findings:
        for f in shadowing_findings:
            results.append(_make_sarif_result(
                rule_line=f.shadowed_rule.raw_line,
                check_id=f"SHADOWING-{f.shadow_type}",
                filepath=filepath,
                message=f"{f.shadow_type} shadowing: {f.description}",
                location_chain=f.chain,
                location_rule_index=f.shadowed_rule_index,
            ))
    
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "firewall-analyzer",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/firewall-analyzer",
                }
            },
            "results": results,
        }]
    }
    
    return json.dumps(sarif, indent=2)


def _make_sarif_result(
    rule_line: str,
    check_id: str,
    filepath: str,
    message: Optional[str] = None,
    location_chain: Optional[str] = None,
    location_rule_index: Optional[int] = None,
) -> dict:
    """Create a SARIF result object."""
    return {
        "ruleId": check_id,
        "level": "error",
        "message": {
            "text": message or f"Firewall audit check failed: {check_id}"
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": filepath,
                },
                "region": {
                    "snippet": {"text": rule_line[:200]},
                }
            }
        }],
        "properties": {
            "chain": location_chain,
            "rule_index": location_rule_index,
        }
    }


def export_html(
    chains: Mapping[str, Chain],
    audit_results: Optional[Mapping[str, object]] = None,
    shadowing_findings: Optional[list[ShadowFinding]] = None,
    filepath: str = "",
    title: str = "Firewall Audit Report",
) -> str:
    """Export audit results as HTML report."""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #444; margin-top: 30px; }}
        h3 {{ color: #555; }}
        .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }}
        .metadata span {{ margin-right: 20px; }}
        .chain {{ margin-bottom: 30px; }}
        .chain-header {{ background: #0066cc; color: white; padding: 10px 15px; border-radius: 6px 6px 0 0; font-weight: bold; }}
        .rule {{ border: 1px solid #ddd; border-top: none; padding: 12px 15px; margin-bottom: 8px; background: #fafafa; }}
        .rule:last-child {{ border-radius: 0 0 6px 6px; }}
        .rule-header {{ display: flex; gap: 15px; margin-bottom: 8px; font-size: 13px; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
        .badge-accept {{ background: #d4edda; color: #155724; }}
        .badge-drop {{ background: #f8d7da; color: #721c24; }}
        .badge-reject {{ background: #fff3cd; color: #856404; }}
        .badge-jump {{ background: #cce5ff; color: #004085; }}
        .badge-log {{ background: #e2e3e5; color: #383d41; }}
        .rule-details {{ font-family: monospace; font-size: 12px; color: #666; }}
        .rule-raw {{ font-family: monospace; font-size: 12px; color: #333; background: #f8f9fa; padding: 8px; border-radius: 4px; margin-top: 8px; overflow-x: auto; }}
        .trace-step {{ padding: 10px; margin: 8px 0; border-radius: 4px; }}
        .trace-match {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .trace-nomatch {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .trace-chain {{ background: #e2e3e5; font-weight: bold; margin-top: 20px; }}
        .finding {{ padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid; }}
        .finding-full {{ background: #f8d7da; border-color: #dc3545; }}
        .finding-partial {{ background: #fff3cd; border-color: #ffc107; }}
        .finding-redundant {{ background: #cce5ff; border-color: #0066cc; }}
        .finding-unreachable {{ background: #f8d7da; border-color: #dc3545; }}
        .finding-title {{ font-weight: bold; margin-bottom: 5px; }}
        .finding-desc {{ color: #666; font-size: 14px; }}
        .section {{ margin-top: 40px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        
        <div class="metadata">
            <span><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</span>
            <span><strong>Source:</strong> {filepath}</span>
            <span><strong>Chains:</strong> {len(chains)}</span>
        </div>
"""
    
    # Chains section
    html += '<div class="section"><h2>Chains & Rules</h2>'
    for name, chain in chains.items():
        html += f'''
        <div class="chain">
            <div class="chain-header">Chain: {name} (table: {chain.table}) 
                <span style="float:right; font-weight:normal;">Policy: {chain.default_policy or "none"}</span>
            </div>
'''
        for idx, rule in enumerate(chain.rules):
            action_class = rule.action.lower()
            if action_class not in ['accept', 'drop', 'reject', 'jump', 'log']:
                action_class = 'jump'
            
            html += f'''
            <div class="rule">
                <div class="rule-header">
                    <span class="badge badge-{action_class}">{rule.action}</span>
                    <span>#{idx}</span>
                    <span>proto: {rule.protocol or 'any'}</span>
                    <span>src: {', '.join(str(s) for s in rule.sources) or 'any'}</span>
                    <span>dst: {', '.join(str(d) for d in rule.destinations) or 'any'}</span>
                </div>
                <div class="rule-details">
                    ports: {', '.join(str(p) for p in rule.ports) or 'any'} | 
                    sport: {', '.join(str(p) for p in rule.source_ports) or 'any'} | 
                    states: {', '.join(rule.states) or 'any'} | 
                    in: {rule.in_interface or 'any'} | 
                    out: {rule.out_interface or 'any'}
                </div>
                <div class="rule-raw">{rule.raw_line}</div>
            </div>
'''
        html += '</div>'
    html += '</div>'
    
    # Audit results
    if audit_results:
        html += '<div class="section"><h2>Audit Results</h2>'
        for check_name, check_data in audit_results.items():
            if check_name.startswith("_"):
                continue
            html += f'<h3>{check_name}</h3>'
            if isinstance(check_data, list):
                if not check_data:
                    html += '<p style="color: #28a745;">✓ PASS - No issues found</p>'
                else:
                    for item in check_data:
                        if isinstance(item, str):
                            html += f'<div class="finding finding-full"><div class="finding-desc">{item}</div></div>'
            elif isinstance(check_data, dict):
                for k, v in check_data.items():
                    html += f'<p><strong>{k}:</strong> {v}</p>'
        html += '</div>'
    
    # Shadowing findings
    if shadowing_findings:
        html += '<div class="section"><h2>Shadowing Analysis</h2>'
        for f in shadowing_findings:
            cls = f"finding-{f.shadow_type.lower()}"
            html += f'''
            <div class="finding {cls}">
                <div class="finding-title">[{f.shadow_type}] Chain: {f.chain} - Rule {f.shadowing_rule_index} → Rule {f.shadowed_rule_index}</div>
                <div class="finding-desc">{f.description}</div>
                <div style="margin-top: 10px; font-size: 12px; font-family: monospace;">
                    <div>Shadowing: {f.shadowing_rule.raw_line[:200]}</div>
                    <div>Shadowed: {f.shadowed_rule.raw_line[:200]}</div>
                </div>
            </div>
'''
        html += '</div>'
    
    html += """
    </div>
</body>
</html>"""
    
    return html


def write_export(output: str, filepath: str) -> None:
    """Write export output to file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(output)