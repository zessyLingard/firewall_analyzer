"""Human-readable audit report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


CHECK_LABELS = {
    "missing_established_related": "Missing ESTABLISHED,RELATED rule",
    "ssh_missing_comment": "SSH rule missing comment",
    "ssh_open_source": "SSH open to unrestricted sources",
    "input_no_port": "INPUT ACCEPT without destination-port restriction",
    "output_no_port": "OUTPUT ACCEPT without destination-port restriction",
    "input_fully_open": "Fully open INPUT ACCEPT rule",
    "output_fully_open": "Fully open OUTPUT ACCEPT rule",
    "ssh_outside_admin": "SSH source outside administrator network",
    "sport_spoofable": "Spoofable source-port-only rule",
}


def write_text_report(report_path: Path, result: dict[str, Any]) -> None:
    """Write only actionable audit failures and their original rules."""
    lines = [
        f"[{result['status']}] {result['source_file']}",
        f"Format: {result.get('source_format', 'unknown')}",
    ]
    findings = result.get("findings", {})
    default_policy = findings.get("default_policy", {})
    failed_checks = 0
    if isinstance(default_policy, dict) and not default_policy.get("passed"):
        lines.append(f"[FAIL] Default policy: {default_policy.get('reason', '')}")
        failed_checks += 1
    for check_name, values in findings.items():
        if check_name == "default_policy" or not isinstance(values, list):
            continue
        if not values:
            continue
        failed_checks += 1
        lines.append(f"[FAIL] {CHECK_LABELS.get(check_name, check_name)}")
        for value in values:
            lines.append(f"  {value}")
    if failed_checks == 0:
        lines.append("[PASS] No failed checks")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
