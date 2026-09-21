#!/usr/bin/env python3
"""Process many firewall files through the parse and analyze stages."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from firewall_analyzer.analyzer import run_audit
from firewall_analyzer.parsers import load_rules
from firewall_analyzer.reporting import write_text_report

SUPPORTED_FORMATS = {"iptables", "nftables", "firewalld", "ufw"}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch-parse and analyze firewall files",
    )
    parser.add_argument("input", type=Path, help="Input file or directory")
    parser.add_argument(
        "--normalized-dir",
        type=Path,
        default=Path("normalized"),
        help="Directory for canonical JSON files",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("results"),
        help="Directory for analysis result files",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="Batch summary JSON path (default: <results-dir>/summary.json)",
    )
    parser.add_argument(
        "--format",
        choices=sorted(SUPPORTED_FORMATS),
        required=True,
        help="Firewall format for every file in this batch",
    )
    parser.add_argument(
        "--pattern",
        default="*.txt",
        help="File pattern when input is a directory (default: *.txt)",
    )
    parser.add_argument(
        "--admin-cidr",
        nargs="+",
        default=None,
        help="Trusted administrator network(s)",
    )
    parser.add_argument(
        "--all-zones",
        action="store_true",
        help="Include inactive firewalld zones in the audit",
    )
    args = parser.parse_args()

    files = discover_files(args.input, args.pattern)
    if not files:
        print(f"[ERROR] No input files found under {args.input}", file=sys.stderr)
        raise SystemExit(2)

    args.normalized_dir.mkdir(parents=True, exist_ok=True)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.summary or args.results_dir / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    for source in files:
        records.append(process_one(source, args))

    summary = build_summary(args.input, records)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print_summary(summary, summary_path)

    if summary["errors"]:
        raise SystemExit(3)
    if summary["failed"] or summary["unknown"]:
        raise SystemExit(1)
    raise SystemExit(0)


def discover_files(input_path: Path, pattern: str) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        return sorted(path for path in input_path.rglob(pattern) if path.is_file())
    return []


def process_one(source: Path, args: argparse.Namespace) -> dict[str, Any]:
    relative_name = source.name
    if args.input.is_dir():
        relative_name = str(source.relative_to(args.input))

    normalized_path = args.normalized_dir / Path(relative_name).with_suffix(".json")
    result_path = args.results_dir / Path(relative_name).with_name(
        Path(relative_name).stem + ".result.json"
    )
    report_path = args.results_dir / Path(relative_name).with_name(
        Path(relative_name).stem + ".result.txt"
    )
    normalized_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        format_name = args.format

        graph = load_rules(str(source), format=format_name)
        if not graph:
            raise ValueError(f"No rules were parsed as {format_name}")
        graph.metadata["source_file"] = str(source)
        normalized_path.write_text(graph.to_json() + "\n", encoding="utf-8")

        audit = run_audit(
            graph,
            admin_cidrs=args.admin_cidr,
            active_only=False if args.all_zones else None,
        )
        result = {
            "schema_version": "1.0",
            "source_file": str(source),
            "source_format": format_name,
            "analysis_options": {
                "admin_cidr": args.admin_cidr or [],
                "admin_cidr_check": "APPLIED" if args.admin_cidr else "SKIPPED",
            },
            "status": "FAIL" if audit.has_failures() else "PASS",
            "findings": audit.to_dict(),
        }
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        write_text_report(report_path, result)
        return {
            "source_file": str(source),
            "source_format": format_name,
            "status": result["status"],
            "normalized_file": str(normalized_path),
            "result_file": str(result_path),
            "report_file": str(report_path),
        }
    except Exception as error:
        error_result = {
            "schema_version": "1.0",
            "source_file": str(source),
            "status": "ERROR",
            "error": str(error),
        }
        result_path.write_text(json.dumps(error_result, indent=2) + "\n", encoding="utf-8")
        report_path.write_text(
            f"[ERROR] {source}\n{error}\n",
            encoding="utf-8",
        )
        return {
            "source_file": str(source),
            "source_format": None,
            "status": "ERROR",
            "result_file": str(result_path),
            "report_file": str(report_path),
            "error": str(error),
        }


def build_summary(input_path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {status.lower(): sum(record["status"] == status for record in records)
              for status in ("PASS", "FAIL", "UNKNOWN", "ERROR")}
    return {
        "schema_version": "1.0",
        "input": str(input_path),
        "total": len(records),
        "passed": counts["pass"],
        "failed": counts["fail"],
        "unknown": counts["unknown"],
        "errors": counts["error"],
        "files": records,
    }


def print_summary(summary: dict[str, Any], summary_path: Path) -> None:
    for record in summary["files"]:
        print(f"{record['status']}: {record['source_file']}")
    print(f"Processed: {summary['total']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Unknown: {summary['unknown']}")
    print(f"Errors: {summary['errors']}")
    print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
