# Plan: Unified Parser + Single Analyzer Architecture

## Context

4 parsers (iptables, nftables, firewalld, ufw) should each be a single focused file. 4 audit scripts should each be ~15 lines. All audit logic goes into one shared module. Frontend (GUI/Electron) is out of scope.

## Target Structure

```
firewall_analyzer/
  __init__.py          # FirewallAnalyzer (orchestrator — already exists)
  core_models.py       # Chain, Rule dataclasses (already exists)
  predicates.py        # shared audit predicates (already exists, rename from audit_predicates.py)
  trace_engine.py      # packet trace (already exists)
  shadowing.py         # rule shadowing (already exists)
  export.py            # HTML/SARIF/JSON export (already exists)

  parsers/
    __init__.py        # re-exports load_rules() that auto-detects format
    iptables.py        # ~100-150 lines — parsing only, no predicates
    nftables.py        # ~100-150 lines — parsing only
    firewalld.py        # ~100-150 lines — parsing only
    ufw.py             # ~100-150 lines — parsing only

  analyzer.py          # ONE audit runner — all 10 sections here (~200 lines)

cli/
  audit.py             # unified CLI — accepts --format flag, one script for all 4
                       # optionally keep iptables_audit.py etc. as aliases if needed
```

## Steps

### 1. Clean up existing shared modules

- Rename `audit_predicates.py` → `predicates.py`
- Remove duplicate predicates that exist inside `iptables_parser.py` (already duplicated in `audit_predicates.py` / `predicates.py`)
- Remove dual-mode dict/Chain adapter code in parsers — parsers only return `Chain[]`

**Files:** `audit_predicates.py`, `iptables_parser.py`

### 2. Create `firewall_analyzer/parsers/` with 4 minimal parser files

Each parser:
- One `load_<fmt>(source)` function — `source` is a file path or text
- Returns `dict[str, Chain]` (same shape for all 4)
- Zero predicates, zero audit logic — parsing only

```
parsers/
  iptables.py   — handles iptables-save format
  nftables.py  — handles nftables list output
  firewalld.py  — handles firewalld XML + CLI output
  ufw.py       — handles ufw status/rules output
  __init__.py  — auto-detects format and calls the right parser
```

**Files:** `parsers/iptables.py`, `parsers/nftables.py`, `parsers/firewalld.py`, `parsers/ufw.py`, `parsers/__init__.py`

### 3. Create `firewall_analyzer/analyzer.py`

One file. All audit logic (10 sections). Calls `predicates.py`. Takes `dict[str, Chain]`. Returns `AuditResult`.

**File:** `analyzer.py` (~200 lines, replaces 4×300-line copies)

### 4. Unify CLI to `cli/audit.py`

One script, accepts `--format` (or auto-detects). No need for 4 separate scripts.

```python
# cli/audit.py — 15 lines
from firewall_analyzer.parsers import load_rules
from firewall_analyzer.analyzer import run_audit

rules = load_rules(source, format=fmt)
results = run_audit(rules, admin_cidrs=cidrs)
print_report(results)
```

### 5. Delete old redundant files

- `iptables_audit.py`, `nftables_audit.py`, `firewalld_audit.py` → replace with `cli/audit.py`
- `iptables_parser.py`, `nftables_parser.py`, `firewalld_parser.py` → superseded by `parsers/`
- Remove GUI/Electron (`gui/`) — out of scope
- `firewall_analyzer/__init__.py` update: import from new `parsers/` and `analyzer.py`

### 6. Verify

- `python -m cli.audit test_fixtures/iptables.txt --format iptables` works
- `python -m cli.audit test_fixtures/firewalld.xml --format firewalld` works
- Trace/shadow output unchanged (those engines untouched)
- Output identical to current audit output
