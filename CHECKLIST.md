# Firewall Audit Checklist Traceability

## Compliance Requirements Mapping

| Requirement | Check ID | Title | Severity | Engines | Status |
|-------------|----------|-------|----------|---------|--------|
| Cấu hình rule mặc định chặn kết nối vào ra | CHECK-001 | Default firewall policy | CRITICAL | iptables, nftables, firewalld | ✅ Implemented |
| INPUT: Không cho phép rule 0.0.0.0/0 mọi port mọi protocol | CHECK-002 | Unrestricted INPUT ACCEPT | CRITICAL | iptables, nftables, firewalld | ✅ Implemented |
| OUTPUT: Không cho phép rule 0.0.0.0/0 mọi port mọi protocol | CHECK-002 | Unrestricted OUTPUT ACCEPT | CRITICAL | iptables, nftables, firewalld | ✅ Implemented |
| SSH không được giới hạn địa chỉ nguồn | CHECK-003 | SSH source restriction | HIGH | iptables, nftables, firewalld | ✅ Implemented |

## Security Analysis (SEC-*)

| Check ID | Title | Severity | Engines | Status |
|----------|-------|----------|---------|--------|
| SEC-001 | High-risk port exposure | CRITICAL | iptables, nftables | ✅ Implemented |
| SEC-002 | Loopback address on non-loopback interface | HIGH | iptables, nftables | ✅ Implemented |
| SEC-003 | NOTRACK without IP restrictions | HIGH | iptables, nftables | ✅ Implemented |
| SEC-004 | INVALID state handling | HIGH | iptables, nftables | ✅ Implemented |
| SEC-005 | Shadowed DROP/REJECT rules | MEDIUM | iptables, nftables | ✅ Implemented |
| SEC-006 | Missing ESTABLISHED,RELATED rule | MEDIUM | iptables, nftables | ✅ Implemented |
| SEC-007 | OUTPUT source-port without destination-port | HIGH | iptables, nftables | ✅ Implemented |
| SEC-008 | INPUT source-port without destination-port/state | HIGH | iptables, nftables | ✅ Implemented |
| SEC-009 | Negated IP includes public internet | HIGH | iptables, nftables | ✅ Implemented |
| SEC-010 | Unbound firewalld zones | MEDIUM | firewalld | ✅ Implemented |

## Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| Parser correctness (iptables) | 5 | ✅ 5/5 |
| Parser correctness (nftables) | 2 | ✅ 2/2 |
| CHECK-001 Default Policy | 4 | ✅ 4/4 |
| CHECK-002 Unrestricted | 6 | ✅ 6/6 |
| CHECK-003 SSH | 7 | ✅ 7/7 |
| SEC-001 High-risk ports | 2 | ✅ 2/2 |
| SEC-002 Loopback spoof | 1 | ✅ 1/1 |
| SEC-005 Shadowed rules | 1 | ✅ 1/1 |
| Integration | 3 | ✅ 3/3 |
| Zone model | 6 | ✅ 6/6 |
| Helper functions | 11 | ✅ 11/11 |
| **Total** | **53** | **✅ 53/53** |

## Compliance Status Semantics

| Status | Meaning |
|--------|---------|
| PASS | Check evaluated and satisfied |
| FAIL | Check evaluated and violated |
| NOT_APPLICABLE | Check does not apply to this configuration |
| ERROR | Check could not be reliably evaluated |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All compliance checks passed |
| 1 | One or more compliance checks failed |
| 2 | Error parsing ruleset or file not found |
