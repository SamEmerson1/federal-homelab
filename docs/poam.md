# Plan of Action and Milestones (POA&M)

Every finding that was not remediated, with an owner, a date, and a reason. The POA&M is where
honesty lives in an RMF package: an empty POA&M on a real system means the assessment was not
thorough, not that the system is clean.

**System:** Federal-Aligned Security Lab
**Prepared by:**
**Last updated:**

---

## Summary

| Severity | Open | In progress | Closed | Risk accepted |
|---|---|---|---|---|
| Critical / CAT I | `__` | `__` | `__` | `__` |
| High / CAT II | `__` | `__` | `__` | `__` |
| Medium / CAT III | `__` | `__` | `__` | `__` |
| **Total** | `__` | `__` | `__` | `__` |

## Open items

| ID | Weakness | Source | Affected asset | Severity | Control | Detected | Mitigation / milestones | Resources | Sched. completion | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| P-001 | | OpenSCAP / SCC / Nessus | | CAT I–III | e.g. CM-6 | YYYY-MM-DD | | | YYYY-MM-DD | Open |
| P-002 | | | | | | | | | | |
| P-003 | | | | | | | | | | |

### Column definitions

| Column | Meaning |
|---|---|
| Weakness | What is wrong, in plain language — not the raw rule title |
| Source | The scan that found it, and the rule or plugin ID |
| Control | The NIST 800-53 control the weakness maps to |
| Mitigation / milestones | Dated steps, not a single "will fix" |
| Resources | What it would take — time, license, hardware, or a decision |
| Status | Open / In progress / Completed / Risk accepted |

## Risk-accepted items

Findings deliberately not remediated. Each needs a written justification, because "I couldn't fix
it" and "fixing it would break a required function" are very different statements.

| ID | Weakness | Why remediation is not being performed | Compensating control | Accepted by | Date |
|---|---|---|---|---|---|
| RA-001 | | e.g. STIG requires smart-card logon; no PKI in this lab | e.g. 15-char password policy + lockout at 3 attempts | | |

## Closed items

| ID | Weakness | Remediation applied | Verified by | Closed |
|---|---|---|---|---|
| | | | Rescan output in `scans/` | |

---

## Working notes

- Every item must map to a scan result file in `scans/`. No item exists because it seemed plausible.
- Closing an item requires a **rescan**, not a configuration change. The rescan file is the proof.
- STIG CAT I findings get scheduled before CAT II regardless of how easy the CAT IIs look.
- Where a STIG rule cannot be met in a lab (smart-card authentication, FIPS-validated crypto
  modules, enterprise certificate services), that is a legitimate risk-accepted item — and
  explaining why in an interview demonstrates more than a 100% compliance score would.
