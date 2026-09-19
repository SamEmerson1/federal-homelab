# RHEL01 baseline — 2026-09-16

**Tool:** OpenSCAP 1.3.14 with `scap-security-guide`
**Benchmark:** DISA STIG for Red Hat Enterprise Linux 9 (`xccdf_org.ssgproject.content_benchmark_RHEL-9`)
**Benchmark version:** 0.1.82
**Profile:** `xccdf_org.ssgproject.content_profile_stig`
**Target:** Rocky Linux 9.8 minimal, 10.10.10.30
**Scan type:** local, run as root
**Duration:** 21 seconds

| Result | Count |
|---|---|
| Pass | 167 |
| Fail | 258 |
| N/A | 42 |
| Not checked | 10 |
| **Compliance (OpenSCAP default scoring)** | **44.9%** |

| Severity of failures | Count |
|---|---|
| High | 11 |
| Medium | 224 |
| Low | 20 |
| Other | 3 |

## Notes

Rocky Linux is binary compatible with Red Hat Enterprise Linux, and the SCAP content declares both
`cpe:/o:rocky:rocky:9` and `cpe:/o:redhat:enterprise_linux:9` as applicable platforms. The scan runs
against the published DISA RHEL 9 benchmark, not an approximation of it.

The compliance figure is OpenSCAP's default weighted score, which is what the HTML report displays.
The raw pass rate — 167 / (167 + 258) — is 39.3%. The post-remediation scan must use the same
scoring method for the delta to be meaningful.

## Evidence

[Full OpenSCAP report](https://samemerson1.github.io/federal-homelab/scans/openscap/rhel01-baseline-20260916.html)
