# Plan of Action and Milestones

Open findings from STIG compliance assessment of this environment, with the reason each remains
open and what would close it. A POA&M exists so that residual risk is stated and accepted
deliberately rather than discovered later; an item here is a decision, not an oversight.

Every finding traces to a scan report committed under [`scans/`](../scans/). Control references are
the CCI and NIST SP 800-53 Rev. 5 mappings published in the DISA benchmark content.

**As of:** 2026-09-22

| Host | Assessed | Remediated | Open | Reference |
|---|---|---|---|---|
| RHEL01 | 2026-09-16 | 2026-09-20 | 17 | [scan](../scans/openscap/rhel01-post-20260920.md) · [method](rhel01-remediation.md) |
| WS01 | 2026-09-17 | 2026-09-22 | 7 (+1 residual) | [scan](../scans/scc/ws01-post-20260922.md) · [method](ws01-stig-gpo.md) |
| DC01 | 2026-09-18 | Deferred | 138 | [scan](../scans/scc/dc01-baseline-20260918.md) |

---

## WS01 — Windows 11 Pro

Seven rules remain open out of 148 at baseline. They fall into two groups: three with no
remediation path in this environment, and four awaiting certificate content newer than the current
DoD distribution tool provides.

### No remediation path

| ID | Rule | STIG ID | CAT | Control |
|---|---|---|---|---|
| WS01-001 | Credential Guard must be running | WN11-CC-000075 | **I** | CCI-000366 · CM-6 b |
| WS01-002 | Domain-joined systems must use Windows 11 Enterprise | WN11-00-000005 | II | CCI-000366 · CM-6 b |
| WS01-003 | Multifactor authentication for local and network access | WN11-SO-000251 | II | CCI-000765 · IA-2 (1) |

**WS01-001 and WS01-002** are one finding expressed twice. Credential Guard is a Windows 11
Enterprise and Education feature; WS01 runs Pro. Microsoft's Enterprise evaluation image was past
its expiration date at download and enforced hourly shutdowns, so Pro was substituted during the
build. The policy values are set and the platform prerequisites are satisfied — virtualization-based
security and HVCI both run on this host — but the edition gates the feature itself.

*Risk:* LSA credential material is not isolated in a VSM enclave, so credential-theft techniques
that read LSASS memory are not mitigated by this control on this host. Partially offset by HVCI,
the deny-logon rights that keep privileged domain accounts off the workstation entirely, and network
isolation.

*Closure:* a Windows 11 Enterprise license. Not planned for this lab.

**WS01-003** requires DoD CAC/PIV infrastructure — card issuance, middleware, and a reader — which
does not exist in an isolated virtual environment with no physical smart card hardware.

*Risk:* authentication is single-factor. Offset by a 15-character domain minimum, 20 characters for
privileged and service accounts, a 3-attempt lockout, and no route from the lab to any other
network.

*Closure:* out of scope. Would require physical PKI hardware.

### Certificate content version gap

| ID | Rule | STIG ID | CAT | Control |
|---|---|---|---|---|
| WS01-004 | DoD Root CA certificates in Trusted Root store | WN11-PK-000005 | II | CCI-000185 · IA-5 (2) |
| WS01-005 | External Root CA certificates in Trusted Root store | WN11-PK-000010 | II | CCI-000185 · IA-5 (2) |
| WS01-006 | DoD Interoperability cross-certificates in Untrusted store | WN11-PK-000015 | II | CCI-002470 · SC-23 (5) |
| WS01-007 | CCEB Interoperability cross-certificates in Untrusted store | WN11-PK-000020 | II | CCI-002470 · SC-23 (5) |

DoD certificates were introduced through **InstallRoot 5.6**, the current NIPR release, transferred
into the isolated segment and verified by SHA-256 and Authenticode signature before execution. It
installed DoD Root CA 3, 4, and 5, 45 intermediates, and two Interoperability cross-certificates.

STIG V2R10 tests these four rules against **specific certificate thumbprints**, and the set it
expects is newer than the trust-anchor payload the tool ships. WN11-PK-000005 requires DoD Root CA
3, 5, and **6**; Root CA 6 is not in the payload. The cross-certificate rules name particular
certificates by expiry that the payload does not contain.

This is a version gap between the distribution tool and the benchmark, not a misconfiguration on the
host. Running the tool elevated also fails its own trust-anchor verification offline —
`Unable to find a valid TAMP message` — because it builds the validation path against the machine
store it is about to populate.

*Risk:* certificate paths chaining to DoD Root CA 6 do not validate, and the specific
interoperability cross-certificates named by the benchmark are not explicitly distrusted. Low in
practice: this host contacts no DoD PKI-protected service and has no route off the lab segment.

*Closure:* source the current PKCS#7 certificate bundles directly from the DoD Cyber Exchange rather
than relying on the tool payload, and import with `certutil -addstore` to `Root` and `Disallowed`.
Scheduled for the next maintenance window.

### Residual — not a scan finding

| ID | Item | Severity | Status |
|---|---|---|---|
| WS01-008 | System volume encrypted at XTS-AES 128, Used Space Only | Informational | Open |

WN11-00-000030 passes: the volume is encrypted, protection is on, and pre-boot authentication is
enforced by TPM+PIN with the recovery password escrowed to Active Directory. No rule in this
benchmark tests the encryption algorithm or the conversion type, so the scan does not flag this.

It is recorded anyway. The volume was already fully encrypted at XTS-AES 128 by Windows' automatic
Device Encryption before hardening began, in a suspended state with no key protectors. Remediation
added protectors and resumed protection rather than decrypting and re-encrypting, because a
full-volume rewrite on this host had previously coincided with an unrecoverable shell failure
(documented in [`ws01-stig-gpo.md`](ws01-stig-gpo.md)) and the rule tests protection status alone.

*Risk:* used-space-only conversion leaves previously deleted sectors unencrypted, and DoD prefers
XTS-AES 256. Data-at-rest exposure is limited to the virtual disk file on the host; the VM holds no
production or personal data.

*Closure:* offline `chkdsk /f /r`, snapshot, decrypt, re-encrypt at XTS-AES 256 with full-volume
conversion, re-escrow. Deferred maintenance.

---

## RHEL01 — Rocky Linux 9

17 rules remain open out of 258 at baseline, itemised in the
[post-remediation scan summary](../scans/openscap/rhel01-post-20260920.md).

| Category | Count | Summary |
|---|---|---|
| Platform substitution | 1 | Rocky Linux 9 in place of RHEL 9; one rule tests Red Hat-specific packaging |
| Filesystem layout | 6 | Separate partitions for `/var`, `/var/log`, `/var/log/audit`, `/var/tmp`, `/home`, `/tmp` — requires a rebuild, not a configuration change |
| Missing lab infrastructure | 7 | Filed as controls depending on services this environment does not run: a remote log collector (4 rules), a second DNS server (1), and smart card PKI for certificate mapping (1). The seventh, `rsyslog_remote_access_monitoring`, was filed here in error — see below |
| Risk-based deferral | 2 | Accepted with stated reasons |
| Benchmark self-conflict | 1 | `scap-security-guide` 0.1.82 contains rules demanding mutually exclusive SSH MAC orderings; see [`rhel01-remediation.md`](rhel01-remediation.md) |

The filesystem-layout items close at next rebuild. Of the infrastructure items, the four
log-forwarding rules become closable once a collector runs on SIEM01, which is planned for the
current phase. The DNS and PKI items remain open with no planned closure.

**Misclassified: `rsyslog_remote_access_monitoring`.** Grouped with the log-forwarding rules at
the time of remediation on the strength of its title. Its OVAL definition in
`scap-security-guide` 0.1.82 tests `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` for selector
lines covering `auth.*`, `authpriv.*`, and `daemon.*` that write to a file or forward — a local
destination satisfies it, and no remote host is required. "Remote access" in the title refers to
the access methods being logged, not to where the logs go. The current configuration fails on
`auth.*` and `daemon.*`; `authpriv.*` already matches. Closable without new infrastructure and
scheduled with the rsyslog work.

---

## Environmental and scope items

| ID | Item | Status |
|---|---|---|
| ENV-001 | DC01 STIG remediation deferred | Open — planned Phase 3 |
| ENV-002 | SIEM01 excluded from compliance scanning | Accepted, documented scope limitation |
| ENV-003 | KALI01 excluded from compliance scanning | Accepted — assessment platform, no applicable STIG |
| ENV-004 | DISA GPO package v2r8 against benchmark V2R10 | Open — compensating policy in place |

**ENV-001 — DC01 remediation deferred.** DC01 was assessed and its baseline is committed
([`dc01-baseline-20260918.md`](../scans/scc/dc01-baseline-20260918.md)): 42.74%, 138 failed rules.
Remediation is deferred rather than attempted.

DC01 is the sole domain controller in this environment, with no replication partner to fail over to.
The Windows Server 2025 STIG's authentication controls — LDAP signing and channel binding, SMB
signing, NTLM restrictions, and Kerberos encryption-type constraints — alter the authentication path
that every other host depends on, including the scanner service account, the workstation's secure
channel, time synchronisation for the Linux hosts, and the administrative access used to perform the
remediation itself. Applying them without a second domain controller and a validated rollback plan
for each cross-host dependency exceeds the risk tolerance for this phase.

*Risk:* the domain controller runs at its assessed baseline. Offset by network isolation, no
inbound path from outside the lab segment, and the domain-wide password and lockout policy
strengthened during workstation remediation.

*Closure:* stand up a second domain controller, then apply the Server 2025 STIG GPO to the Domain
Controllers OU in stages with cross-host dependency validation between each. Planned as Phase 3,
after the Splunk build.

**ENV-004 — GPO package version drift.** DISA's published Windows 11 STIG GPO package is at v2r8
while the SCAP benchmark used for assessment is V2R10. Three rules present in V2R10 have no
corresponding setting in the package and were confirmed failing after a clean import. A
supplemental GPO (`Lab - STIG V2R10 Supplement`) supplies them.

*Closure:* adopt the v2r10 GPO package when DISA publishes it, then retire the supplemental GPO.
Until then the supplement is the compensating control, and its name records why it exists.

---

## Notes on method

Three findings in this POA&M were identified by reading the OVAL definitions behind the rules rather
than the rule titles — the BitLocker protection-status test, the certificate thumbprint tests, and
the per-profile evaluation of user-scope registry rules. Rule titles describe intent; the OVAL
describes what is actually measured, and the two differ often enough that remediation planned from
titles alone tends to be either insufficient or unnecessarily destructive.

This is a training environment, not an accredited system. The format follows RMF POA&M practice
under NIST SP 800-37 so the artifact is recognisable, but no authorising official, milestone dates,
or resource estimates are asserted.
