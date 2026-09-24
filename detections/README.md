# Detections

One file per detection, named `<ATT&CK-ID>-<slug>.md`. Each documents the hypothesis, the SPL, the
false positives it will produce, the analyst response, and what it does not catch.

A search that has never run against real telemetry is a hypothesis, not a detection. An entry is
marked **Validated** only after the matching Atomic Red Team test has been executed on WS01 and the
scheduled alert confirmed to fire on the resulting events. Each validated entry links to its
evidence under [`evidence/`](evidence/): the exported Splunk results, the alert-fired log, and the
Atomic Red Team execution log.

| Technique | ATT&CK ID | Primary log source | Status | Time to detect | Evidence |
|---|---|---|---|---|---|
| [PowerShell encoded command](T1059.001-powershell-encoded-command.md) | T1059.001 | Security 4688, PowerShell 4104 | **Validated** | 4 m 44 s | [T1059.001](evidence/T1059.001/) |
| [Local account creation](T1136.001-local-account-creation.md) | T1136.001 | Security 4720, 4732 | **Validated** | 4 m 17 s | [T1136.001](evidence/T1136.001/) |
| [Scheduled task creation](T1053.005-scheduled-task-creation.md) | T1053.005 | Security 4698 | **Validated** | 4 m 16 s | [T1053.005](evidence/T1053.005/) |
| [UAC bypass via registry](T1548.002-uac-bypass-registry.md) | T1548.002 | Sysmon 12/13 | **Validated** | 1 m 04 s | [T1548.002](evidence/T1548.002/) |
| [Clear Windows event logs](T1070.001-clear-event-logs.md) | T1070.001 | Security 1102, System 104 | Not validated | — | — |

Four of the five detections are validated against live telemetry. The fifth, T1070.001, is written
and scheduled but could not be validated: the Atomic Red Team release used has no test for that
sub-technique. Its file states this plainly rather than claiming a result.

All five run as scheduled alerts on SIEM01, every 5 minutes over a non-overlapping five-minute
window. The alert definitions are committed at
[`config/siem01/lab_siem_config/local/savedsearches.conf`](../config/siem01/lab_siem_config/local/savedsearches.conf).

## Validation method

Each test was run through the Atomic Red Team framework on WS01, selected by GUID (test numbers
shift as the upstream library changes). For every technique: run the test, confirm the events reach
Splunk, confirm the scheduled alert fires, export the events and the alert log to CSV, then run the
test's cleanup and revert WS01 to a pre-test snapshot. Time to detect is measured from the event
timestamp to the alert's scheduled run, so the 1–6 minute range reflects the 5-minute schedule, not
search latency.

Two results were more informative than a simple pass:

- **T1136.001** fired even on the runs the STIG password policy *blocked*: Windows still wrote a
  4720 (immediately followed by a 4726) for the rejected account, so the attempt was visible.
- **T1548.002** was detected on the registry write, and Microsoft Defender then removed the planted
  value 15 seconds later — prevention and detection both observable in the same timeline.

## Coverage and blind spots

Five techniques across Execution, Persistence, Privilege Escalation, and Defense Evasion. Stating
where the coverage ends matters more than the count:

- **Endpoint telemetry only.** Sysmon event 3 records which process made a network connection, but
  there is no packet or flow data, no firewall or network sensor. Lateral movement and
  command-and-control between hosts are not visible here.
- **No credential-access coverage.** Detecting LSASS access requires Sysmon process-access tuning
  not yet in place.
- **Windows only.** The Linux hosts do not forward logs.
- **WS01 only.** DC01 does not forward, so domain-level variants (for example domain account
  creation, T1136.002) are out of scope.
