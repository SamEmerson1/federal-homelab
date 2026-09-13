# Detections

One file per detection, named `<ATT&CK-ID>-<slug>.md`. Each documents the hypothesis, the SPL, the
false positives it will produce, the analyst response, and what it does not catch.

A search that has never run against real telemetry is a hypothesis, not a detection. Every entry
here is validated by executing the matching Atomic Red Team technique on WS01 and confirming the
search fires on the resulting events.

| Technique | ATT&CK ID | Primary log source | Status |
|---|---|---|---|
| PowerShell | T1059.001 | Sysmon EID 1, PowerShell 4104 | — |
| Create Account: Local Account | T1136.001 | Security 4720, 4732 | Draft |
| Scheduled Task/Job | T1053.005 | Security 4698, Sysmon EID 1 | — |
| Abuse Elevation Control: UAC Bypass | T1548.002 | Sysmon EID 1, 13 | — |
| Clear Windows Event Logs | T1070.001 | Security 1102, System 104 | — |

## Coverage and blind spots

Five techniques across Execution, Persistence, Privilege Escalation, and Defense Evasion. Stating
where the coverage ends matters more than the count:

- **No network telemetry.** Without a firewall or network sensor in the segment, lateral movement and command-and-control are invisible here.
- **No credential-access coverage.** Detecting LSASS access requires Sysmon process-access tuning not yet in place.
- **Windows only.** The Linux hosts do not currently forward logs.
