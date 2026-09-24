# Network Diagram

## Topology

The segment layout and host roles are diagrammed in the
[README](../README.md#environment) and are not duplicated here, so the two cannot drift apart.
Addressing, the isolation boundary, and the VM inventory are in
[`architecture.md`](architecture.md).

## Log flow

**Status:** live for WS01 since 2026-09-23; detections validated 2026-09-24. Build details in
[`logging-pipeline.md`](logging-pipeline.md).

```mermaid
flowchart LR
    A["WS01<br/>Sysmon · Security<br/>PowerShell · System"] -->|"Universal Forwarder :9997"| D["SIEM01<br/>index=lab_sysmon<br/>index=lab_win"]
    D --> E["SPL detections<br/>mapped to MITRE ATT&CK"]
    E --> F["Dashboard and alerts"]
    G["Atomic Red Team<br/>WS01 only"] -.->|"generates telemetry"| A
    E -.->|"validates against"| G
```

## Assessment flow

```mermaid
flowchart TB
    S1["OpenSCAP<br/>RHEL01"] --> R1["Baseline scan"]
    R1 --> REM1["Reviewed fix scripts<br/>applied in stages"]
    REM1 --> R2["Rescan"]

    S2["SCAP Compliance Checker<br/>WS01"] --> R3["Baseline scan"]
    R3 --> REM2["DISA STIG GPO package<br/>linked to Workstations OU"]
    REM2 --> R4["Rescan"]

    S3["Nessus<br/>KALI01"] --> R5["Uncredentialed baseline"]
    R5 --> R6["Credentialed baseline"]
    R6 --> REM3["Patch and reconfigure"]
    REM3 --> R7["Verification rescan"]
```
