# Deployed configuration

Configuration files as deployed on each host, committed so every setting described in
[`docs/logging-pipeline.md`](../docs/logging-pipeline.md) can be read directly.

| Path | Deployed to |
|---|---|
| `siem01/lab_siem_config/` | `/opt/splunk/etc/apps/lab_siem_config/` on SIEM01 |
| `ws01/lab_ws01_config/` | `C:\Program Files\SplunkUniversalForwarder\etc\apps\lab_ws01_config\` on WS01 |
| `ws01/sysmon/sysmonconfig-lab.diff` | Provenance and the single change to the loaded Sysmon configuration |

The Sysmon configuration itself is not copied here; it is sysmon-modular's published release,
identified by release tag and SHA-256 in the diff file.
