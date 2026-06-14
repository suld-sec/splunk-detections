# Splunk Detection Rules

A collection of Splunk SPL detection rules for SOC threat hunting and security monitoring. Each rule targets a specific adversary behavior, with detection logic, the technique it catches, and tuning notes.

Built and maintained by a SOC team lead working in a financial-services environment. All rules are sanitized — hostnames, IPs, and identifiers are generic examples and contain no production data.

## Why this exists

Most detection content online is either too generic to deploy or buried in vendor docs. These rules are written the way a working SOC actually uses them: clear logic, mapped to MITRE ATT&CK, with notes on what's noisy and how to tune it down.

## Detections

| Rule | Technique | MITRE ATT&CK |
|------|-----------|--------------|
| DNS Beaconing Detection | Periodic C2 callbacks over DNS | T1071.004 |
| Lateral Movement (Auth) | Anomalous cross-host authentication | T1021 |
| Failed Auth / Brute Force | Credential-guessing bursts | T1110 |

## Structure

Each detection lives in its own file with:
- **Purpose** — what adversary behavior it catches
- **SPL** — the Splunk search
- **Logic** — how it works, field by field
- **Tuning** — known false positives and how to reduce them
- **MITRE mapping** — technique reference

## Disclaimer

These rules are provided as-is for educational and reference purposes. Test in a non-production environment and tune to your own data before deploying. No warranty is implied.

## License

MIT — see [LICENSE](LICENSE).
