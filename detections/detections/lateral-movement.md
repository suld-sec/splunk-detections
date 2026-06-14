# Lateral Movement Detection (Authentication)

## Purpose
Detects an account authenticating to an unusually high number of distinct hosts in a short window — a common signature of lateral movement, where an attacker uses stolen or forged credentials to spread across the network after an initial foothold.

## MITRE ATT&CK
- **T1021** — Remote Services

## SPL
```spl
index=win_sec EventCode=4624
| stats dc(dest_host) AS hosts_accessed,
        values(dest_host) AS host_list,
        count AS logon_count
        BY user
| where hosts_accessed > 10
| sort - hosts_accessed
```

## Logic
- `index=win_sec EventCode=4624` — Windows successful-logon events.
- `dc(dest_host) BY user` — counts how many *distinct* hosts each account logged into during the search window.
- `where hosts_accessed > 10` — flags accounts touching an abnormal number of machines. A normal user hits a handful; an attacker pivoting hits many.
- `sort - hosts_accessed` — most-spread accounts first.

## Tuning
- **Service accounts** are the main false positive — backup, monitoring, scanning, and admin automation accounts legitimately touch many hosts. Build an allowlist of known service accounts and exclude them.
- **Logon type matters:** add `Logon_Type=3` (network) or `Logon_Type=10` (RemoteInteractive/RDP) to focus on remote access, which is more relevant to lateral movement than local logons.
- **Threshold:** `10` is a baseline. Profile your environment's normal first — admins and helpdesk accounts may legitimately run higher.
- **Pivot:** On a hit, review the `host_list` and timeline — rapid sequential access across hosts in minutes is far more suspicious than the same count spread over a day.

## Notes
Sanitized reference rule. Field names (`dest_host`, `user`) follow common CIM mappings — adjust to your data model.
