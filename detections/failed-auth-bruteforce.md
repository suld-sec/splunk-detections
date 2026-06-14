# Failed Authentication / Brute Force Detection

## Purpose
Detects credential-guessing attacks by surfacing accounts or source hosts generating a burst of failed logons in a short window. Catches both password spraying (many accounts, few attempts each) and classic brute force (one account, many attempts).

## MITRE ATT&CK
- **T1110** — Brute Force

## SPL
```spl
index=win_sec EventCode=4625
| bucket _time span=5m
| stats count AS failed_attempts,
        dc(user) AS targeted_accounts,
        values(user) AS account_list
        BY _time, src_ip
| where failed_attempts > 20
| sort - failed_attempts
```

## Logic
- `index=win_sec EventCode=4625` — Windows *failed*-logon events.
- `bucket _time span=5m` — groups events into 5-minute windows to catch bursts rather than activity spread thinly over hours.
- `stats count ... BY _time, src_ip` — counts failed attempts per source host per window.
- `dc(user)` — distinct accounts targeted from that source: a high count signals **password spraying**; a low count with high `failed_attempts` signals **brute force** against one account.
- `where failed_attempts > 20` — flags abnormal bursts.

## Tuning
- **Threshold + window:** `20` per 5 minutes is a starting point. Misconfigured apps, expired service-account passwords, and stale mapped drives cause benign floods — baseline before alerting.
- **Spray vs. brute force:** split into two alerts using `targeted_accounts` — high distinct users = spray; single user + high count = brute force. They warrant different responses.
- **Correlate with success:** the highest-value follow-up is a failed-then-succeeded pattern from the same `src_ip` — that's a likely *successful* compromise, not just an attempt.
- **External vs internal:** separate internet-facing sources from internal ones; internal brute force is often more serious (already inside).

## Notes
Sanitized reference rule. Tune thresholds to your authentication baseline before deploying.
