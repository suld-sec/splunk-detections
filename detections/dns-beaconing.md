# DNS Beaconing Detection

## Purpose
Detects malware command-and-control (C2) channels that tunnel over DNS. Beaconing malware "phones home" to its C2 server at regular intervals — this rule surfaces hosts making an unusually high volume of DNS queries to a single domain, a hallmark of DNS-based C2 and exfiltration.

## MITRE ATT&CK
- **T1071.004** — Application Layer Protocol: DNS

## SPL
```spl
index=netfw sourcetype=dns
| stats count AS query_count,
        dc(_time) AS unique_times,
        values(query) AS queried_domains
        BY src_ip, query
| where query_count > 50
| sort - query_count
```

## Logic
- `index=netfw sourcetype=dns` — scopes the search to DNS traffic from the firewall/network logs.
- `stats count BY src_ip, query` — groups DNS requests by source host and the domain queried, counting how many times each host hit each domain.
- `dc(_time)` — counts distinct timestamps, helping separate a few bursts from steady, regular beaconing.
- `where query_count > 50` — flags hosts exceeding a query threshold to a single domain in the search window. Beaconing produces many repeated lookups; normal browsing rarely does to one domain.
- `sort - query_count` — surfaces the noisiest, most suspicious hosts first.

## Tuning
- **Threshold:** `50` is a starting point. Tune to your environment — busy hosts (proxies, mail servers, internal resolvers) generate high legit DNS volume and will false-positive. Raise the threshold or exclude known-good hosts.
- **Whitelisting:** Exclude legitimate high-frequency domains (telemetry, software-update, CDN, time sync) via an allowlist lookup.
- **Stronger signal:** For real beaconing, measure the *regularity* of intervals, not just volume. A follow-up search bucketing query times and measuring variance between them catches low-and-slow beacons that stay under a volume threshold.
- **Pivot:** On a hit, pivot to the full query log for that `src_ip` to inspect the domain (DGA-looking? newly registered? long subdomains suggesting tunneling?).

## Notes
Sanitized reference rule. Index names and thresholds are examples — adapt to your data model and baseline before deploying.
