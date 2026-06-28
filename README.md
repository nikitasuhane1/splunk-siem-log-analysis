# SIEM Log Analysis & Dashboarding — Splunk

## Objective
Ingest and analyse multi-source logs (HTTP, DNS, SSH) 
using Splunk to identify traffic anomalies, 
authentication activity, and potential security threats. 
Build monitoring dashboards for real-time visibility.

## Tools & Technologies
- Splunk SIEM
- Log sources: HTTP access logs, DNS query logs, 
  SSH authentication logs
- SPL (Search Processing Language)

## What I Did
- Ingested logs from multiple sources into Splunk 
  and configured sourcetypes for correct parsing
- Wrote SPL queries to detect failed login attempts, 
  abnormal HTTP request patterns, and suspicious 
  DNS queries
- Correlated events across log sources to identify 
  attack patterns that span multiple protocols
- Built Splunk dashboards with panels for failed 
  login trends, top source IPs, DNS query volume, 
  and SSH activity monitoring

## SPL Queries Used
See the `/spl-queries/` folder for all queries with 
inline comments explaining the detection logic.

Key detections built:
- Brute-force SSH login attempts (>5 failures/10 min)
- HTTP requests with suspicious user-agents or 
  abnormal status code distributions
- DNS queries to rare/newly seen domains

## Dashboard Screenshots
![Security Dashboard](screenshots/dashboard-overview.png)
![Failed Login Detection](screenshots/failed-login-detection.png)

## MITRE ATT&CK Mapping
| Detection | Technique ID | Technique Name |
|---|---|---|
| SSH brute force | T1110 | Brute Force |
| Suspicious HTTP | T1071.001 | Web Protocols |
| DNS anomaly | T1071.004 | DNS |

## Key Learnings
- Multi-source log correlation surfaces attacks 
  that single-source analysis misses
- SPL streamstats is effective for sequence-based 
  detection (failure → success patterns)
- Dashboard design matters — grouping by protocol 
  makes triage faster
