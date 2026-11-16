# Exploitation-impact ledger — KEV additions in 2026, snapshot 2026-11-16

96 of 297 KEV entries added in 2026 researched (157 searches recorded). Each record is the best published evidence found for one CVE: exposed instances, compromised hosts, victim organizations, attack volume, downtime, and the earliest public claim of exploitation. Figures were collected by web search and read through a summarizing fetch tool, so quotes are near-verbatim and need checking against the source before publication.

Not researched: 201 entries (listed in the JSON).

## Yield

| best evidence | entries | share |
|---|---:|---:|
| quantified compromise | 12 | 12% |
| exposure only | 21 | 22% |
| attack volume only | 8 | 8% |
| qualitative only | 44 | 46% |
| nothing found | 11 | 11% |

Entries carrying at least one figure of each kind: exposed 29 (30%), compromised 18 (19%), organizations 13 (14%), attack volume 20 (21%), downtime 6 (6%).

## Yield by month added

| month | entries | compromise counted | exposure only | attack volume only | qualitative | nothing | any downtime figure |
|---|---:|---:|---:|---:|---:|---:|---:|
| 2026-01 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| 2026-02 | 4 | 0 | 1 | 0 | 2 | 1 | 0 |
| 2026-03 | 10 | 2 | 1 | 0 | 7 | 0 | 0 |
| 2026-04 | 7 | 0 | 4 | 0 | 2 | 1 | 0 |
| 2026-05 | 3 | 0 | 0 | 1 | 1 | 1 | 0 |
| 2026-06 | 2 | 0 | 0 | 0 | 2 | 0 | 0 |
| 2026-07 | 7 | 0 | 1 | 2 | 3 | 1 | 0 |
| 2026-08 | 5 | 0 | 3 | 0 | 1 | 1 | 0 |
| 2026-09 | 15 | 2 | 1 | 4 | 7 | 1 | 0 |
| 2026-10 | 27 | 8 | 10 | 1 | 8 | 0 | 6 |
| 2026-11 | 15 | 0 | 0 | 0 | 10 | 5 | 0 |

## First public exploitation claim to KEV addition

75 entries have a dated claim from a source other than CISA; 21 do not. Lag in days (KEV date − first claim): median 2, mean 24.3, p25 1, p75 6, p90 29, max 798. Within 3 days: 64%; within 28: 89%; KEV first (negative lag): 0.

## Campaigns with a counted figure

79 campaigns across 96 entries (chained CVEs share one campaign). Largest figure of each kind per campaign; a figure is repeated across the CVEs of a chain in the raw records and counted once here.

| campaign | CVEs | KEV added | compromised | organizations | exposed | attack volume | downtime |
|---|---:|---|---|---|---|---|---|
| Barracuda Networks / Multiple Products | 2 | 2026-11-10 |  | stated |  |  |  |
| OpenBSD / OpenSSH | 1 | 2026-11-09 |  |  |  | 8 attempts from 1 IP |  |
| GPUStack / GPUStack | 1 | 2026-11-09 | stated |  |  |  |  |
| WordPress / WordPress Core | 1 | 2026-11-03 |  |  |  | 13095 |  |
| Ivanti / Connect Secure | 2 | 2026-10-30 |  |  | 5,500 (Shadowserver) |  |  |
| GitLab / Community Edition and Enterprise Edition | 1 | 2026-10-29 |  | 1 (Alpine Linux) | 82,454 (Censys) |  | 8 |
| Cisco / Secure Firewall ASA Software and Cisco Secure FTD So | 1 | 2026-10-29 |  |  | 51,000 (Shadowserver) |  |  |
| Linux / Kernel | 1 | 2026-10-28 | 25 (Dream Security) | 3 (Dream Security) |  |  |  |
| Google / Brotli | 1 | 2026-10-27 |  |  |  | 1 source IP (94.154.43.7) named; no attempt coun |  |
| Adobe / Commerce and Magento | 1 | 2026-10-27 | 471 (Sansec) |  |  | 82% |  |
| PHP Group / PHP | 2 | 2026-10-26 | 25 (Dream Security) |  | 34,400,000 (Censys) | tens of thousands in 45 minutes; hundreds of tho | preemptive service shutdowns (unquantified) |
| Collabora / Collabora Online – Built-in CODE Server | 1 | 2026-10-23 |  | 3 (Administrator reports on Git) |  |  | credential/wallet search; unconfirmed ransomware |
| Arista / VeloCloud Orchestrator | 1 | 2026-10-23 |  |  |  | 2 |  |
| Plex / Media Server | 4 | 2026-10-20 | stated |  | 36,000 (Shadowserver Foundation) |  |  |
| BeyondTrust / Remote Support | 1 | 2026-10-16 | 2 (BeyondTrust) |  | 1,400 (Shadowserver) |  | credential exposure, no outage reported |
| Atlassian / Multiple Products | 1 | 2026-10-15 |  |  |  | 15 |  |
| Cisco / Secure Email Gateway | 1 | 2026-10-14 |  |  | 300 (Shadowserver) |  |  |
| AhsayCBS auth-bypass + command-injection chain (Oct 2026) | 2 | 2026-10-14 |  | 5 (Huntress) |  |  |  |
| Integrity Technology Group / Flax Typhoon (joint advisory AA | 1 | 2026-10-08 |  | stated |  |  |  |
| Citrix / NetScaler | 1 | 2026-10-04 |  |  | 20,000 (Shadowserver) |  | repeated forced reboots, multiple customers (no  |
| NetScaler Sept-2026 zero-days (CVE-2026-88771/88772) | 2 | 2026-09-27 |  | 100 (Kevin Beaumont) | 42,000 (Censys) |  |  |
| Adobe / Commerce and Magento | 1 | 2026-09-24 |  |  |  | exploitation attempts blocked (no count) |  |
| F5 / BIG-IP APM | 1 | 2026-09-22 |  |  | 14,700 (Shadowserver) |  |  |
| Arista / VeloCloud Orchestrator | 1 | 2026-09-22 |  |  |  | 2 |  |
| Cisco / Identity Services Engine | 1 | 2026-09-16 |  |  |  | 540 |  |
| GitLab commits API path traversal (September 2026) | 1 | 2026-09-11 |  |  |  | probing since 06:00 UTC 2026-09-11, no count |  |
| ConnectWise / ScreenConnect | 1 | 2026-09-11 | 3 (Huntress) |  | 1,000 (Shadowserver) |  |  |
| Citrix / NetScaler | 1 | 2026-09-09 |  |  |  | 10 attempts from 6 IPs |  |
| StyleSmuggler | 1 | 2026-09-08 | stated |  |  | 12 |  |
| Citrix / NetScaler ADC and NetScaler Gateway | 1 | 2026-08-26 |  |  | 22,000 (Shadowserver) | 3 |  |
| Gitea / Gitea | 1 | 2026-08-25 | 1 (Anonymous developer on Habr) |  | 8,393 (Shadowserver) |  |  |
| macOS Screen Sharing cryptominer exploitation | 1 | 2026-08-18 | stated |  | 40,000 (Independent researcher @osxr) |  |  |
| Arista / VeloCloud Orchestrator | 1 | 2026-07-27 |  |  |  | 3 |  |
| FortiSandbox June 2026 exploitation | 2 | 2026-07-16 |  |  |  | 49 |  |
| Balbooa / Forms | 1 | 2026-07-10 | 1 (mySites.guru) |  |  |  |  |
| Adobe / ColdFusion | 1 | 2026-07-07 |  |  | 750 (The Shadowserver Foundation) | 107 |  |
| DAEMON Tools Lite supply-chain compromise | 1 | 2026-05-27 | stated |  |  |  |  |
| Drupal / Core | 1 | 2026-05-22 |  |  |  | 15000 |  |
| ScreenConnect SlashAndGrab (CVE-2024-1709 + CVE-2024-1708),  | 1 | 2026-04-28 | stated |  | 8,800 (Censys) |  |  |
| Mirai campaign on EoL D-Link DIR-823X (Akamai SIRT, 2026) | 1 | 2026-04-24 |  |  |  | honeypot exploitation attempts (no count) |  |
| Apache / ActiveMQ | 1 | 2026-04-16 |  |  | 7,500 (Shadowserver Foundation) |  |  |
| FortiClient EMS exploitation March-April 2026 | 2 | 2026-04-06 |  |  | 2,000 (Shadowserver) |  |  |
| F5 BIG-IP APM RCE exploitation 2026 | 1 | 2026-03-27 |  |  | 240,000 (Shadowserver) |  |  |
| TeamPCP Trivy supply-chain compromise | 1 | 2026-03-26 |  | 1,000 (Mandiant Consulting) | 10,000 (Socket) |  |  |
| Craft CMS CVE-2025-32432 / CVE-2024-58136 exploitation (Feb- | 1 | 2026-03-20 | 300 (Orange Cyberdefense) |  | 13,000 (Orange Cyberdefense) |  |  |
| UNC6201 Dell RecoverPoint zero-day | 1 | 2026-02-18 |  | stated |  |  |  |
| GitLab 2021 SSRF flaws added to KEV, February 2026 | 2 | 2026-02-03 |  |  | 49,000 (Shodan) |  |  |
| FortiCloud SSO abuse January 2026 | 1 | 2026-01-27 |  | stated |  |  |  |

## Distribution across campaigns

- **compromised**: 8 campaigns with a number; median 14, max 471, min 1; the largest holds 57% of the sum.
- **organizations**: 6 campaigns with a number; median 4, max 1,000, min 1; the largest holds 90% of the sum.
- **exposed**: 22 campaigns with a number; median 13,850, max 34,400,000, min 300; the largest holds 98% of the sum.

Evidence items: 173; measuring organization's own page read for 43, quoted through a secondary for 59, not recorded for 71 (the October–November pilot predates the field).
