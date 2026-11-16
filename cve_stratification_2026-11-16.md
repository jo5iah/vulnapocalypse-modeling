# CVE stratification — 365 days to 2026-11-16

Built by `cve_strata.py report` from `data/cve_strata.csv.gz` (last synced with NVD 2026-11-16T18:00:32 UTC, table floor 2025-11-16). **Published**: 107,720 CVEs with an NVD publication date in (2025-11-16, 2026-11-16]. **KEV additions**: 321 CVEs CISA added in the same window, whatever their publication date; 246 of them were also published in it. *Per 1,000 published* divides the two, the stratified analogue of the model's conversion; *lift* is a class's share of KEV additions over its share of publications.

## Coverage of each field

| field | published in window | KEV additions |
|---|---:|---:|
| vendor from NVD CPE applicability | 42.8% | 100.0% |
| vendor from the assigner's `affected` block | 49.5% | 0.0% |
| any vendor | 92.3% | 100.0% |
| CVSS vector (exposure class) | 93.6% | 100.0% |
| … scored by NVD itself | 7.8% | 23.1% |
| weakness type (CWE) | 90.4% | 99.4% |
| SSVC decision points (CISA) | 90.3% | 100.0% |

## By exposure class

| exposure (CVSS) | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| remote, no privileges, no user action | 33,324 | 30.9% | 185 | 57.6% | 5.6 | 1.9× | 152 |
| remote, other | 47,171 | 43.8% | 87 | 27.1% | 1.8 | 0.6× | 60 |
| local or physical | 20,363 | 18.9% | 49 | 15.3% | 2.4 | 0.8× | 34 |
| unscored | 6,862 | 6.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By vendor: the 20 with most KEV additions, and the rest

Vendors are chosen by exploitation, not volume. Rates for vendors whose CVEs are often unanalyzed are overstated to the extent their publications sit in *(no vendor recorded)*.

| vendor | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| microsoft | 5,665 | 5.3% | 42 | 13.1% | 7.4 | 2.5× | 29 |
| cisco | 406 | 0.4% | 22 | 6.9% | 54.2 | 18.2× | 20 |
| apple | 1,260 | 1.2% | 12 | 3.7% | 9.5 | 3.2× | 7 |
| google | 4,935 | 4.6% | 12 | 3.7% | 2.4 | 0.8× | 12 |
| fortinet | 256 | 0.2% | 11 | 3.4% | 43.0 | 14.4× | 11 |
| linux | 9,322 | 8.7% | 8 | 2.5% | 0.9 | 0.3× | 4 |
| ivanti | 65 | 0.1% | 8 | 2.5% | 123.1 | 41.3× | 8 |
| adobe | 1,269 | 1.2% | 7 | 2.2% | 5.5 | 1.9× | 5 |
| oracle | 4,154 | 3.9% | 6 | 1.9% | 1.4 | 0.5× | 3 |
| sonicwall | 53 | 0.0% | 6 | 1.9% | 113.2 | 38.0× | 6 |
| citrix | 45 | 0.0% | 6 | 1.9% | 133.3 | 44.7× | 6 |
| synacor | 25 | 0.0% | 5 | 1.6% | 200.0 | 67.1× | 3 |
| vmware | 195 | 0.2% | 5 | 1.6% | 25.6 | 8.6× | 3 |
| langflow | 218 | 0.2% | 5 | 1.6% | 22.9 | 7.7× | 5 |
| paloaltonetworks | 112 | 0.1% | 5 | 1.6% | 44.6 | 15.0× | 5 |
| checkpoint | 23 | 0.0% | 5 | 1.6% | 217.4 | 73.0× | 5 |
| gitlab | 271 | 0.3% | 4 | 1.2% | 14.8 | 5.0× | 2 |
| solarwinds | 48 | 0.0% | 4 | 1.2% | 83.3 | 28.0× | 3 |
| arista | 9 | 0.0% | 4 | 1.2% | 444.4 | 149.1× | 4 |
| jfrog | 45 | 0.0% | 4 | 1.2% | 88.9 | 29.8× | 4 |
| (other vendors) | 71,084 | 66.0% | 140 | 43.6% | 2.0 | 0.7× | 101 |
| (no vendor recorded) | 8,260 | 7.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## Vendor × exposure: KEV additions / published, per 1,000

| vendor | remote, no privileges, no user action | remote, other | local or physical | unscored |
|---|---:|---:|---:|---:|
| microsoft | 10/775 = 12.9 | 16/1,679 = 9.5 | 16/3,211 = 5.0 | — |
| cisco | 16/200 = 80.0 | 3/170 = 17.6 | 3/36 = 83.3 | — |
| apple | 1/279 = 3.6 | 5/268 = 18.7 | 6/713 = 8.4 | — |
| google | 1/276 = 3.6 | 8/3,827 = 2.1 | 3/832 = 3.6 | — |
| fortinet | 9/91 = 98.9 | 2/139 = 14.4 | 0/26 = 0.0 | — |
| linux | 1/1,190 = 0.8 | 0/118 = 0.0 | 7/4,270 = 1.6 | 0/3,744 = 0.0 |
| ivanti | 5/17 = 294.1 | 2/38 = 52.6 | 1/10 = 100.0 | — |
| adobe | 3/162 = 18.5 | 2/543 = 3.7 | 2/564 = 3.5 | — |
| oracle | 5/1,350 = 3.7 | 0/2,214 = 0.0 | 1/590 = 1.7 | — |
| sonicwall | 3/15 = 200.0 | 2/30 = 66.7 | 1/8 = 125.0 | — |
| citrix | 6/33 = 181.8 | 0/1 = 0.0 | 0/11 = 0.0 | — |
| synacor | 2/1 = 2000.0 | 3/24 = 125.0 | — | — |
| vmware | 4/101 = 39.6 | 1/79 = 12.7 | 0/15 = 0.0 | — |
| langflow | 3/62 = 48.4 | 2/154 = 13.0 | 0/2 = 0.0 | — |
| paloaltonetworks | 4/38 = 105.3 | 1/34 = 29.4 | 0/40 = 0.0 | — |
| checkpoint | 4/14 = 285.7 | 0/4 = 0.0 | 1/5 = 200.0 | — |
| gitlab | 4/47 = 85.1 | 0/223 = 0.0 | 0/1 = 0.0 | — |
| solarwinds | 4/11 = 363.6 | 0/34 = 0.0 | 0/3 = 0.0 | — |
| arista | 3/3 = 1000.0 | 1/6 = 166.7 | — | — |
| jfrog | 2/6 = 333.3 | 2/38 = 52.6 | 0/1 = 0.0 | — |
| (other vendors) | 95/26,065 = 3.6 | 37/35,298 = 1.0 | 8/9,589 = 0.8 | 0/132 = 0.0 |
| (no vendor recorded) | 0/2,588 = 0.0 | 0/2,250 = 0.0 | 0/436 = 0.0 | 0/2,986 = 0.0 |

## By weakness type: the 15 with most KEV additions

A CVE with several CWEs counts under each, so these rows overlap and do not sum.

| CWE | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-78 | 2,432 | 2.3% | 21 | 6.5% | 8.6 | 2.9× | 19 |
| CWE-287 | 1,479 | 1.4% | 19 | 5.9% | 12.8 | 4.3× | 12 |
| CWE-94 | 2,285 | 2.1% | 19 | 5.9% | 8.3 | 2.8× | 14 |
| CWE-22 | 3,399 | 3.2% | 18 | 5.6% | 5.3 | 1.8× | 10 |
| CWE-787 | 2,565 | 2.4% | 14 | 4.4% | 5.5 | 1.8× | 12 |
| CWE-306 | 2,120 | 2.0% | 14 | 4.4% | 6.6 | 2.2× | 13 |
| CWE-502 | 1,499 | 1.4% | 14 | 4.4% | 9.3 | 3.1× | 10 |
| CWE-416 | 3,744 | 3.5% | 13 | 4.0% | 3.5 | 1.2× | 8 |
| CWE-434 | 1,063 | 1.0% | 11 | 3.4% | 10.3 | 3.5× | 6 |
| CWE-918 | 2,395 | 2.2% | 11 | 3.4% | 4.6 | 1.5× | 7 |
| CWE-119 | 1,497 | 1.4% | 10 | 3.1% | 6.7 | 2.2× | 6 |
| CWE-89 | 4,677 | 4.3% | 9 | 2.8% | 1.9 | 0.6× | 8 |
| CWE-20 | 2,241 | 2.1% | 9 | 2.8% | 4.0 | 1.3× | 8 |
| CWE-288 | 352 | 0.3% | 9 | 2.8% | 25.6 | 8.6× | 8 |
| CWE-77 | 1,242 | 1.2% | 8 | 2.5% | 6.4 | 2.2× | 6 |

## By CVSS severity

| severity | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| CRITICAL | 11,306 | 10.5% | 147 | 45.8% | 13.0 | 4.4× | 123 |
| HIGH | 42,871 | 39.8% | 139 | 43.3% | 3.2 | 1.1× | 94 |
| MEDIUM | 39,595 | 36.8% | 34 | 10.6% | 0.9 | 0.3× | 28 |
| LOW | 7,017 | 6.5% | 1 | 0.3% | 0.1 | 0.0× | 1 |
| NONE | 69 | 0.1% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| unscored | 6,862 | 6.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By CISA's SSVC exploitation value

CISA's own assessment at the time it enriched the record: `none`, `poc` (a public proof of concept) or `active`. KEV additions are `active` by construction; the useful rows are how many published CVEs carry `poc`, the supply a PoC-conditioned hazard would act on.

| exploitation | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| active | 246 | 0.2% | 321 | 100.0% | 1304.9 | 437.9× | 246 |
| poc | 21,139 | 19.6% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| none | 75,866 | 70.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| (not assessed) | 10,469 | 9.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By SSVC automatable

| automatable | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| yes | 24,582 | 22.8% | 155 | 48.3% | 6.3 | 2.1× | 129 |
| no | 72,669 | 67.5% | 166 | 51.7% | 2.3 | 0.8× | 117 |
| (not assessed) | 10,469 | 9.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## How much composition a single population rate misses

Share of KEV additions that one population-wide rate assigns to the wrong class (half the summed absolute difference between observed and expected additions). This is the baseline a stratified calibration has to beat without being fitted to it.

| partition | classes | misallocated |
|---|---:|---:|
| exposure | 4 | 26.7% |
| vendor (top 20 + 2) | 22 | 39.0% |
| vendor × exposure | 67 | 45.3% |
| severity | 6 | 38.8% |
