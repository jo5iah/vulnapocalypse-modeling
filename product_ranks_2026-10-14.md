# Product rankings — snapshot 2026-10-14

Exploited: the whole CISA KEV catalog, 1,741 CVEs, 100% carrying CPE applicability.  
Vulnerable: every CVE published 2025-10-14 to 2026-10-14 (365 days), 94,256 CVEs, 46% carrying CPE applicability.

Both sides are counted in one taxonomy — `vendor:product` parsed from NVD's `configurations[].nodes[].cpeMatch[].criteria` — so the two rankings are directly comparable. Counts are CVE-product pairs, not a partition of the corpus: a CVE listing eight affected products contributes to all eight. CPE applicability is added during NVD analysis, so records still awaiting analysis drop out entirely, which censors the most recent weeks hardest.

## Top exploited families (whole KEV catalog)

| rank | vendor:product family | CVEs | share |
|---:|---|---:|---:|
| 1 | `microsoft:windows_server` | 231 | 13.3% |
| 2 | `microsoft:windows` | 228 | 13.1% |
| 3 | `debian:debian_linux` | 124 | 7.1% |
| 4 | `apple:iphone_os` | 93 | 5.3% |
| 5 | `fedoraproject:fedora` | 88 | 5.1% |
| 6 | `microsoft:windows_rt` | 88 | 5.1% |
| 7 | `apple:ipados` | 80 | 4.6% |
| 8 | `google:chrome` | 77 | 4.4% |
| 9 | `apple:macos` | 70 | 4.0% |
| 10 | `redhat:enterprise_linux_server` | 59 | 3.4% |
| 11 | `redhat:enterprise_linux_workstation` | 58 | 3.3% |
| 12 | `redhat:enterprise_linux_desktop` | 57 | 3.3% |
| 13 | `canonical:ubuntu_linux` | 47 | 2.7% |
| 14 | `apple:watchos` | 46 | 2.6% |
| 15 | `opensuse:opensuse` | 45 | 2.6% |

## Top vulnerable families (publication window)

| rank | vendor:product family | CVEs | share |
|---:|---|---:|---:|
| 1 | `google:chrome` | 3,314 | 7.7% |
| 2 | `linux:linux_kernel` | 3,047 | 7.1% |
| 3 | `microsoft:windows` | 2,022 | 4.7% |
| 4 | `microsoft:windows_server` | 1,981 | 4.6% |
| 5 | `apple:macos` | 844 | 2.0% |
| 6 | `google:android` | 594 | 1.4% |
| 7 | `mozilla:firefox` | 585 | 1.4% |
| 8 | `openclaw:openclaw` | 575 | 1.3% |
| 9 | `apple:iphone_os` | 562 | 1.3% |
| 10 | `apple:ipados` | 561 | 1.3% |
| 11 | `mozilla:thunderbird` | 506 | 1.2% |
| 12 | `microsoft:365_apps` | 479 | 1.1% |
| 13 | `microsoft:office` | 467 | 1.1% |
| 14 | `apple:visionos` | 334 | 0.8% |
| 15 | `adobe:experience_manager` | 332 | 0.8% |

## Families appearing in both top tens

- `microsoft:windows_server` — exploited rank 1, vulnerable rank 4
- `microsoft:windows` — exploited rank 2, vulnerable rank 3
- `apple:iphone_os` — exploited rank 4, vulnerable rank 9
- `apple:ipados` — exploited rank 7, vulnerable rank 10
- `google:chrome` — exploited rank 8, vulnerable rank 1
- `apple:macos` — exploited rank 9, vulnerable rank 5

## Where each top-ten vulnerable family sits in the exploitation catalog

| vulnerable rank | family | exploited rank |
|---:|---|---:|
| 1 | `google:chrome` | 8 |
| 2 | `linux:linux_kernel` | 25 |
| 3 | `microsoft:windows` | 2 |
| 4 | `microsoft:windows_server` | 1 |
| 5 | `apple:macos` | 9 |
| 6 | `google:android` | 32 |
| 7 | `mozilla:firefox` | 47 |
| 8 | `openclaw:openclaw` | not in top 50 |
| 9 | `apple:iphone_os` | 4 |
| 10 | `apple:ipados` | 7 |

## CISA's own free-text product names, as a cross-check

| rank | vendorProject / product | entries |
|---:|---|---:|
| 1 | Microsoft / Windows | 175 |
| 2 | Apple / Multiple Products | 54 |
| 3 | Google / Chromium V8 | 41 |
| 4 | Microsoft / Internet Explorer | 36 |
| 5 | Adobe / Flash Player | 33 |
| 6 | Linux / Kernel | 31 |
| 7 | Microsoft / Office | 29 |
| 8 | Microsoft / Win32k | 25 |
| 9 | Synacor / Zimbra Collaboration Suite (ZCS) | 17 |
| 10 | Microsoft / Exchange Server | 17 |
