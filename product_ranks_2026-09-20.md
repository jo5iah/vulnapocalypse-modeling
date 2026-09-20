# Product rankings — snapshot 2026-09-20

Exploited: the whole CISA KEV catalogue, 1,716 CVEs, 100% carrying CPE applicability.  
Vulnerable: every CVE published 2025-09-20 to 2026-09-20 (365 days), 84,864 CVEs, 49% carrying CPE applicability.

Both sides are counted in one taxonomy — `vendor:product` parsed from NVD's `configurations[].nodes[].cpeMatch[].criteria` — so the two rankings are directly comparable. Counts are CVE-product pairs, not a partition of the corpus: a CVE listing eight affected products contributes to all eight. CPE applicability is added during NVD analysis, so records still awaiting analysis drop out entirely, which censors the most recent weeks hardest.

## Top exploited families (whole KEV catalogue)

| rank | vendor:product family | CVEs | share |
|---:|---|---:|---:|
| 1 | `microsoft:windows_server` | 230 | 13.4% |
| 2 | `microsoft:windows` | 227 | 13.2% |
| 3 | `debian:debian_linux` | 122 | 7.1% |
| 4 | `apple:iphone_os` | 92 | 5.4% |
| 5 | `microsoft:windows_rt` | 88 | 5.1% |
| 6 | `fedoraproject:fedora` | 86 | 5.0% |
| 7 | `apple:ipados` | 79 | 4.6% |
| 8 | `google:chrome` | 77 | 4.5% |
| 9 | `apple:macos` | 70 | 4.1% |
| 10 | `redhat:enterprise_linux_server` | 59 | 3.4% |
| 11 | `redhat:enterprise_linux_workstation` | 58 | 3.4% |
| 12 | `redhat:enterprise_linux_desktop` | 57 | 3.3% |
| 13 | `canonical:ubuntu_linux` | 46 | 2.7% |
| 14 | `apple:watchos` | 46 | 2.7% |
| 15 | `opensuse:opensuse` | 44 | 2.6% |

## Top vulnerable families (publication window)

| rank | vendor:product family | CVEs | share |
|---:|---|---:|---:|
| 1 | `linux:linux_kernel` | 3,413 | 8.2% |
| 2 | `google:chrome` | 2,872 | 6.9% |
| 3 | `microsoft:windows` | 1,656 | 4.0% |
| 4 | `microsoft:windows_server` | 1,626 | 3.9% |
| 5 | `apple:macos` | 838 | 2.0% |
| 6 | `openclaw:openclaw` | 575 | 1.4% |
| 7 | `apple:iphone_os` | 555 | 1.3% |
| 8 | `apple:ipados` | 554 | 1.3% |
| 9 | `google:android` | 479 | 1.2% |
| 10 | `mozilla:firefox` | 457 | 1.1% |
| 11 | `microsoft:365_apps` | 390 | 0.9% |
| 12 | `microsoft:office` | 378 | 0.9% |
| 13 | `mozilla:thunderbird` | 373 | 0.9% |
| 14 | `adobe:experience_manager` | 332 | 0.8% |
| 15 | `apple:visionos` | 330 | 0.8% |

## Families appearing in both top tens

- `microsoft:windows_server` — exploited rank 1, vulnerable rank 4
- `microsoft:windows` — exploited rank 2, vulnerable rank 3
- `apple:iphone_os` — exploited rank 4, vulnerable rank 7
- `apple:ipados` — exploited rank 7, vulnerable rank 8
- `google:chrome` — exploited rank 8, vulnerable rank 2
- `apple:macos` — exploited rank 9, vulnerable rank 5

## Where each top-ten vulnerable family sits in the exploitation catalogue

| vulnerable rank | family | exploited rank |
|---:|---|---:|
| 1 | `linux:linux_kernel` | 25 |
| 2 | `google:chrome` | 8 |
| 3 | `microsoft:windows` | 2 |
| 4 | `microsoft:windows_server` | 1 |
| 5 | `apple:macos` | 9 |
| 6 | `openclaw:openclaw` | not in top 50 |
| 7 | `apple:iphone_os` | 4 |
| 8 | `apple:ipados` | 7 |
| 9 | `google:android` | 32 |
| 10 | `mozilla:firefox` | 47 |

## CISA's own free-text product names, as a cross-check

| rank | vendorProject / product | entries |
|---:|---|---:|
| 1 | Microsoft / Windows | 174 |
| 2 | Apple / Multiple Products | 53 |
| 3 | Google / Chromium V8 | 41 |
| 4 | Microsoft / Internet Explorer | 36 |
| 5 | Adobe / Flash Player | 33 |
| 6 | Linux / Kernel | 31 |
| 7 | Microsoft / Office | 29 |
| 8 | Microsoft / Win32k | 25 |
| 9 | Synacor / Zimbra Collaboration Suite (ZCS) | 17 |
| 10 | Microsoft / Exchange Server | 17 |
