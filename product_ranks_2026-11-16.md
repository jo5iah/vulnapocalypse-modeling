# Product rankings — snapshot 2026-11-16

Exploited: the whole CISA KEV catalog, 1,781 CVEs, 100% carrying CPE applicability.  
Vulnerable: every CVE published 2025-11-16 to 2026-11-16 (365 days), 107,742 CVEs, 43% carrying CPE applicability.

Both sides are counted in one taxonomy — `vendor:product` parsed from NVD's `configurations[].nodes[].cpeMatch[].criteria` — so the two rankings are directly comparable. Counts are CVE-product pairs, not a partition of the corpus: a CVE listing eight affected products contributes to all eight. CPE applicability is added during NVD analysis, so records still awaiting analysis drop out entirely, which censors the most recent weeks hardest.

## Top exploited families (whole KEV catalog)

| rank | vendor:product family | CVEs | share |
|---:|---|---:|---:|
| 1 | `microsoft:windows_server` | 231 | 13.0% |
| 2 | `microsoft:windows` | 228 | 12.8% |
| 3 | `debian:debian_linux` | 125 | 7.0% |
| 4 | `apple:iphone_os` | 94 | 5.3% |
| 5 | `fedoraproject:fedora` | 89 | 5.0% |
| 6 | `microsoft:windows_rt` | 88 | 4.9% |
| 7 | `apple:ipados` | 81 | 4.5% |
| 8 | `google:chrome` | 78 | 4.4% |
| 9 | `apple:macos` | 71 | 4.0% |
| 10 | `redhat:enterprise_linux_server` | 59 | 3.3% |
| 11 | `redhat:enterprise_linux_workstation` | 58 | 3.3% |
| 12 | `redhat:enterprise_linux_desktop` | 57 | 3.2% |
| 13 | `canonical:ubuntu_linux` | 47 | 2.6% |
| 14 | `apple:watchos` | 47 | 2.6% |
| 15 | `opensuse:opensuse` | 45 | 2.5% |

## Top vulnerable families (publication window)

| rank | vendor:product family | CVEs | share |
|---:|---|---:|---:|
| 1 | `google:chrome` | 3,968 | 8.6% |
| 2 | `linux:linux_kernel` | 3,338 | 7.2% |
| 3 | `microsoft:windows` | 2,913 | 6.3% |
| 4 | `microsoft:windows_server` | 2,863 | 6.2% |
| 5 | `apple:macos` | 1,121 | 2.4% |
| 6 | `google:android` | 722 | 1.6% |
| 7 | `apple:iphone_os` | 693 | 1.5% |
| 8 | `apple:ipados` | 692 | 1.5% |
| 9 | `openclaw:openclaw` | 575 | 1.2% |
| 10 | `mozilla:firefox` | 574 | 1.2% |
| 11 | `microsoft:365_apps` | 569 | 1.2% |
| 12 | `microsoft:office` | 563 | 1.2% |
| 13 | `mozilla:thunderbird` | 516 | 1.1% |
| 14 | `apple:visionos` | 432 | 0.9% |
| 15 | `microsoft:microsoft` | 407 | 0.9% |

## Families appearing in both top tens

- `microsoft:windows_server` — exploited rank 1, vulnerable rank 4
- `microsoft:windows` — exploited rank 2, vulnerable rank 3
- `apple:iphone_os` — exploited rank 4, vulnerable rank 7
- `apple:ipados` — exploited rank 7, vulnerable rank 8
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
| 7 | `apple:iphone_os` | 4 |
| 8 | `apple:ipados` | 7 |
| 9 | `openclaw:openclaw` | not in top 50 |
| 10 | `mozilla:firefox` | 49 |

## CISA's own free-text product names, as a cross-check

| rank | vendorProject / product | entries |
|---:|---|---:|
| 1 | Microsoft / Windows | 175 |
| 2 | Apple / Multiple Products | 55 |
| 3 | Google / Chromium V8 | 41 |
| 4 | Microsoft / Internet Explorer | 36 |
| 5 | Adobe / Flash Player | 33 |
| 6 | Linux / Kernel | 32 |
| 7 | Microsoft / Office | 30 |
| 8 | Microsoft / Win32k | 25 |
| 9 | Synacor / Zimbra Collaboration Suite (ZCS) | 17 |
| 10 | Microsoft / Exchange Server | 17 |
