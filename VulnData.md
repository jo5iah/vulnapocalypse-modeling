
# The Data Behind the Model: Vulnerability Disclosure and Exploitation, Measured

This page documents the data behind
[Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model](https://jo5iah.github.io/vulnapocalypse-modeling/).
It lists the sources and the measured quantities, and shows how every model parameter is obtained. It states
the known biases in the source data and shows the shape of the inflow. It then tests the model against the
catalog and the corpus. Snapshot: **2026-11-16**.

Acquisition is in `VulnData.ipynb`. It queries the sources, caches every response under `data/`, writes
every model input and draws the figure on this page. Visualization and section numbers refer to the model
document. Bracketed numbers refer to its
[reference list](https://jo5iah.github.io/vulnapocalypse-modeling/#references).

Contents

- [Sources](#sources)
- [Measured quantities](#measured-quantities)
- [Every parameter, and how it is obtained](#every-parameter-and-how-it-is-obtained)
- [Biases in the source data](#biases-in-the-source-data)
- [The shape of the inflow](#the-shape-of-the-inflow)
- [Checks against the catalog and the corpus](#checks-against-the-catalog-and-the-corpus)
    - [1. Exploited stock, global](#1-exploited-stock-global)
    - [2. Exploited stock, SharePoint](#2-exploited-stock-sharepoint)
    - [3. Backlog size](#3-backlog-size)
    - [4. Is discovery supply-limited?](#4-is-discovery-supply-limited)
    - [How independent the checks are](#how-independent-the-checks-are)

## Sources

| Source | Provides | Used for |
|---|---|---|
| **NVD** [1] | the CVE corpus, publication dates, CVSS attack vectors, CPE applicability, and the KEV flags mirrored into each record | $\gamma$, $\varepsilon$, publication history, backlog check, product ranks |
| **CISA KEV** [2] | which CVEs are known-exploited, and the date CISA added each | the additions that calibrate $C$ and the hazards along the measured history; the anchor test |
| **MITRE CVE Services** [3] | CNA publication timestamps | confirming NVD's dates are not materially lagged |
| Verizon 2026 DBIR [4] | 26% of known-exploited flaws ever fully patched; 43-day median time to fix for those that are | $f$, $\tau$ |
| CrowdStrike 2026 [5] | a 42% rise in zero-days exploited before public disclosure | context for the pre-disclosure channel; a growth rate, not a share |
| VulnCheck [20, 21] | 28.3% of newly exploited CVEs evidenced within a day of publication; its lead over KEV | the fast n-day share, hence $\beta_n$; the KEV bias below |
| Mandiant M-Trends 2026 [6] | time-to-exploit estimated at −7 days for 2025 | corroborates the pre-disclosure channel |
| ZDI, July 2026 [7]; Tenable [25]; MSRC [26] | Microsoft shipped 621 CVEs with 3 under active exploit (2 on release day, a third flagged the next); 6.6× its 2025 monthly average of 94 | Visualization 6; Future work §5 |
| Verizon 2025 DBIR [22]; Imperva [23]; EPSS v3 [24] | where exploitation concentrates, and its breadth per vulnerability | Limitations 1 and 2 |
| Synopsys OSSRA 2024 [8] | mean open-source vulnerability age over 2.5 years; nearly a quarter of codebases carry flaws more than 10 years old | $1/\lambda$ |
| Anthropic *n-days* [9]; CVE-Genie [10]; Pesoli, Errico & Cavallaro [11] | machine-generated exploits under an hour after a patch ships; reproduction at a few dollars per CVE and privilege-escalation chains at about $2,000 each; the caveat that these are reproductions rather than production chains | the throughput axis of Visualization 6; Future work §4 |
| FIRST EPSS [14] | exploit-prediction scores | Limitation 1; Future work §1 |

Two analyses sit beside the model. `anchor_gap.py` reproduces the anchor correction below in full.
`product_ranks.py` builds the per-product rankings quoted in the model's executive summary, and writes
`product_ranks_<snapshot>.md` as a standalone report. The rankings are not model outputs. Nothing in the
model depends on them.

## Measured quantities

| Quantity | Global | SharePoint |
|---|---|---|
| CVE corpus | 426,069 | 747 (across 8 CPE product names) |
| Publication rate | **297.3/day** trailing year (used); 523.9/day most recent quarter | **0.225/day** 3-year (used); 0.499/day trailing year |
| Publication history | 2008–2026: 5,664 → 115,045/yr (2026 annualized), CAGR **+39%** for 2021–2026 | 2003–2026; 2026 annualizes to 202, the highest on record |
| Known-exploited (KEV) | 1,781 = 0.42% of corpus; **915** added from 2023 to the snapshot (0.647/day) calibrate the model | 22 = **2.9%**, i.e. **7.0×** the global rate |
| Disclosure → KEV lag | median 216 d (p10 0, p90 2,577) | median 85 d |
| Exploited by publication day | **13.4%** in KEV, a floor | 3 of 22 |
| Network-reachable (CVSS AV:N/A) | 75.6% | 78.6% |
| Ever fully patched | **26%**; median time to fix **43 days** for those that are | same figure applied |

## Every parameter, and how it is obtained

Each parameter falls in one of three classes. A *measured* value comes directly from a source. A
*calibrated* value is set so the model reproduces a measured quantity. An *assumed* value has no source and
is stated as a choice.

| Symbol | Meaning | Value (global; SharePoint) | Class | Basis | Tested in |
|---|---|---|---|---|---|
| $\gamma$ | publication rate | 297.3/day; 0.225/day | measured | NVD, trailing 364 days; SharePoint over three years (see biases) | Viz 8, 9 |
| — | KEV additions the model is calibrated to | 915 from 2023-01-01 (0.647/day); 22 over five years | measured | KEV `dateAdded`, matched by the model's conversion integrated along the measured history (biases, below) | anchor check |
| — | pre-disclosure share of exploitation | 13.4%; 14% | measured | KEV entries exploited on or before NVD publication, global and SharePoint. A floor, since CISA dates exploitation by its evidence | — |
| $\varepsilon$ | reachable share of supply | 0.756; 0.786 | measured | CVSS attack vector of KEV entries / SharePoint CVEs | Viz 5 |
| $\tau$ | days before patch adoption begins | 43 d | measured | DBIR median time to fix [4] | Viz 3, 5, 10 |
| — | ever-fully-patched share | 26% | measured | DBIR [4] | Viz 4 |
| $f$ | share routed to the remediable compartment | 0.265; 0.266 | calibrated | set so the realized ever-patched share is 26% | Viz 3, 4 |
| — | share of post-disclosure exploitation within one day of disclosure | 28% | measured | VulnCheck 2025 Q1 [20]: 28.3% of 159 newly exploited CVEs. The source counts all exploitation, not only post-disclosure, so the split is approximate | — |
| $\beta_h, \beta_n, \beta_x$ | exploitation hazards | — | calibrated | their split, so supply divides into the measured pre-disclosure, fast n-day and aged shares; their level, with $C$, as below | — |
| $C$ | attacker throughput ceiling | 2.42/day; 0.036/day | calibrated | with the hazard level, so that the model's conversion along the measured history reproduces the KEV additions above, and $P/C$ holds on today's state | Viz 6 |
| $P/C$ | supply relative to throughput, today | 1 (results reported over 0.5–2) | **assumed** | No source measures it. 1 is where the catalog's growth sits. KEV additions rose 81% from 2023 to 2026, against 82% in the model at 1 and 59% at 2. Publications per cataloged exploit widened ×1.66, against ×1.72 and ×1.85 (`anchor_gap.py`). A rising weaponization rate fits the same data at higher values | Viz 6 |
| $\rho$ | patch adoption rate once begun | 0.2/day (5 days to complete) | **assumed** | chosen so $\tau + 1/\rho$ = 48 d sits near the 43-day median | Viz 3 |
| $\delta$ | runtime mitigation of exploited flaws | 0.003/day | **assumed** | no public measurement | Viz 3 |
| $\delta_d$ | disclosure rate | 1/45 day⁻¹ | **assumed** | the 90-day coordinated-disclosure norm, with many vendor-found bugs faster | — |
| $\mu$ | maturation into the backlog | 1/30 day⁻¹ | **assumed** | one patch cycle | Viz 3 |
| $\phi$ | retirement from support | 1/1825; 1/3650 day⁻¹ | **assumed** | 5- and 10-year support horizons | backlog check |
| $\lambda$ | decommissioning of exploited software | 1/2000; 1/1825 day⁻¹ | **assumed** | OSSRA vulnerability ages [8]; SharePoint's shorter horizon is required by its anchor (below) | anchor check; Viz 4 |

The weakest links are the two assumed quantities the results depend on most. $P/C$ sets every attacker-side
sensitivity. $\lambda$ sets the level.

## Biases in the source data

Three biases act in a known direction. None is corrected for.

**Publication-date rates are undercounts.** A window's count is not fixed when the window closes. NVD keeps
ingesting records whose publication date falls inside it. The window 2026-05-07 → 2026-08-06 returned 25,148
when first counted on 2026-08-06, and **25,361 eight days later, +0.85%**. Re-queried thirteen days after
that, on 2026-08-27, it still returned 25,361. It returned the same on 2026-10-14 and 2026-11-16. The
late-arrival tail is essentially complete within a fortnight.

Daily counts agree. Of the days first counted at the 2026-10-14 snapshot, only the snapshot day itself
changed when re-queried, from 732 to 829, because it was still filling. From 2026-10-14 to this snapshot the
corpus grew by 546 a day, against a windowed publication rate of 524 a day.

Every $\gamma$ here is therefore low, and lowest for the most recent weeks. The acceleration is understated,
not overstated. The 2008–2026 history that drives the model's transient is the measured monthly series for
the global ecosystem, with each month's rate held constant within it. SharePoint uses annual rates.

**Single-product rates are quantized by release cadence.** SharePoint gained 29 CVEs in the eight days to
2026-08-14. All were published on 2026-08-11, one Patch Tuesday, and they moved its trailing-year rate by 22%.
The model uses the 3-year rate for that reason.

**KEV is a lower bound on exploitation, and its additions reflect cataloging policy.** Annual additions ran
311, 555, 187, 186 and 245 for 2021–2025. 2026 has 297 so far, already more than any year but 2022.

The model is therefore calibrated to additions pooled over a window, not year by year: 915 from 2023-01-01 to
the snapshot, over 1,415 days, or **0.647/day**. The model's own conversion, integrated along the measured
history over the same days, matches that rate. Pooling damps the year-to-year swing and gives the partial
current year its true weight.

The window starts in 2023 because KEV opened in November 2021. Its 311 additions that year and 555 in 2022
(226 of them in March) are a backfill of earlier exploitation, not a rate. Including 2022 would raise today's
count 37%. Starting in 2024 instead changes it by 1%.

VulnCheck's catalog lists exploitation earlier than KEV in two-thirds (67.6%) of the 376 CVEs the two shared
in 2024–2025, by a mean of 28 days and a median of 3 [21]. The influx, and the throughput $C$ calibrated from
it, are floors. Future work §5 of the model document measures exploitation from vendor announcements, ahead
of the catalog.

## The shape of the inflow

![Velocity, acceleration and jerk of CVE publication and of KEV additions, on a monthly grid
over 2008-2026 and a daily grid over the recent window](figure:inflow_derivatives)

Both inflows are differentiated as cumulative counts. The rows are therefore the rate itself, its rate of
change, and whether *that* is turning. The monthly columns use a filter wide enough to find a turning point
in nineteen years. That filter extrapolates across its own two-year half-window at each end, so the monthly
columns describe history, not the present. The daily columns describe the present and nothing earlier.

**On the monthly grid, the publication series has no turning point.** Acceleration has been positive
continuously since **2018-12**, and jerk since **2019-09**. Each run is far longer than the 24-month dwell a
sign change must clear. The inflow is growing by a growing amount, and has been for most of a decade.

At this snapshot the acceleration dips below zero in the interior's last month, 2024-09, to −5 CVEs/day per
year, inside a bootstrap band of −7 to +10. That is one month against a 24-month dwell, so it is not counted.
It comes from the filter, not the data. The window centered there now holds 2026's surge in its right half,
and the cubic undershoots in the middle. The smoothed rate there, 97 a day, sits below 2024's measured 111.
Jerk at the same month is the highest in the record.

**KEV resolves no turning point either.** At 0.8 additions a day against a 25-month window, that is expected.
Its level is not flat. The smoothed rate runs from 0.15/day in early 2023 to 0.69/day by mid-2025. Annual
rates are 0.51, 0.51, 0.67 and 0.93 per day for 2023 to 2026.

**What the two series show is a divergence in pace.** From 2025 to 2026, disclosure rose **130%** (136.9 to
315.0 a day) and cataloged exploitation rose **38%**. Publications per cataloged exploit went from **204 to
339**, and to **414** across the last ninety days. October 2026 published 564 CVEs a day, the highest
complete month on record, and drew 36 KEV additions. September's 43 remain the most in any month since
June 2022. The last ninety days hold 111 additions, 1.23 a day, the most in any ninety days since 2022. The
ninety-day ratio therefore narrowed from 439 at the 2026-10-14 snapshot, while the annual ratio still
widened.

**Most of that widening is not attackers saturating.** Driven month by month, the model widens publications
per cataloged exploit by ×1.49 from 2025 to 2026, even with throughput ten times supply, where there is almost
no saturation. The reason is the backlog. At equilibrium 62% of supply comes from a backlog that takes five
years to fill, so supply grows far more slowly than publication.

The remaining widening places the ratio of supply to capacity near 0.5 to 1. There the model gives ×1.61 and
×1.72, against the measured ×1.66. The catalog's compounded growth from 2023 to 2026, +81%, matches the
model's +82% at a ratio of 1 (+59% at 2). Single years swing by about twenty points on cataloging policy
(−1%, +32%, +38%), so they are not used alone. A rate of weaponization that is itself rising would produce
the same pattern at higher saturation. This comparison places the ratio; it does not measure it.
`anchor_gap.py` reproduces it.

**The daily columns oscillate on a monthly beat.** Smoothed publication moves between about 360 and 690 a
day inside the measured interior, as vendor releases arrive. A centered 7-day mean removes the weekly cycle.
Nothing removes the monthly one, so no daily sign change is counted unless it outlasts a full cadence. None
does, in either series. Smoothed KEV additions end the daily window at 1.78 a day, extrapolated at the edge.

A $\gamma$ read off a trailing year averages over a window in which the rate itself more than tripled, from
161 a day in its first quarter to 524 in its last. That is the shelf life of every absolute figure in the
model.

## Checks against the catalog and the corpus

Four checks compare the model with data. The first two test the exploited stock against the KEV catalog. The
third tests the backlog against the size of the corpus. The fourth asks whether discovery is supply-limited.
The last subsection states how independent the checks are of the calibration.

### 1. Exploited stock, global

KEV holds 1,781 entries. NVD's mirror of it, which the parameters read, holds the same.

The obvious anchor is not one. It says 26% are ever fully patched, so about 1,320 remain unremediated. That
applies the *completed* limit for patching and the *zero* limit for decommissioning at the same instant. KEV
opened 2021-11-03 and was backfilled to 2002. By publication date, **44% of its entries are older than one
residual residence time**, and have already been decommissioned.

The corrected anchor puts both sides on one clock. It runs the catalog's onset history through the exit
kernel the model integrates, for onset ages $a_i$:

$$
\sum_i \left[\, f e^{-(\delta + 1/(\tau+1/\rho)+\lambda) a_i} + (1-f) e^{-\lambda a_i} \,\right]
$$

This gives **645 [616, 787]**. The bracket spans the two defensible onset proxies: NVD publication at the low
end, and CISA's addition date at the high. Today's state is **727**, a ratio of **1.13**, inside the bracket.
The equilibrium target of 1,981 gives 3.07. The transient is the right comparison, since the anchor is itself
an accumulated quantity.

Earlier editions calibrated differently. They set the hazards and $C$ so that an *equilibrium* at the
trailing-year publication rate converted at the KEV rate. But the system the measured history has built is
about a third of that equilibrium. A surge in the trailing rate therefore lowered the conversion assigned to
every past year. Between the 2026-08-14 snapshot and this one, that calibration moved from 1.12 times the
anchor to 0.89, below the bracket. Calibrated along the measured history instead, the model does not drift.
With the earlier ratio and annual drive, it held between 1.15 and 1.19 at all five snapshots from 2026-08-14.

### 2. Exploited stock, SharePoint

SharePoint's 22 KEV entries give a kernel anchor of **9.4 [9.1, 10.9]**, against today's **13.4**: a ratio
of 1.42. One Poisson standard error at $n$ = 22 is 21%, so the ratio lies about two standard errors out. The
target of 20.8 gives 2.21.

This check also fixes a parameter. At SharePoint's 10-year support horizon, the ratios degrade to 1.77 and
3.60. Decommissioning of exploited instances is therefore a roughly 5-year process. Support duration governs
patch availability ($\phi$), not removal from service ($\lambda$).

### 3. Backlog size

A pool fed at $\gamma$ and drained by retirement and exploitation settles at
$\mu N/(\phi + \mathrm{conv}\,\beta_x)$. That gives **540,109** against NVD's 426,069, **+26.8%**, from a
5-year support horizon that was assumed, not fitted. For SharePoint it gives **764** against 747, 2.3% high.

Both now run high. That is the direction a rising $\gamma$ produces: the equilibrium is computed at the
trailing-year rate, while the observed corpus accumulated at lower past rates. The global check ran about 5%
low at the 2026-08-14 snapshot, about 1% high at 2026-08-27, 7% high at 2026-09-20 and 16% high at
2026-10-14. Three months of accelerating publication have moved it thirty-two points, eleven of them in the
last month. It is an order-of-magnitude test, not a calibration, because its equilibrium assumes a stationary
$\gamma$, and $\gamma$ is not stationary.

### 4. Is discovery supply-limited?

Saturating fits to nineteen years of cumulative discovery leave the reservoir unidentified, and annual counts
have risen every year since 2017. **The reservoir is not the binding constraint at either scale.**
Visualization 7 of the model document shows the fits.

### How independent the checks are

Checks 1 and 2 are less independent than they look. Now that the calibration runs along the history, they
are less independent than before. The model is calibrated to KEV additions from 2023. 80% of the corrected
global anchor, 519 of 645, comes from onsets after the catalog opened. The anchor's level therefore largely
shares a window with the calibration. What survives as independent content is the exit kernel and the
*shape* of the onset history.

Observed onsets per day run 0.39, 0.88, 1.19 and 0.81 times the model's realized conversion $I(t)$, over
2008–2015, 2016–2020, 2021–2023 and 2024–2026. The early shortfall is what KEV's documented incompleteness
predicts. The latest window is short because the catalog has not yet listed many recent onsets: the median
lag from publication to listing is 216 days.

The exit kernel is tested only loosely. The ratio of anchor to model is flat, at 0.86 to 0.89, for
$1/\lambda$ anywhere from 3 to 8 years. It falls to 0.81 at 12 years and 0.69 at 20. The anchor excludes a
decade-plus horizon, but it cannot choose a value inside 3–8.
