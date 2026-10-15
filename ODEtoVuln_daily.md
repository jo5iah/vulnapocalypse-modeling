
# Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model

A continuous-time model of how vulnerabilities move from discovery to exploitation to removal, parameterized
from public vulnerability data and evaluated for two populations: the **global software ecosystem** and
**Microsoft SharePoint** as an instance of enterprise server software. Time is in days throughout. Data
acquisition is in `VulnData.ipynb`; the model and every figure are computed in `ODEtoVuln_daily.ipynb`; this
document is the only written account of what they show. Snapshot: **2026-10-14**.

## Executive summary

Security programs are measured on how fast they patch. This model asks what sets the number of
vulnerabilities under active exploitation at any moment, using rates measured in public data (NVD, the CISA
KEV catalog, published incident telemetry) for the whole software ecosystem and for Microsoft SharePoint.
Four findings bear on where a program should spend.

- **Finishing remediation and shrinking reachable surface beat patching faster.** About a quarter of
  exploited vulnerabilities are ever fully patched; the rest stay exploitable until the software leaves
  service. A 30% cut in patch delay changes the standing count by **0.2%**. A 30% cut in reachable surface
  changes it by **12.5%**, 30% more remediations completed by **10.5%**, and a 30% higher rate of
  decommissioning exploited software by **22.9%**.
- **Rising disclosure volume raises exploitation far less than proportionally, but only under an
  assumption.** The model assumes weaponizable supply runs at twice attacker capacity. On that assumption a
  tenfold rise in disclosures raises exploitation **43%**, tripling attacker capacity raises it **80%**, and
  both figures follow directly from the assumed ratio. What is measured is the divergence it is meant to
  explain. From 2025 to 2026 the disclosure rate rose **111%** and cataloged exploitation **33%**, so
  publications per cataloged exploit went from 204 to **322**, and to **439** over the last ninety days.
- **The software with the most CVEs is not the software being exploited.** Over the past year the Linux
  kernel was second in CVE volume with 3,047 and ranks **25th** in the exploitation catalog; Windows Server
  leads exploitation and is **fourth** by volume. Prioritizing by counts points at the wrong software.
- **Nothing a program changes will show in these numbers for years.** The populations that drive
  exploitation turn over on a five-year clock and sit at **50%** of the level today's disclosure rate already
  implies. The standing count is the cataloged exploitation rate times a 1,480-day residence time, so a
  catalog rate rising 33% a year lifts the destination from 1,211 to about **1,620** in one more year. Next
  quarter's exploited count cannot evaluate a control introduced last quarter.

The practical implication is to move effort from response time toward completing remediations, reducing
reachable surface and retiring unsupported software, and to expect none of them to register quickly.

**How far to trust these numbers.** The largest uncertainty cannot be resolved from public data. KEV records
what CISA catalogs, not what attackers do; its annual additions ran 555, 187 and 186 across 2022 to 2024 on
cataloging policy. The widening gap between disclosure and cataloged exploitation therefore has two readings
that point opposite ways. Either attackers are saturating, which is what the model assumes and what makes
rising CVE counts tolerable, or the catalog is falling behind, in which case every exploitation figure here is
low by a growing margin. Until exploitation telemetry separates them (Future work §5), read the exploitation
numbers as a floor.
Beyond that, the absolute counts are orders of magnitude rather than estimates: tested against the catalog on a
consistent footing, the model runs 4% low (§2), and calibrating to 2025's KEV rate alone (0.671/day) rather
than the pooled 2022-onward rate (0.819/day) would lower the level by 18%, since the level scales in proportion
to the calibrated influx. The rankings survive both. Finally, the model counts vulnerabilities rather than
compromised systems, so one flaw exploited on a million hosts counts the same as one exploited once. That
understates the scenario cheaper automated exploitation makes most likely. Stratifying by exposure class and
adding a layer of compromised systems are the extensions most likely to change these conclusions (Future work).

Contents

- [1. The system](#1-the-system)
    - [Discovery, disclosure, and the known backlog](#discovery-disclosure-and-the-known-backlog)
    - [Conversion: from opportunity to exploitation](#conversion-from-opportunity-to-exploitation)
    - [Exploitation, and the two ways out of it](#exploitation-and-the-two-ways-out-of-it)
    - [Finite vulnerability supply, as a forcing layer](#finite-vulnerability-supply-as-a-forcing-layer)
- [2. Data](#2-data)
    - [Sources](#sources)
    - [Measured quantities](#measured-quantities)
    - [Every parameter, and how it is obtained](#every-parameter-and-how-it-is-obtained)
    - [Measurement biases in the source data](#measurement-biases-in-the-source-data)
    - [The shape of the inflow](#the-shape-of-the-inflow)
    - [Checks against the catalog and the corpus, and how independent they are](#checks-against-the-catalog-and-the-corpus-and-how-independent-they-are)
- [3. Results](#3-results)
    - [Visualization 1 — what sets the level, and a test against unused data](#viz-1)
    - [Visualization 2 — discovery volume against attacker throughput](#viz-2)
    - [Visualization 3 — is finite vulnerability supply the binding constraint?](#viz-3)
    - [Visualization 4 — which parameters move the exploited population](#viz-4)
    - [Visualization 5 — defender completeness against attacker shocks](#viz-5)
    - [Visualization 6 — measured stocks and flows](#viz-6)
    - [Visualization 7 — four futures for discovery, one of them mechanistic](#viz-7)
    - [Visualization 8 — where the system is, against where it is heading](#viz-8)
    - [Visualization 9 — five interventions at equal effort](#viz-9)
    - [Visualization 10 — the patch-delay / attack-surface plane](#viz-10)
- [Limitations](#limitations)
- [Future work](#future-work)
- [Appendix: the slow-manifold reduction](#appendix-the-slow-manifold-reduction)
    - [Visualization 11 — phase portrait](#viz-11)
    - [Visualization 12 — the fast manifold in 3-D](#viz-12)
- [References](#references)

## 1. The system

Five stocks hold vulnerabilities. Three describe where a vulnerability sits before it is attacked, and two
describe what happens after it is.

![Five stocks and the flows between them, labeled with the terms used in the equations](figure:structure)

### Discovery, disclosure, and the known backlog

$$
\dot H = \gamma - \delta_d H - \mathrm{conv}\,\beta_h H
$$

$H$ is the **hidden pool**: vulnerabilities someone has found that are not yet public. It fills at the
discovery rate $\gamma$ and empties two ways: by disclosure at rate $\delta_d$, and by exploitation before
disclosure at hazard $\beta_h$. Its mean residence time $1/(\delta_d + \mathrm{conv}\,\beta_h)$ is 45 days,
so $H$ is a fast state.

$$
\dot N = \delta_d H - \mu N - \mathrm{conv}\,\beta_n N
$$

$N$ is the **freshly disclosed pool**. Its only inflow is disclosure from $H$: nothing becomes public without
first being found. It empties by maturing into the standing backlog at rate $\mu$ = 1/30 day⁻¹, one patch
cycle, and by exploitation at hazard $\beta_n$. It is also fast, about 30 days.

$$
\dot X = \mu N - \phi X - \mathrm{conv}\,\beta_x X
$$

$X$ is the **known backlog**: disclosed, aged, mostly patch-available, and by far the largest stock. It empties
by retirement at rate $\phi$, when the affected version leaves support, and by exploitation at hazard
$\beta_x$. Its residence time $1/(\phi + \mathrm{conv}\,\beta_x)$ is 1,821 days, so $X$ is a **slow** state:
five years against 45 days for $H$. That ratio produces most of the model's dynamic behavior.

The per-vulnerability hazards differ by more than an order of magnitude: on a given day a vulnerability in $N$
is 24 times as likely to be attacked as one in $X$, and one in $H$ 9 times. Because $X$ is so much larger, it supplies the most all the same.
At equilibrium $X$ supplies 62% of weaponizable opportunity, $N$ 24% and $H$ 13%. Today, with $X$ at under half
its equilibrium size, $X$ supplies 40%, $N$ 38% and $H$ 21%.

### Conversion: from opportunity to exploitation

$$
P = \beta_h H + \beta_n N + \beta_x X, \qquad
I = \frac{C\,P}{C + P}, \qquad
\mathrm{conv} = \frac{I}{P}
$$

$P$ is the **gross rate at which weaponizable opportunities arise**, the sum of the three hazard flows. It is
not the rate at which exploitation happens, because turning an opportunity into deployed exploitation takes
attacker effort, and that effort is finite. $C$ is the **throughput ceiling**, the maximum conversion rate.
The saturating form gives $I \approx P$ when opportunities are scarce relative to capacity, and $I \to C$ when
they are abundant.

The form has one consequence that the rest of the document depends on. Because $I$ is concave in $P$,
**increases in supply saturate but decreases do not**. With $P = 2C$, the ratio assumed throughout, a tenfold
rise in $P$ raises $I$ by 43%, while cutting $P$ to 5% cuts $I$ by 86%. The elasticity of $I$ with respect to
supply is $C/(C+P) = 1/3$ and with respect to capacity $P/(C+P) = 2/3$; both are the assumed ratio restated.

$\mathrm{conv} = I/P$ is the converted share. It appears in all three pool equations for a conservation
reason: an opportunity attackers do not take is not destroyed, and the vulnerability stays in its pool,
still disclosed, still unpatched, still available later. Only the converted share leaves. With this factor,
discovery equals retirement plus patching plus decommissioning exactly; without it the pools would lose
$P - I$ vulnerabilities a day to nothing. Because $\mathrm{conv}$ depends on the pools and the pools on
$\mathrm{conv}$, the equilibrium is solved self-consistently.

### Exploitation, and the two ways out of it

$$
\dot E_p = f I - \left(\delta + \frac{1}{\tau + 1/\rho} + \lambda\right) E_p, \qquad
\dot E_r = (1-f) I - \lambda E_r, \qquad E = E_p + E_r
$$

Exploited vulnerabilities split into two compartments because remediation is not universal. $E_p$ is the
**remediable** share. It drains through runtime mitigation at rate $\delta$, through patching, and through
decommissioning at rate $\lambda$. Patching waits $\tau$ days before adoption begins and takes $1/\rho$ days
to complete, so its rate is $1/(\tau + 1/\rho)$ and its mean time $\tau + 1/\rho$ = 48 days, consistent with
the measured 43-day median. The residence time of $E_p$ is 41 days.

$E_r$ is the **residual** share. It receives no patching and drains only by decommissioning, at
$1/\lambda \approx 5.5$ years. This asymmetry does more to set the exploited population than any other
feature of the model: the residual compartment holds influx × decommissioning horizon, 135 times what the
remediable compartment holds.

$f$ is the share of realized exploitation routed to $E_p$. Because a small part of $E_p$ still leaves by
decommissioning rather than patching, $f$ = 0.265 is calibrated so the *realized* ever-patched share equals
the measured 26%. The same leak caps the realized share at 98% even when $f$ = 1.

Two structural consequences follow. There is **no ceiling on $E$**: the system is bounded because
$\lambda > 0$, so the brake on exploitation is software leaving service, not attacker saturation. And the
system is **linear except for the conversion term**, which is monotone and saturating, so exactly one
equilibrium exists and it is stable (Appendix).

### Finite vulnerability supply, as a forcing layer

A codebase contains finitely many vulnerabilities, so discovery in principle depletes a reservoir:

$$
\dot U = \sigma S - \psi U, \qquad \gamma = \psi U
$$

$U$ is the latent stock of undiscovered vulnerabilities, depleted by discovery at efficiency $\psi$ and
replenished at $\sigma S$ as new code ships. Section 2 shows that $U$ cannot be estimated from available data
and that discovery is not currently supply-limited, so $\gamma$ is held at its measured value in every figure
except Visualization 7, where $U$ is evolved separately to generate $\gamma(t)$.

## 2. Data

### Sources

| Source | Provides | Used for |
|---|---|---|
| **NVD** [1] | the CVE corpus, publication dates, CVSS attack vectors, CPE applicability, and the KEV flags mirrored into each record | $\gamma$, $\varepsilon$, publication history, backlog check, product ranks |
| **CISA KEV** [2] | which CVEs are known-exploited, and the date CISA added each | the exploitation influx that calibrates $C$; the anchor test |
| **MITRE CVE Services** [3] | CNA publication timestamps | confirming NVD's dates are not materially lagged |
| Verizon 2026 DBIR [4] | 26% of known-exploited flaws ever fully patched; 43-day median time to fix for those that are | $f$, $\tau$ |
| CrowdStrike 2026 [5] | a 42% rise in zero-days exploited before public disclosure | context for the pre-disclosure channel; a growth rate, not a share |
| VulnCheck [20, 21] | 28.3% of newly exploited CVEs evidenced within a day of publication; its lead over KEV | the fast n-day share, hence $\beta_n$; the KEV bias below |
| Mandiant M-Trends 2026 [6] | time-to-exploit estimated at −7 days for 2025 | corroborates the pre-disclosure channel |
| ZDI, July 2026 [7]; Tenable [25]; MSRC [26] | Microsoft shipped 621 CVEs with 3 under active exploit (2 on release day, a third flagged the next); 6.6× its 2025 monthly average of 94 | Visualization 2; Future work §5 |
| Verizon 2025 DBIR [22]; Imperva [23]; EPSS v3 [24] | where exploitation concentrates, and its breadth per vulnerability | Limitations 1 and 2 |
| Synopsys OSSRA 2024 [8] | mean open-source vulnerability age over 2.5 years; nearly a quarter of codebases carry flaws more than 10 years old | $1/\lambda$ |
| Anthropic *n-days* [9]; CVE-Genie [10]; Pesoli, Errico & Cavallaro [11] | machine-generated exploits under an hour after a patch ships; reproduction at a few dollars per CVE and privilege-escalation chains at about $2,000 each; the caveat that these are reproductions rather than production chains | the throughput axis of Visualization 2; Future work §4 |
| FIRST EPSS [14] | exploit-prediction scores | Limitation 1; Future work §1 |

Acquisition is in `VulnData.ipynb`, which writes every model input. Two analyses sit beside the model:
`anchor_gap.py` reproduces the anchor correction below in full, and `product_ranks.py` builds the per-product
rankings quoted in the executive summary, writing `product_ranks_<snapshot>.md` as a standalone report. The
rankings are not model outputs and nothing in the model depends on them.

### Measured quantities

| Quantity | Global | SharePoint |
|---|---|---|
| CVE corpus | 408,059 | 745 (across 8 CPE product names) |
| Publication rate | **259.7/day** trailing year (used); 459.6/day most recent quarter | **0.224/day** 3-year (used); 0.512/day trailing year |
| Publication history | 2008–2026: 5,664 → 105,352/yr (2026 annualized), CAGR **+37%** for 2021–2026 | 2003–2026; 2026 annualizes to 223, the highest on record |
| Known-exploited (KEV) | 1,741 = 0.43% of corpus; influx **0.819/day**, 2022 to the snapshot | 22 = **3.0%**, i.e. **6.9×** the global rate |
| Disclosure → KEV lag | median 245 d (p10 0, p90 2,627) | median 85 d |
| Exploited by publication day | **13.4%** in KEV, a floor | 3 of 22 |
| Network-reachable (CVSS AV:N/A) | 75.5% | 78.5% |
| Ever fully patched | **26%**; median time to fix **43 days** for those that are | same figure applied |

### Every parameter, and how it is obtained

| Symbol | Meaning | Value (global; SharePoint) | Class | Basis | Tested in |
|---|---|---|---|---|---|
| $\gamma$ | publication rate | 259.7/day; 0.224/day | measured | NVD, trailing 364 days; SharePoint over three years (see biases) | Viz 7, 8 |
| $I$ | realized exploitation influx | 0.819/day; 0.0121/day | measured | KEV additions pooled from 2022; SharePoint's 22 entries over five years | anchor check |
| — | pre-disclosure share of exploitation | 13.4%; 14% | measured | KEV entries exploited on or before NVD publication, global and SharePoint; a floor, since CISA dates exploitation by its evidence | — |
| $\varepsilon$ | reachable share of supply | 0.755; 0.785 | measured | CVSS attack vector of KEV entries / SharePoint CVEs | Viz 10 |
| $\tau$ | days before patch adoption begins | 43 d | measured | DBIR median time to fix [4] | Viz 4, 9, 10 |
| — | ever-fully-patched share | 26% | measured | DBIR [4] | Viz 5 |
| $f$ | share routed to the remediable compartment | 0.265; 0.266 | calibrated | set so the realized ever-patched share is 26% | Viz 4, 5 |
| — | share of post-disclosure exploitation within one day of disclosure | 28% | measured | VulnCheck 2025 Q1 [20]: 28.3% of 159 newly exploited CVEs; the source counts all exploitation, not only post-disclosure, so the split is approximate | — |
| $\beta_h, \beta_n, \beta_x$ | exploitation hazards | — | calibrated | set so supply splits into the measured pre-disclosure, fast n-day and aged shares | — |
| $C$ | attacker throughput ceiling | 1.228/day; 0.018/day | calibrated | set so $I$ equals the KEV rate at today's supply, given $P/C$ | Viz 2 |
| $P/C$ | supply relative to throughput | 2 | **assumed** | the one free structural ratio; it fixes the elasticities to capacity (2/3) and to supply (1/3), and makes $C$ a floor rather than an estimate | — |
| $\rho$ | patch adoption rate once begun | 0.2/day (5 days to complete) | **assumed** | chosen so $\tau + 1/\rho$ = 48 d sits near the 43-day median | Viz 4 |
| $\delta$ | runtime mitigation of exploited flaws | 0.003/day | **assumed** | no public measurement | Viz 4 |
| $\delta_d$ | disclosure rate | 1/45 day⁻¹ | **assumed** | the 90-day coordinated-disclosure norm, with many vendor-found bugs faster | — |
| $\mu$ | maturation into the backlog | 1/30 day⁻¹ | **assumed** | one patch cycle | Viz 4 |
| $\phi$ | retirement from support | 1/1825; 1/3650 day⁻¹ | **assumed** | 5- and 10-year support horizons | backlog check |
| $\lambda$ | decommissioning of exploited software | 1/2000; 1/1825 day⁻¹ | **assumed** | OSSRA vulnerability ages [8]; SharePoint's shorter horizon is required by its anchor (below) | anchor check; Viz 5 |

The weakest links are the two assumed quantities the results depend on most: $P/C$, which sets every
attacker-side sensitivity, and $\lambda$, which sets the level.

### Measurement biases in the source data

Three act in a known direction and are not corrected for.

**Publication-date rates are undercounts.** A window's count is not fixed when the window closes: NVD keeps
ingesting records whose publication date falls inside it. The window 2026-05-07 → 2026-08-06 returned 25,148
when first counted on 2026-08-06 and **25,361 eight days later, +0.85%**. Re-queried on 2026-08-27, thirteen
days after that, it returned 25,361 unchanged, and again on 2026-10-14: the late-arrival tail is essentially
complete within a fortnight. Daily counts agree: of the fourteen days to 2026-09-20 that were first counted on
that date, only the last changed when re-queried at this snapshot. From 2026-09-20 to the snapshot the corpus
grew by 518 a day against a windowed publication rate of 460 a day. Every $\gamma$ here is therefore low, by more for the most recent weeks, and the acceleration is
understated rather than overstated. The 2008–2026 history used for the transient runs is as measured.

**Single-product rates are quantized by release cadence.** SharePoint gained 29 CVEs in the eight days to
2026-08-14, all published on 2026-08-11, one Patch Tuesday, which moved its trailing-year rate by 22%. The
3-year rate is used for that reason.

**KEV is a lower bound on exploitation, and its additions reflect cataloging policy.** Annual additions run
311, 555, 187, 186, 245 for 2021–2025 and 257 so far in 2026. The influx is therefore pooled rather than
averaged year by year: 1,430 additions from 2022-01-01 to the snapshot over 1,747 days, **0.819/day**. Pooling
damps the year-to-year swing and gives the partial current year its true weight. 2021 is excluded because KEV
opened that November and its 311 additions are a backfill of earlier exploitation, not a rate. Exploitation is
listed earlier by VulnCheck's catalog in two-thirds (67.6%) of the 376 CVEs the two shared in 2024–2025, by a
mean of 28 days and a median of 3 [21]. The influx, and the throughput $C$ calibrated from it, are floors.
Future work §5 measures exploitation from vendor announcements, ahead of the catalog.

### The shape of the inflow

![Velocity, acceleration and jerk of CVE publication and of KEV additions, on a monthly grid
over 2008-2026 and a daily grid over the recent window](figure:inflow_derivatives)

Both inflows are differentiated as cumulative counts, so the rows are the rate itself, its rate of change, and
whether *that* is turning. The monthly columns use a filter wide enough to find a turning point in nineteen
years, which extrapolates across its own two-year half-window at each end; they describe history, not the
present. The daily columns describe the present and nothing earlier.

On the monthly grid the publication series has no turning point. Acceleration has been positive continuously
since **2018-12** and jerk since **2019-09**, each far longer than the 24-month dwell a sign change must clear:
the inflow is growing by a growing amount, and has been for most of a decade. KEV resolves no turning point
either, which at 0.8 additions a day against a 25-month window is expected. Its level is not flat: the smoothed
rate runs from 0.15/day in early 2023 to 0.69/day by mid-2025, and annual rates are 0.51, 0.51, 0.67 and 0.90
per day for 2023 to 2026.

What the two series show is a divergence in pace. From 2025 to 2026 disclosure rose **111%** (136.9 to 288.4 a
day) and cataloged exploitation **33%**, so publications per cataloged exploit went **204 → 322**, and **439**
across the last ninety days. September 2026 published 503 CVEs a day, the highest complete month on record, and
drew 43 KEV additions, the most in any month since June 2022; the ratio widened anyway. That widening ratio is what the throughput ceiling $C$ describes, and it is the
only place in this document where the saturation the model assumes is visible directly in the data, subject to
the catalog caveat in the summary.

The daily columns oscillate on a monthly beat: smoothed publication moves between about 245 and 590 a day
inside the measured interior as vendor releases arrive. A centered 7-day mean removes the weekly cycle but
nothing removes the monthly one, so no daily sign change is counted unless it outlasts a full cadence, and none
does. A $\gamma$ read off a trailing year averages over a window in which the rate itself more than tripled,
from 149 a day in its first quarter to 460 in its last, which is the shelf life of every absolute figure here.

### Checks against the catalog and the corpus, and how independent they are

1. **Exploited stock, global.** KEV holds 1,745 entries (NVD's mirror of it, which the parameters read, held
   1,741 on the same day). The obvious anchor, that 26% are ever fully patched so about 1,290 remain
   unremediated, is not one: it applies the *completed* limit for patching and the *zero*
   limit for decommissioning at the same instant. KEV opened 2021-11-03 and was backfilled to 2002, so by
   publication date **43% of its entries are older than one residual residence time** and have already been
   decommissioned. Running the catalog's onset history through the exit kernel the model integrates,
   $\sum_i [\,f e^{-(\delta + 1/(\tau+1/\rho)+\lambda) a_i} + (1-f) e^{-\lambda a_i}\,]$ for onset ages $a_i$,
   puts both sides on one clock and gives **627 [596, 770]**. The bracket spans the two defensible onset
   proxies, NVD publication at the low end and CISA's addition date at the high. Today's state is **604**, a
   ratio of **0.96**, inside the bracket; the equilibrium target of 1,211 gives 1.93. The transient is the
   right comparison, since the anchor is itself an accumulated quantity. That the target lands near the naive
   1,288 is two errors cancelling, not a second agreement.
2. **Exploited stock, SharePoint.** Its 22 KEV entries give a kernel anchor of **9.8 [9.3, 11.3]** against
   today's **11.5**, a ratio of 1.18. One Poisson standard error at $n$ = 22 is 21%, so the ratio lies inside
   one standard error. The target of 16.1 gives 1.64. This check also fixes a parameter:
   at SharePoint's 10-year support horizon the ratios degrade to 1.55 and 2.71, so decommissioning of exploited
   instances is a roughly 5-year process. Support duration governs patch availability ($\phi$), not removal
   from service ($\lambda$).
3. **Backlog size.** A pool fed at $\gamma$ and drained by retirement and exploitation settles at
   $\mu N/(\phi + \mathrm{conv}\,\beta_x)$: **472,411** against NVD's 408,059, **+15.8%**, from a 5-year
   support horizon that was assumed rather than fitted; and **773** against SharePoint's 745, 3.8% high.
   Both now run high, the direction a rising $\gamma$ produces: the equilibrium is computed at the trailing-year
   rate, while the observed corpus accumulated at lower past rates. The global check ran about 5% low at the
   2026-08-14 snapshot, about 1% high at 2026-08-27 and 7% high at 2026-09-20; two months of accelerating
   publication moved it twenty-one points, and SharePoint's moved eleven in the last 24 days. It is an
   order-of-magnitude test, not a calibration, because the equilibrium it computes assumes a $\gamma$ that is
   not stationary.
4. **Is discovery supply-limited?** Visualization 3. Saturating fits to nineteen years of cumulative discovery
   leave the reservoir unidentified, and annual counts have risen every year since 2017. **The reservoir is
   not the binding constraint at either scale.**

Checks 1 and 2 are less independent than they look. $C$ is calibrated from the KEV rate, and 80% of the
corrected global anchor, 503 of 627, comes from onsets after the catalog opened, inside the window calibration
used. What survives as independent content is the *shape* of the onset history rather than its level. Observed
onsets per day run 0.42, 0.95, 1.40 and 0.96 times the model's realized conversion $I(t)$ over 2008–2015,
2016–2020, 2021–2023 and 2024–2026. The early shortfall is what KEV's documented incompleteness predicts. In the
current window the model converts 4% less per day than the catalog records, which accumulates into the 4%
shortfall of the stock in check 1. The exit kernel is tested only loosely: the ratio of anchor to model is flat
at 1.00 to 1.04 for $1/\lambda$ anywhere from 3 to 8 years, falling to 0.93 at 12 and 0.79 at 20, so the anchor
excludes a decade-plus horizon but cannot choose a value inside 3–8.

## 3. Results

### Visualization 1 — what sets the level, and a test against unused data

**Two measured facts set the level.** The model states the level as $E = I \times T$, realized influx times
influx-weighted mean residence time:

$$
T = \frac{f}{\delta + 1/(\tau + 1/\rho) + \lambda} + \frac{1-f}{\lambda}, \qquad
E^* = 0.818/\text{day} \times 1{,}480\ \text{days} = 1{,}211
$$

Neither term is fitted to $E$. Factored one mechanism at a time from **101**, the level at full conversion
and full remediation, the throughput ceiling divides by **3.0** to **34**, the level if every exploited
vulnerability entered the remediable compartment. Incomplete remediation then multiplies by **36**: routing
73% of the influx to a compartment that drains only by decommissioning stretches $T$ from the 41-day
remediable residence to 1,480 days. Lifting the ceiling instead of applying it would give 3,626, which is why
the two steps are shown separately. The equilibrium is a target. Driven by the measured 2008–2026 publication
history, today's global exploited population is **604**, 50% of the way there. The lower panel places today's
state against the KEV anchors from §2: 0.96× the global anchor and 1.18× SharePoint's, with the naive anchor
marked for comparison.

![Visualization 1 — the level as influx times residence time, factored one mechanism at a time, and tested against the KEV catalog](figure:viz-1)

### Visualization 2 — discovery volume against attacker throughput

**Discovery volume saturates; throughput does not.** $E^*$ contoured over a discovery multiplier and a
throughput multiplier. The contours flatten toward horizontal: a 10× increase in discovery moves $E^*$
**+43%**, while tripling throughput moves it **+80%**, and both together **3.9×**. These are the assumed
$P/C$ = 2 at work (§1), not independent findings. The observation consistent with them is vendor-level:
Microsoft's July 2026 release shipped 621 CVEs with 3 under active exploit (ZDI [7] counted 2 on release day;
Microsoft flagged a third the next [26]), 6.6× its 2025 monthly
average [25]. The right panel pairs each scenario's eventual target with the value five years from today: 912 with
no change, 1,247 under 10× discovery, 1,380 under 3× throughput. No scenario delivers more than 60% of its
eventual movement within a planning horizon. CVE counts measure the saturating axis. Throughput, the one that
does not saturate, has no published index, though machine-generated exploits landing within an hour of a patch [9, 12, 13]
and exploit reproduction at a few dollars per CVE [10] show it moving, with the caveat that these are
reproductions rather than production chains [11].

![Visualization 2 — equilibrium exploited count over discovery and throughput multipliers, and the five-year value of each scenario](figure:viz-2)

### Visualization 3 — is finite vulnerability supply the binding constraint?

**Finite vulnerability supply does not bind.** Depletion requires the cumulative discovery curve to
decelerate; annual counts have instead risen in every year from 2017 to 2026. Saturating fits cannot recover
the reservoir. Both forms now run $U$ to the fit's 10-billion upper bound (the logistic to 9.8 billion), where
the reported uncertainty collapses to zero, the signature of a parameter the data do not constrain. Until the
2026-09-20 snapshot the logistic form still returned an interior value, 5.5 million ± 128%, and that value was
dominated by the 2017 CNA-expansion step, a bookkeeping change rather than a property of code; 2026's
acceleration has removed even that. SharePoint shows the failure directly: fits through 2022,
2023 and 2024 give asymptotes of **13,720 / 1,828 / 958**, tracking the recent slope rather than a stock. Those
fits read the 2022–24 trough as exhaustion; 2026 then annualizes to **223**, the product's highest year. The
conclusion is falsifiable: **per-product discovery must bend where code is not churning**, and mature
enterprise products are where that would appear first. It has not appeared. Fits are unweighted least squares
with $U$ bounded below by the observed count; the covariance understates uncertainty because the residuals are
strongly autocorrelated.

![Visualization 3 — annual and cumulative discovery with two saturating fits, and SharePoint's fitted asymptote at three cutoff years](figure:viz-3)

### Visualization 4 — which parameters move the exploited population

**Which lever dominates depends on remediation completeness.** Elasticities of $E^*$ (±1% central
differences) for both ecosystems, beside a counterfactual with $f$ = 1, in which all exploitation enters the
remediable compartment and 98% is eventually patched. At the measured 26%, decommissioning dominates at
**−0.99**, throughput follows at +0.67, completeness is −0.35, and patch delay, adoption and mitigation are all
at or below ±0.01. In the counterfactual, patch delay rises to **+0.77**, mitigation to −0.12 and adoption to
−0.09, while decommissioning falls to −0.02 and $E^*$ falls from 1,211 to 34. The patch-delay elasticity rises
monotonically with completeness: +0.016 at a 50% ever-patched share, +0.048 at 75%, +0.306 at 95%. Both
columns are the same model at different completeness, so a disagreement about whether patch timing or software
retirement matters more is, in this model, a disagreement about what fraction of exploited vulnerabilities an
organization finishes remediating. Throughput, discovery, surface and weaponization are unaffected by
completeness because they act on the influx rather than on either drain; the last three share one elasticity,
+0.33, because each enters only through $P$. The pale bars, for the count five years out, keep decommissioning
(−0.52) and throughput (+0.45) on top but reorder below them: surface and weaponization (+0.28) pass
completeness (−0.25), and maturation (−0.08) passes retirement, which falls from −0.21 to −0.06. Maturation and
patch delay are the only levers not smaller at five years than at equilibrium.

![Visualization 4 — elasticities of the equilibrium exploited count, measured and at full remediation](figure:viz-4)

### Visualization 5 — defender completeness against attacker shocks

**Completeness and decommissioning outweigh the attacker-side shocks.** $E^*$ against the realized
ever-patched share at three decommissioning horizons, with attacker scenarios as reference levels. Raising the
ever-patched share from 26% to 75% cuts $E^*$ **66%**, to 409. Shortening the decommissioning horizon from 5.5
to 3 years cuts it **45%**, and a 30% cut in reachable surface **13%**. Halving patch delay from 43 to 21 days
cuts it 0.3%. Against these, 10× discovery adds 43%, 3× throughput 80%, and all three attacker shocks together
(10× discovery, 3× weaponization, 3× throughput) 329%. This figure also shows the model's largest sensitivity.
At the measured 26%, moving the decommissioning horizon across 3–10 years spans 667 to about 2,200, a factor of
about three. At 50% ever patched the target is 818 rather than 1,211. The dashed curves, five years out, sit
above the equilibrium at high completeness: improving completeness cannot retire a backlog already present. The
horizontal axis ends at 98%, the most the model can realize.

![Visualization 5 — equilibrium exploited count against the ever-patched share at three decommissioning horizons, and a ranked comparison of levers and shocks](figure:viz-5)

### Visualization 6 — measured stocks and flows

**The flow structure is thin at the point that matters.** The stock-and-flow diagram with measured rates,
arrow widths scaled to flow, each box carrying its target and today's value. Globally 259.7 CVEs a day enter
and 0.818 a day are converted, **1 in 317**; for SharePoint the ratio is 1 in 19, consistent with its 6.9×
higher KEV rate. Weaponizable supply reaches 2.45 a day against a throughput of 1.23, so 33% is converted and
the rest stays in the pools. The residual compartment holds 1,202 of the global 1,211 (99%), because it drains
only through decommissioning. The pre-disclosure channel carries 13% of supply at equilibrium and 21% today,
while the backlog is still filling; a structure in which exploitation only follows disclosure would omit it,
and since KEV dates exploitation by its evidence, 13% is a floor. Every box balances.

![Visualization 6 — five stocks with measured flows for both ecosystems](figure:viz-6)

### Visualization 7 — four futures for discovery, one of them mechanistic

**The choice of discovery future barely propagates.** Four trajectories for $\gamma$: an exogenous fade, a
permanent step to the measured 1.77× (most recent quarter against trailing year), compounding at that same
figure read as +77% a year and capped at 10×, and a 10× efficiency jump against a finite reservoir. The cap and
the compounding rate are arbitrary. The measured 2021–2026 growth rate is 37% a year, so the compounding case
is an upper bound. The reservoir case uses $U_0$ = 1.0 million remaining, a lower bound since the reservoir is
unidentified (Visualization 3), with $\psi$ pinned so $\psi U_0$ equals today's discovery rate and
replenishment set equal to it. Its surge decays on a timescale of $U_0/(10\gamma)$, about thirteen months,
without any assumption about behavior. Starting from today's 604, every path rises over 25 years, to between
1,203 and 1,712, because the slow compartments are still filling whatever discovery does. Three of the four end
within **17%** of one another; only sustained compounding separates.

![Visualization 7 — four discovery trajectories and the exploited count each produces](figure:viz-7)

### Visualization 8 — where the system is, against where it is heading

**The system has two clocks.** Each stock along the measured 2008–2026 publication history, continued at
today's rate, against its equilibrium target. The fast pools have overshot theirs, at **111%** globally and
**273–274%** for SharePoint: a stock whose residence time is weeks tracks a rising inflow, and the target is
computed at a trailing-year rate the current quarter exceeds. The slow ones are far short. The known backlog is
at **45%** of target and needs **8 more years** to reach 90% of it. The residual exploited compartment is at
**50%** and needs **11**. SharePoint's backlog is at 64% and its residual at 71%. Most of the movement still to
come was committed by publications that happened years ago, which is why exploitation counts cannot evaluate a
recent control. Publication history is interpolated linearly between annual rates and seeded in 2008 from the
equilibrium that year's rate implies.

![Visualization 8 — each stock driven by measured history and continued at today's rate, against its target](figure:viz-8)

### Visualization 9 — five interventions at equal effort

**Effect and speed rank in nearly opposite orders.** Five controls, each given the same 30% relative
improvement in one parameter from today's history-driven state, plotted as eventual effect against the time
to reach 90% of it. "Equal effort" is a normalization, not a cost model.

| Control (30% improvement) | Eventual change in $E^*$ | After 5 years | Time to 90% |
|---|---|---|---|
| decommissioning rate $\lambda$ | −22.9% | −14.0% | 17.0 yr |
| reachable surface $\varepsilon$ | −12.5% | −10.4% | 11.7 yr |
| ever-patched share | −10.5% | −7.6% | 14.1 yr |
| retirement rate $\phi$ | −5.3% | −1.6% | 21.9 yr |
| patch delay $\tau$ | −0.2% | −0.2% | 1.7 yr |

Patch delay acts on the remediable compartment directly and is fast and weak. The other four act through
multi-year stocks and are slow and, retirement excepted, strong. For SharePoint, retirement does not reach 90%
of its effect within the 30 years integrated, and the figure places it at that edge.

![Visualization 9 — five controls at equal relative effort, effect against time to take effect](figure:viz-9)

### Visualization 10 — the patch-delay / attack-surface plane

**Of the two levers a program controls most directly, patch delay barely moves the outcome and reachable
surface moves it substantially.** $E^*$ over patch delay (0–180 days) and a multiplier on the measured
reachable share (0.05–1.0). The contours are nearly horizontal: across the full range of $\tau$ the outcome
changes by about 2%, because $\tau$ acts only on the remediable compartment. Reachable surface spans
**0.14× to 1.01×** of the target. That is a larger movement than tripling throughput produces (1.80×), because
cutting supply is not damped by saturation the way raising it is (§1). With no change, the count five years
from today is 0.75× the target (0.86× for SharePoint).

![Visualization 10 — equilibrium exploited count over patch delay and reachable surface](figure:viz-10)

## Limitations

1. **Mean-field.** One hazard per pool, where the 3.5% of vulnerabilities scoring 0.36 or more on the
   exploit-prediction score [14] hold 68% of observed exploitation [24], and edge devices and VPNs were the
   target in 22% of breaches involving vulnerability exploitation, up from 3% the year before [22]. Stratifying is the extension most likely to change the results (Future work §1).
2. **$E$ counts vulnerabilities, not compromised systems.** CitrixBleed 2 (CVE-2025-5777) drew more than 11.5
   million attack attempts against thousands of sites within weeks of disclosure [23] and scores as 1, so a rise in breadth per vulnerability is invisible (Future work §3).
3. **$C$ is calibrated, not measured, and $P/C$ is assumed.** $C$ absorbs every unmodeled mechanism,
   including defender interdiction, and $P/C$ fixes every attacker-side sensitivity (Future work §4).
4. **The 26% ever-patched figure is one survey median** and carries more of the result than any other
   measured value. At 50%, $E^*$ is 818 rather than 1,211; at 75%, 409.
5. **$\rho$ and $\delta$ are assumed without measurement.** They matter little at 26% completeness and a
   great deal at high completeness (Visualization 4).
6. **No defender adaptation.** $f$, $\tau$ and $C$ are constants; coordinated disclosure programs, such as the
   Akrites letter [15], are attempts to move $f$ and $\delta_d$, and the model cannot represent their effect (Future work §4).
7. **Non-stationarity.** 2026 is running at 288.4 CVEs a day against 2025's 136.9, so equilibrium statements
   describe a moving target, and the absolute figures here have a shelf life of months (see the backlog check
   in §2).

## Future work

The first four items are ordered by dependency: the first two complete the present layer, the third builds a
layer above it, and the fourth a layer above that. Each later layer consumes the one beneath it. The fifth depends
on none of them and can be done before any of them: it replaces the lagging catalog measurements every layer
reads, so doing it first improves the inputs the other four consume.
The same structure is kept in `plan.md`.

### 1. Stratify by type, severity, product and exposure

Every hazard in the model is a single population average. Exploitation is not distributed that way, and
`product_ranks.py` already measures a composition the present model cannot represent: the Linux kernel is
second in CVE volume and sits 25th in the exploitation catalog, while Windows Server leads exploitation and is
fourth by volume. The change is to split each pool into classes with class-specific $\beta$ and $\varepsilon$, and,
where the data support it, class-specific $f$ and $\lambda$. Four axes are available in records the
acquisition notebook already pulls: **type** (CWE), **severity** (CVSS base score, and EPSS [14] where available),
**product** (CPE `vendor:product`, rolled up to families), and **exposure** (CVSS attack vector and privileges
required: internet-facing and pre-authentication; network-reachable but authenticated; local or adjacent).
Severity and exposure are correlated through the CVSS vector, so they are not independent dimensions. Start
with exposure, add type, and treat severity as a check until the correlation is measured. CPE applicability is
missing from about half of recent records, censoring the latest months hardest. The test this admits is one the
present model cannot attempt: a class-stratified calibration should reproduce the *composition* of the KEV
catalog, which classes and vendors dominate it, without being fitted to that composition.

### 2. Tighten the decommissioning rate

$1/\lambda$ = 5.5 years rests on open-source vulnerability age, and the corrected anchor (§2) excludes
horizons of a decade or more but is consistent with anything from 3 to 8 years. Since $\lambda$ sets the
residence time of the compartment that holds 99% of the exploited population, it remains the most load-bearing
number in the model, which is why Visualization 5 sweeps it. **Fit it to how long KEV-listed vulnerabilities
remain observable in internet-exposure scans**, which measures removal from service directly rather than
inferring it from the age of flaws still present. The input is per-CVE scan telemetry tracked over years. The
test is whether the fitted horizon lands inside the 3-to-8-year window and whether SharePoint's shorter horizon
survives against its own scan history. The same work bears on the one discrepancy the anchor leaves: the model
converts 4% less per day than the catalog records in the current window, which recalibrating $C$ against a
better $\lambda$ would either remove or confirm.

### 3. A layer above: exploited systems

The present layer counts vulnerabilities. Harm accrues to systems, and the two are not proportional: one
vulnerability drew more than 11.5 million attack attempts [23], and this model scores it as 1. The remedy is a second
layer that consumes this one's output rather than modifying it. For each vulnerability in the exploited
compartments it would carry a susceptible installed base $S_i$ and a compromised count $Q_i$, with $\dot Q_i$
driven by scan-and-exploit contact against $S_i$ and drained by instance-level remediation: an epidemic layer
whose *number of simultaneous epidemics* is supplied by the layer below. Aggregate harm becomes a weighted sum
over $Q_i$ rather than a count of vulnerabilities, parameterized by exposure counts per product, scanning
telemetry and incident counts. Two SharePoint cases, an authentication bypass [18] and a flaw exploited shortly
after its proof of concept was published [19], are the worked examples to read before specifying it. It matters for the conclusions already drawn because automation plausibly
increases the breadth of exploitation per vulnerability without changing the number exploited, a large
movement in harm that the present layer registers as none.

### 4. A layer above that: the economics of attack and defense

Both layers above take effort as given. $C$, the parameter that dominates the response to automation, is
calibrated rather than explained, and the defender-side parameters $f$, $\tau$, $\rho$ and $\lambda$ are
constants, so neither side can adapt. A third layer would make them decisions. On the attack side, throughput
becomes a choice: spend on exploit production against expected return per compromised system. Both terms are
now roughly measurable. Per-exploit production costs have been reported from a few dollars for reproducing a
known vulnerability [10] to about $2,000 for a chained privilege escalation [9], and expected return follows from the
second layer's compromise counts. On the defense side, completeness, patch speed, surface and retirement each
carry a cost curve, and the equilibrium sits where marginal cost equals marginal harm avoided, the framing of the security
economics literature [16, 17]. The questions
only this layer can answer are whether rising throughput reflects falling production cost or rising expected
return, whether optimal attacker throughput scales with a hundredfold fall in exploit cost or saturates against
target selection and monetization, and whether a defender's best response shifts from speed toward
completeness as attacker costs fall. It would also settle one the current model cannot pose: whether the
historical stability of exploitation rates is coincidence or an equilibrium between two adapting parties.

### 5. Independent of all four: an exploitation signal ahead of the catalog

Every exploitation quantity in this document is a catalog entry, and catalogs lag events. The median
disclosure → KEV lag is 245 days (p90 2,627); VulnCheck lists exploitation before KEV in 67.6% of the CVEs the
two share, by a median of 3 days and a mean of 28 [21]; and NVD keeps adding records to publication windows that
have already closed (§2). Zero-days are announced first by vendors, responders and the press, often before a CVE
is published. Vendor records move too. Microsoft published the SharePoint flaw CVE-2026-58644 on 2026-07-14
without its exploited flag, corrected the flag the next day, and CISA listed it on 2026-07-16, so July's
exploited count was 2 on release day and 3 a day later. Its fix had shipped in June with the CVE left out of
that release [26]: for a month the fix existed with no public record of the flaw it fixed.
The remedy is to read that earlier record directly: structured vendor exploitation flags, such as
the `Exploited` field of the Microsoft Security Update Guide [26] and the `exploit_status` threat category of
CSAF 2.0 advisories [27]; the fixed phrasings of browser, mobile and edge-device advisories ("may have been
exploited", "aware that an exploit … exists in the wild"); curated trackers such as Project Zero's list of
zero-days exploited in the wild [28]; and the trade press, which supplies first timestamps but not counts, since
it over-samples prominent vendors. Each claim reduces to a first public timestamp per vulnerability and a coded
strength of claim, alongside the vendor's own patch statement: fix available, workaround only, no fix planned, or
end of life.

Four measurements follow, each replacing something the present layer assumes or brackets. The lag from first
claim to CVE publication to KEV addition replaces the onset bracket in the anchor test (§2). Publications per
exploitation claim, set beside publications per KEV addition, separates the two readings of the widening gap in
the executive summary: if the advisory ratio widens as KEV's does, attackers are saturating; if claims rise with
disclosure while catalog additions do not, the catalog is falling behind and every exploitation figure here is
low by a growing margin. Claims for the current month, scaled by the measured claim-to-catalog ratio, estimate
the influx $I$ before the catalog catches up. And the share of exploited vulnerabilities whose vendor states no
fix or end of life is a direct lower bound on $1 - f$, which today rests on one survey median. A fifth
measurement extends the population rather than the timing: vendors also fix security flaws without issuing a
CVE, and matching shipped fixes (release notes, changelogs, upstream commits) against the CVEs that cite them
measures attack surface absent from every rate here, $\gamma$ included. The test is that advisory-derived onsets
reproduce KEV's addition dates shifted by a lag consistent with VulnCheck's published median and mean, without
being fitted to them. Vendor exploitation language is itself policy, as KEV additions are, so each vendor's flag
rate is tracked over time and a change of phrasing is treated as a change of instrument.

## Appendix: the slow-manifold reduction

The uniqueness and stability of the equilibrium follow from the structure (§1). These two figures show the
geometry behind it and check the timescale separation numerically; no result above depends on them.

### Visualization 11 — phase portrait

$H$, $N$ and $E_p$ relax in 45, 30 and 41 days against 1,821 days for $X$ and 2,000 for $E_r$, so the slow
dynamics reduce to the $(X, E_r)$ plane with the fast states held at their equilibrium values. The
$\dot X = 0$ nullcline is **vertical** because nothing in $\dot X$ depends on $E_r$: the backlog's balance
involves only $N$, $X$ and the conversion share, and conversion depends on the pools, not on the exploited
stock. The $\dot E_r = 0$ nullcline rises with $X$ and **flattens** as realized exploitation saturates at $C$.
They cross once, and the crossing is stable. The measured history, drawn from 2008, is still travelling toward
it: today the backlog is at 45% of target and the residual at 50%. The reduction's error is bounded by the
timescale ratio, at least 45:1 between $E_p$ and $E_r$ and wider for $H$ and $N$.

![Visualization 11 — the slow plane with nullclines, flow field and the measured path from 2008](figure:viz-11)

### Visualization 12 — the fast manifold in 3-D

Trajectories of the full global system in $(N, X, E_r)$, with $H$ and $E_p$ started at their equilibrium
values so the collapse of $N$ is isolated. Every orbit reaches the $\dot N = 0$ surface,
$N = \delta_d H^* / (\mu + \mathrm{conv}\,\beta_n)$, within weeks and then travels along it for decades. The
surface depends on $X$ only through $\mathrm{conv}$, and $\mathrm{conv}\,\beta_n$ is under a thousandth of
$\mu$, so it is flat to within that margin and drawn as a plane. Along the measured history $N$ stays within
−8.8% to +1.9% of this relation while $X$ and $E_r$ remain at 45% and 50% of target: being on the nullcline
means $N$ tracks $H$ with a 30-day lag, not that the system has arrived anywhere. The notebook also writes the
rotating view to `ODEtoVuln_daily_phase3d.mp4`; the still below is one viewpoint.

![Visualization 12 — full-system trajectories collapsing onto the N-nullcline, one viewpoint of the rotating view](figure:viz-12)

## References

Numbers in brackets in the text refer to this list. Links were last checked on 2026-10-14.

**Data sources**

1. National Institute of Standards and Technology. *National Vulnerability Database.*
   [nvd.nist.gov](https://nvd.nist.gov/). Queried through the CVE API 2.0,
   `https://services.nvd.nist.gov/rest/json/cves/2.0`, and the CPE API 2.0,
   `https://services.nvd.nist.gov/rest/json/cpes/2.0`.
2. Cybersecurity and Infrastructure Security Agency. *Known Exploited Vulnerabilities Catalog.*
   [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
   Read from the JSON feed, `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
3. The MITRE Corporation, CVE Program. *CVE Services API.* `https://cveawg.mitre.org/api/cve/`;
   [cve.org](https://www.cve.org/).

**Published telemetry**

4. Verizon. *2026 Data Breach Investigations Report.*
   [verizon.com/business/resources/reports/dbir](https://www.verizon.com/business/resources/reports/dbir/).
   Source of the 26% ever-fully-patched share and the 43-day median time to fix.
5. CrowdStrike. *2026 Global Threat Report*, executive summary.
   [crowdstrike.com](https://www.crowdstrike.com/en-us/resources/reports/global-threat-report-executive-summary-2026/).
   Source of the 42% *increase* in zero-day vulnerabilities exploited prior to public disclosure, a growth rate.
   Earlier editions of this document read it as a 42% share and calibrated $\beta_h$ to it; the share is now
   measured from KEV.
6. Mandiant. *M-Trends 2026*, as reported by Help Net Security, "Attackers are handing off access in 22
   seconds, Mandiant finds," 2026-03-24.
   [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/03/24/mandiant-m-trends-2026-report/). Source of
   the time-to-exploit estimated at −7 days for 2025.
7. D. Childs, Trend Micro Zero Day Initiative. "The July 2026 Security Update Review." 2026-07-14.
   [zerodayinitiative.com](https://www.zerodayinitiative.com/blog/2026/7/14/the-july-2026-security-update-review).
   Source of the 621 CVEs, and of the 2 under active exploit on release day; Microsoft flagged a third on
   2026-07-15 (Future work §5).
8. Synopsys. *2024 Open Source Security and Risk Analysis Report* (ninth edition), as summarized in "New Synopsys
   Report Finds 74% of Codebases Contained High-Risk Open Source Vulnerabilities, Surging 54% Since Last Year,"
   2024-02-27. [news.synopsys.com](https://news.synopsys.com/2024-02-27-New-Synopsys-Report-Finds-74-of-Codebases-Contained-High-Risk-Open-Source-Vulnerabilities,-Surging-54-Since-Last-Year).
   Source of the mean open-source vulnerability age of over 2.5 years and of nearly a quarter of codebases
   containing vulnerabilities more than 10 years old. The report series is now published by Black Duck
   ([blackduck.com/ossra](https://www.blackduck.com/ossra)); its 2026 edition does not report vulnerability age.

**Automated exploit generation**

9. Anthropic. "Measuring LLMs' impact on N-day exploits." 2026-06-08.
   [red.anthropic.com/2026/n-days](https://red.anthropic.com/2026/n-days/).
10. S. Ullah, P. Balasubramanian, W. Guo, A. Burnett, H. Pearce, C. Kruegel, G. Vigna, G. Stringhini. "From
    CVE Entries to Verifiable Exploits: An Automated Multi-Agent Framework for Reproducing CVEs" (CVE-Genie).
    2025. [arXiv:2509.01835](https://arxiv.org/abs/2509.01835).
11. A. Pesoli, H. Errico, L. Cavallaro. "Demystifying the Mythos or Disrupting Bugonomics? From Zero-Day
    Asymmetry to Defender Remediation Throughput." 2026. [arXiv:2605.24632](https://arxiv.org/abs/2605.24632).
12. Help Net Security. "Mythos Preview can weaponize N-day vulnerabilities in hours." 2026-06-09.
    [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/06/09/anthropic-mythos-preview-n-day-exploits-firefox-windows/).
13. SecurityWeek. "Claude Mythos Turns N-Days Into N-Hours With Rapid Exploit Creation." 2026.
    [securityweek.com](https://www.securityweek.com/claude-mythos-turns-n-days-into-n-hours-with-rapid-exploit-creation/).

**Prioritization and disclosure**

14. J. Jacobs, S. Romanosky, B. Edwards, M. Roytman, I. Adjerid. "Exploit Prediction Scoring System (EPSS)."
    2019. [arXiv:1908.04856](https://arxiv.org/abs/1908.04856). Scores published by FIRST at
    [first.org/epss](https://www.first.org/epss/).
15. Akrites. "An Open Letter: We All Depend on Open Source. We Will Defend It Together." 2026.
    [akrites.org/letter](https://akrites.org/letter/). Launches a coordinated industry effort to find, fix and
    responsibly disclose vulnerabilities in critical open-source software, which in this model's terms is an
    attempt to raise remediation completeness $f$ and coordinate disclosure $\delta_d$.

**Security economics**

16. R. Anderson. "Why Information Security Is Hard — An Economic Perspective." *Proceedings of the 17th Annual
    Computer Security Applications Conference (ACSAC)*, 2001.
    [acsac.org/2001/papers/110.pdf](https://www.acsac.org/2001/papers/110.pdf).
17. L. A. Gordon, M. P. Loeb. "The Economics of Information Security Investment." *ACM Transactions on
    Information and System Security* 5(4), 2002. [doi:10.1145/581271.581274](https://doi.org/10.1145/581271.581274).

**Further reading for the exploited-systems layer**

18. Rapid7. "Microsoft SharePoint JWT Token Authentication Bypass Technical Analysis (CVE-2026-55040)."
    [rapid7.com](https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040/).
19. SecurityWeek. "SharePoint vulnerability exploited shortly after PoC release."
    [securityweek.com](https://www.securityweek.com/sharepoint-vulnerability-exploited-shortly-after-poc-release/).

**Exploitation telemetry**

20. P. Garrity, VulnCheck. "2025 Q1 Trends in Vulnerability Exploitation." 2025-04-24.
    [vulncheck.com](https://www.vulncheck.com/blog/exploitation-trends-q1-2025). Source of the 28.3% of 159
    newly exploited CVEs with exploitation evidence within a day of publication.
21. T. Embry, VulnCheck. "What 28 Days of Faster Vulnerability Intelligence Is Worth." 2026-02-11.
    [vulncheck.com](https://www.vulncheck.com/blog/economic-value-lead-time). Source of the lead over KEV: a mean
    of 28.13 days and a median of 3 across 376 shared CVEs, VulnCheck first in 254 (67.6%).
22. Verizon. *2025 Data Breach Investigations Report*, Figure 17 and accompanying text.
    [verizon.com](https://www.verizon.com/business/resources/reports/2025-dbir-data-breach-investigations-report.pdf).
    Source of edge devices and VPNs as the target in 22% of breaches involving vulnerability exploitation
    (n = 1,930), against 3% in the 2024 report.
23. G. Sharadin, A. Reich, Imperva. "CVE-2025-5777 Exposes Citrix NetScaler to Dangerous Memory Leak Attacks."
    2025-07-11. [imperva.com](https://www.imperva.com/blog/cve-2025-5777-exposes-citrix-netscaler-to-dangerous-memory-leak-attacks/).
    Source of the more than 11.5 million attack attempts against CitrixBleed 2.
24. J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, A. Sarabi. "Enhancing Vulnerability Prioritization:
    Data-Driven Exploit Predictions with Community-Driven Insights" (EPSS v3). 2023.
    [arXiv:2302.14172](https://arxiv.org/abs/2302.14172). Source of the F1 operating point: scores of 0.36 and
    above flag 3.5% of CVEs and cover 67.8% of exploited ones, at 78.5% efficiency.
25. Tenable. "Microsoft Patch Tuesday 2025 Year in Review."
    [tenable.com](https://www.tenable.com/blog/microsoft-patch-tuesday-2025-year-in-review). Source of the 1,130
    CVEs Microsoft patched in 2025, 94 a month, against which July 2026's 621 is 6.6×.

**Exploitation announcements**

26. Microsoft Security Response Center. *Security Update Guide.*
    [msrc.microsoft.com/update-guide](https://msrc.microsoft.com/update-guide). Read through the CVRF API,
    `https://api.msrc.microsoft.com/cvrf/v3.0/`, whose per-CVE threat notes carry `Exploited:Yes` or `Exploited:No`.
27. OASIS. *Common Security Advisory Framework Version 2.0*, OASIS Standard, 2022.
    [docs.oasis-open.org](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html). Defines the
    `exploit_status` category of a vulnerability's `threats`.
28. Google Project Zero. *0day "In the Wild".*
    [googleprojectzero.blogspot.com/p/0day.html](https://googleprojectzero.blogspot.com/p/0day.html).
