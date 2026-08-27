# Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model

A continuous-time model of how vulnerabilities move from discovery to exploitation to removal, parameterized
from public vulnerability data and evaluated for two populations: the **global software ecosystem** and
**Microsoft SharePoint** as an instance of enterprise server software. Time is in days throughout. Data
acquisition is in `VulnData.ipynb`; figures and their derivations are in `ODEtoVuln_daily.ipynb`. Snapshot:
**2026-08-27**.

## Executive summary

Vulnerabilities are discovered, disclosed, sometimes exploited, and eventually removed, and counting them at
any single moment says little about which changes would help, because each population responds to a change on
its own timescale — some in weeks, some over a decade. This model tracks five such populations with rates
measured from public data, so the effect of changing any one input can be followed through to the number of
vulnerabilities under active exploitation. Parameters come from NVD, the CISA KEV catalogue and published
incident telemetry, for the global software ecosystem and for Microsoft SharePoint as an instance of enterprise
server software, and the result is tested against a quantity that was not used to fit it.

- **Finishing remediations matters far more than accelerating them.** Only about a quarter of exploited
  vulnerabilities are ever fully patched, so the remainder persist until the affected software leaves service —
  which makes the completeness of remediation the dominant influence on how many vulnerabilities are under
  exploitation, and the speed of patching nearly irrelevant to it.
- **The volume of newly discovered vulnerabilities barely moves exploitation.** Attackers already have roughly
  three times more weaponizable material than they convert, so a tenfold rise in discovery raises exploitation
  by under half while merely tripling their production capacity nearly doubles it; and no population examined
  here shows discovery slowing, including a two-decade-old product.
- **The counts being measured lag reality by years and are still rising.** The populations that matter have
  five-year memories and stand at roughly 60% of the level that today's discovery rate already implies, so
  exploitation counts cannot be used to judge a control introduced last quarter, and a discovery surge that
  fades entirely still leaves exploitation climbing afterwards.

Taken together, these shift attention away from the speed of response and the volume of disclosure, and toward
the completeness of remediation and the retirement of old software — both of which act slowly enough that
starting late is the main way to lose. The principal limitation is that the model counts vulnerabilities rather
than compromised systems, so a single flaw exploited across millions of hosts registers exactly as one
exploited once. Extending the model to exposure-weighted outcomes, and stratifying vulnerabilities by how
exposed they are, are the two developments most likely to change these conclusions; both are set out in the
closing section on future work.

Contents

- [1. The system](#1-the-system)
    - [Discovery, disclosure, and the known backlog](#discovery-disclosure-and-the-known-backlog)
    - [Conversion: from opportunity to exploitation](#conversion-from-opportunity-to-exploitation)
    - [Exploitation, and the two ways out of it](#exploitation-and-the-two-ways-out-of-it)
    - [Finite vulnerability supply, as a forcing layer](#finite-vulnerability-supply-as-a-forcing-layer)
- [2. Data](#2-data)
    - [Measured quantities](#measured-quantities)
    - [How each parameter is obtained](#how-each-parameter-is-obtained)
    - [Measurement biases in the source data](#measurement-biases-in-the-source-data)
    - [Tests against quantities not used in calibration](#tests-against-quantities-not-used-in-calibration)
- [3. Results, and the visualization establishing each](#3-results-and-the-visualization-establishing-each)
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
    - [Visualization 11 — phase portrait](#viz-11)
    - [Visualization 12 — the fast manifold in 3-D, rotated](#viz-12)
- [Limitations](#limitations)
- [Future work](#future-work)
    - [1. Stratify by exposure class](#1-stratify-by-exposure-class)
    - [2. Tighten the decommissioning rate, which the anchor no longer constrains](#2-tighten-the-decommissioning-rate-which-the-anchor-no-longer-constrains)
    - [3. A layer above: exploited systems](#3-a-layer-above-exploited-systems)
    - [4. A layer above that: the economics of attack and defence](#4-a-layer-above-that-the-economics-of-attack-and-defence)

Links resolve against the rendered document; the visualization entries reach the figure sections, which are generated from `ODEtoVuln_daily.ipynb` and appear after the text.

## 1. The system

Five stocks hold vulnerabilities. Three describe where a vulnerability sits before it is attacked, and two
describe what happens after it is.

![Five stocks and the flows between them, labelled with the terms used in the equations](figure:structure)

### Discovery, disclosure, and the known backlog

$$
\dot H = \gamma - \delta_d H - \mathrm{conv}\,\beta_h H
$$

$H$ is the **hidden pool**: vulnerabilities that someone has found but that are not yet public. It fills at
the discovery rate $\gamma$ and empties two ways — by disclosure at rate $\delta_d$, and by being exploited
before disclosure at hazard $\beta_h$. Its mean residence time $1/(\delta_d + \mathrm{conv}\,\beta_h)$ is about
45 days, so $H$ is a fast state.

$$
\dot N = \delta_d H - \mu N - \mathrm{conv}\,\beta_n N
$$

$N$ is the **freshly disclosed pool**. Its only inflow is disclosure from $H$, which couples the two: nothing
becomes public without having first been found. It empties by maturing into the standing backlog at rate
$\mu$, and by being exploited at hazard $\beta_n$. With $\mu$ = 1/30 day⁻¹ — one patch cycle — $N$ is also
fast, about 30 days.

$$
\dot X = \mu N - \phi X - \mathrm{conv}\,\beta_x X
$$

$X$ is the **known backlog**: disclosed, aged, mostly patch-available, and by far the largest stock. It empties
by retirement at rate $\phi$ — the vulnerability ceases to matter because the affected version leaves support —
and by exploitation at hazard $\beta_x$. Its residence time $1/(\phi + \mathrm{conv}\,\beta_x)$ is about 1,820
days, so $X$ is a **slow** state: five years against forty-five days for $H$. That ratio produces most of the
model's dynamic behaviour.

The three hazards differ by two orders of magnitude, which is what separates a zero-day from an aged CVE: a
vulnerability in $H$ or $N$ is far likelier to be attacked per day than one in $X$. But $X$ is so much larger
that it still supplies most exploitation in absolute terms.

### Conversion: from opportunity to exploitation

$$
P = \beta_h H + \beta_n N + \beta_x X, \qquad
I = \frac{C\,P}{C + P}, \qquad
\mathrm{conv} = \frac{I}{P}
$$

$P$ is the **gross rate at which weaponizable opportunities arise** — the sum of the three hazard flows. It is
not the rate at which exploitation happens, because converting an opportunity into deployed exploitation takes
attacker effort, and that effort is finite. $C$ is the **throughput ceiling**: the maximum conversion rate. The
saturating form gives $I \approx P$ when opportunities are scarce relative to capacity, and $I \to C$ when they
are abundant. **This is the mechanism by which discovery volume stops mattering:** once $P \gg C$, additional
vulnerabilities queue rather than convert.

$\mathrm{conv} = I/P$ is the converted share, and it appears in all three pool equations for a conservation
reason. An opportunity attackers do not take is not destroyed — the vulnerability stays in its pool, still
disclosed, still unpatched, still available later. Only the converted share leaves. With this factor, discovery
equals retirement plus patching plus decommissioning exactly; without it the pools would shed $P - I$
vulnerabilities per day into nothing. Because $\mathrm{conv}$ depends on the pools and the pools depend on
$\mathrm{conv}$, the equilibrium is solved self-consistently.

### Exploitation, and the two ways out of it

$$
\dot E_p = f I - \left(\delta + \frac{\rho}{1+\tau} + \lambda\right) E_p, \qquad
\dot E_r = (1-f) I - \lambda E_r, \qquad E = E_p + E_r
$$

Exploited vulnerabilities split into two compartments because remediation is not universal. $E_p$ is the
**remediable** share, draining through runtime mitigation at rate $\delta$, through patching at rate
$\rho/(1+\tau)$ — adoption speed $\rho$ discounted by the delay $\tau$ before adoption begins — and through
decommissioning at rate $\lambda$. Its residence time is about 124 days.

$E_r$ is the **residual** share, which receives no patching and drains only by decommissioning, at
$1/\lambda \approx 5.5$ years. This asymmetry does more to set the exploited population than any other feature
of the model: the residual compartment holds influx × decommissioning horizon, roughly forty times what the
remediable compartment holds.

$f$ is the share of realized exploitation routed to $E_p$. Because part of $E_p$ still exits by decommissioning
rather than patching, $f$ = 0.277 is calibrated so the *realized* ever-patched share equals the measured 26 per
cent.

Two structural consequences follow. There is **no ceiling on $E$**: the system is bounded because
$\lambda > 0$, so the brake on exploitation is software leaving service, not attacker saturation. And the system
is **linear except for the conversion term**, which is monotone and saturating, so exactly one equilibrium
exists and it is stable.

### Finite vulnerability supply, as a forcing layer

A codebase contains finitely many vulnerabilities, so discovery in principle depletes a reservoir:

$$
\dot U = \sigma S - \psi U, \qquad \gamma = \psi U
$$

$U$ is the latent stock of undiscovered vulnerabilities, depleted by discovery at efficiency $\psi$ and
replenished at $\sigma S$ as new code ships. Section 2 shows that $U$ cannot be estimated from available data
and that discovery is not currently supply-limited, so $\gamma$ is held at its measured value in every figure
except Visualization 7, where $U$ is evolved separately to generate $\gamma(t)$. The five stocks above are the
integrated states.

## 2. Data

| Source | Provides |
|---|---|
| **NVD** (`services.nvd.nist.gov/rest/json/cves/2.0`) | the CVE corpus, publication dates and rates, CVSS attack vectors, and the CISA KEV flags mirrored into each record |
| **CISA KEV** | which CVEs are known-exploited, the date CISA added each, and the federal remediation deadline |
| **MITRE** (`cveawg.mitre.org`) | CNA publication timestamps, used to confirm NVD's dates are not materially lagged |
| Published telemetry | Verizon 2026 DBIR (remediation completeness and delay), CrowdStrike 2026 (pre-disclosure share), Mandiant M-Trends 2026 (time-to-exploit), ZDI (monthly vendor volumes), Synopsys OSSRA (vulnerability age) |

### Measured quantities

| Quantity | Global | SharePoint |
|---|---|---|
| CVE corpus | 383,528 | 693 (across 8 CPE product names) |
| Publication rate | **212/day** trailing year; 330/day most recent quarter | **0.178/day** 3-year (used); 0.378/day trailing year |
| Publication history | 2008–2026: 5,652 → 89,022/yr, CAGR **+32%** for 2021–2026 | 2003–2026; 2026 annualizes to 188, the highest on record |
| Known-exploited (KEV) | 1,682 = 0.44% of corpus; influx **0.81/day**, 2022 to the snapshot | 21 = **3.0%**, i.e. **6.9×** the global rate |
| Disclosure → exploitation lag | median 266 d (p10 0, p90 2,660) | median 105 d |
| Exploited by publication day | 12.8% in KEV; **42%** in broader telemetry | 3 of 21 |
| Network-reachable (CVSS AV:N/A) | 75.0% | 76.9% |
| Ever fully patched | **26%**; median delay **43 days** for those that are | same figure applied |

### How each parameter is obtained

**Measured directly:** $\gamma$ (publication rate); the exploitation influx used to calibrate $C$ (KEV
additions); the pre-disclosure share; $\varepsilon$ (CVSS reachability); $\tau$ and the 26% completeness.

**Pinned by consistency:** the hazards $\beta_h, \beta_n, \beta_x$ are set so the model reproduces the measured
exploitation influx with the measured split between pre-disclosure, fast n-day and aged exploitation. $C$ is
set so realized conversion equals the measured KEV rate at current supply.

**Assumed, each tested in the figure noted:** $\delta_d$ = 1/45 day⁻¹ (the 90-day coordinated-disclosure norm,
many vendor-found bugs faster); $\mu$ = 1/30 day⁻¹ (one patch cycle); $\phi$ = 1/1825 and 1/3650 day⁻¹ (5- and
10-year support horizons); $1/\lambda$ = 5.5 years, from mean OSS vulnerability age of 2.5+ years with a quarter
of codebases carrying decade-old flaws — tested in Visualization 5; and the supply-to-throughput ratio $P/C$ =
2, the one free structural quantity and the reason $C$ is a floor rather than an estimate.


### Measurement biases in the source data

Three act in a known direction and are not corrected for.

**Publication-date rates are undercounts.** A window's count is not fixed when the window closes: NVD keeps
ingesting records whose publication date falls inside it. The window 2026-05-07 → 2026-08-06 returned 25,148
when first counted on 2026-08-06 and **25,361 eight days later — +0.85%**. Re-queried again at this snapshot,
thirteen days later still, it returned 25,361 unchanged: the late-arrival tail is front-loaded, essentially
complete within a fortnight. The corpus meanwhile grew at 462/day against a windowed publication rate of
330/day. Every $\gamma$ here is therefore low, by more for the most recent weeks, and the acceleration signal is
understated rather than overstated. The 2008–2026 history used for the transient runs is as-measured and not
back-corrected.

**Single-product rates are quantized by release cadence.** SharePoint gained 29 CVEs in the eight days to
2026-08-14, all published on 2026-08-11 — one Patch Tuesday — which moved its trailing-year rate by 22%. The
3-year rate is used for that reason; a trailing-year rate for one product is dominated by whichever releases
fall inside the window.

**KEV is a lower bound on exploitation, and its additions reflect cataloguing policy.** Annual additions run
311, 555, 187, 186, 245 for 2021–2025 and 198 so far in 2026; nothing in the world changed threefold in 2023.
The influx is therefore pooled rather than averaged year by year: 1,371 additions from 2022-01-01 to the
snapshot over 1,699 elapsed days, **0.81/day**. Pooling damps the year-to-year swing and lets the partial
current year contribute at its true weight instead of as a full year. 2021 is excluded because KEV opened that
November and its 311 additions are a backfill of pre-existing exploitation, not a rate. Even so, exploitation
influx — and therefore the throughput $C$ calibrated from it — is a floor.

### Tests against quantities not used in calibration

1. **Exploited stock, global.** KEV holds 1,682 entries. The obvious anchor — 26% are ever fully patched, so
   ~1,245 should remain unremediated — is not one, because it applies the *completed* limit for patching and the
   *zero* limit for decommissioning at the same instant. KEV opened 2021-11-03 and was backfilled to 2002, so by
   publication date **43% of its entries are older than one residual residence time** and have already been
   decommissioned. Running the catalogue's onset history through the exit kernel the model integrates,
   $\sum_i [\,f e^{-(\rho/(1+\tau)+\delta+\lambda) a_i} + (1-f) e^{-\lambda a_i}\,]$ for onset ages $a_i$, puts
   both sides on one clock and gives **607 [572, 750]**, the bracket spanning the two defensible onset proxies
   (NVD publication at the low end, CISA's addition date at the high). Today's state is **704** — ratio
   **1.16**, inside the bracket but at its upper end; the equilibrium target 1,193 gives 1.97. The transient is
   the correct comparison, since the anchor is itself an accumulated quantity. That the target 1,193 lands near
   the naive 1,245 is a coincidence of two errors cancelling, not a second agreement.
2. **Exploited stock, SharePoint.** Its 21 KEV entries give a kernel anchor of **10.1 [9.6, 11.5]** against
   today's **12.0** — ratio 1.19, within one Poisson standard error at $n$ = 21, which is 22% — and a target of
   15.3, ratio 1.52. This test also fixes a parameter: at SharePoint's 10-year support horizon the ratios
   degrade to 1.62 and 2.54, identifying decommissioning of exploited instances as a ~5-year process. Support
   duration governs patch availability ($\phi$); it does not govern removal from service ($\lambda$).
3. **Backlog size.** A pool fed at $\gamma$ and drained by retirement and exploitation settles at
   $\mu N/(\phi + \mathrm{conv}\,\beta_x)$: **385,394** against NVD's 383,528 — **+0.5%**, from a 5-year support
   horizon that was assumed rather than fitted — and **609** against 693, 12% low. The SharePoint shortfall runs
   in the direction expected from CVEs outliving their support horizon; the global figure, which was 5% low at
   the previous snapshot, has been carried across the mark by a quarter of accelerating publication, so its
   present near-exactness should be read as the right order of magnitude rather than as precision.
4. **Is discovery supply-limited?** Fitting saturating curves to 19 years of cumulative discovery leaves the
   reservoir unidentified. The Gompertz form runs $U$ to **4.3 billion** — four orders of magnitude past the
   observed corpus — against the fit's upper bound, where the covariance estimate collapses to zero; a
   parameter the data cannot constrain, not one it pins down. The logistic form gives 1,975,556 ± 691,875, 35%
   relative. Depletion additionally requires the cumulative curve to decelerate, and second differences are
   positive in every year 2021–2026. For SharePoint, asymptotes of 13,720 / 1,828 / 958 emerge from fitting
   through 2022 / 2023 / 2024, so the estimate tracks the recent slope rather than a stock. **The reservoir is
   not the binding constraint at either scale.**

Items 1 and 2 are weaker than the heading implies, and the correction to item 1 is what exposes it. $C$ is
calibrated from the KEV rate, and 80% of the corrected global anchor — 486 of 607 — comes from onsets after the
catalogue opened, inside the window calibration used. What survives as independent content is the *shape* of
the onset history rather than its level: observed onsets per day run 0.34, 0.74, 1.17 and 0.80 times the
model's realized conversion $I(t)$ over 2008–2015, 2016–2020, 2021–2023 and 2024–2026. The early shortfall runs
in the direction KEV's documented incompleteness predicts; the 0.80 in the current window is the same 16%
overshoot that item 1 reports, seen as a rate rather than a stock. The exit kernel is tested on top of that,
and only loosely: the ratio is flat at about 0.86 for $1/\lambda$ anywhere from 3 to 8 years, falling to 0.77
at 12 and 0.65 at 20, so the anchor excludes a decade-plus horizon but cannot pick a value inside 3–8.

## 3. Results, and the visualization establishing each

**Two mechanisms set the level of exploitation, and they separate cleanly — Visualization 1.** A waterfall
isolates each. Were every exploited vulnerability eventually patched, the standing exploited population would
be **100**; at the measured 26% completeness with unconstrained conversion it would be **3,573**; with the
throughput ceiling applied it is **1,193**. The right panel sets that against the KEV-derived anchors — **607
[572, 750]** global and **10.1 [9.6, 11.5]** SharePoint, the catalogue run through the model's own exit kernel so
that both sides count over the same window — and against today's history-driven state, **704** globally. The
figure shows the level to be the product of two independently measured facts, how little is ever remediated and
how little supply is converted, rather than a fitted outcome. It also carries the marker for the anchor the
kernel replaces, 1,245, which is the same catalogue with no decommissioning applied at all.

**Discovery volume is nearly inert; throughput is not — Visualization 2.** $E^*$ contoured over a discovery
multiplier and a throughput multiplier. The contours asymptote to horizontal: a 10× increase in discovery moves
$E^*$ **+43%**, while tripling throughput alone moves it **+80%**. Microsoft's July 2026 release appears as an
observed point — **621 CVEs shipped with 2 under active exploit**, 6.6× its 2025 monthly volume with
exploitation flat. The figure separates the axis that saturates, which is what CVE counts measure, from the
axis that does not, for which no published index exists.

**Finite vulnerability supply does not bind — Visualization 3.** Annual discovery with the cumulative curve and
two saturating fits, beside SharePoint's cumulative curve with asymptotes fitted through three successive
cutoff years. It shows why a depletion argument cannot be sustained on these data: the aggregate curve
accelerates and the per-product asymptote is an artifact of the fitting window. It also states what would
falsify the conclusion — **per-product discovery must bend where code is not churning.**

**Which lever dominates is determined by remediation completeness — Visualization 4.** Elasticities of $E^*$
for both ecosystems beside a counterfactual in which every exploited vulnerability is eventually patched. At
the measured 26%, decommissioning dominates (−0.98) and patch delay is negligible (+0.01); in the
counterfactual the ranking inverts to patch delay +0.55, adoption −0.56, decommissioning −0.06. Since both
columns are the same model at different completeness, an argument about which control matters is an argument
about completeness.

**Completeness and decommissioning outweigh the attacker-side scenarios — Visualization 5.** $E^*$ against the
ever-patched share at three decommissioning horizons, with the AI scenarios as reference levels and a ranked
lever comparison. Raising the ever-patched share from 26% to 75% cuts $E^*$ **66%**; shortening the
decommissioning horizon from 5.5 to 3 years cuts it **44%**; a 10× discovery increase costs +43% and a 3×
throughput increase +80%. The figure also carries the model's largest sensitivity: the 26% figure and the
5.5-year horizon jointly set the level to within a factor of three.

**The flow structure is thin at the point that matters — Visualization 6.** The stock-and-flow diagram with
measured rates, arrow widths scaled to flow, and the conversion node drawn explicitly. Globally 212 CVEs a day
enter and 0.81 a day are converted — **1 in 263** — with 33% of gross opportunity realized; for SharePoint the
ratio is 1 in 16. The residual compartment holds 1,165 of the global 1,193. The diagram is also where
conservation is visible: every box balances and unconverted opportunities remain in their pools.

**The choice of discovery future barely propagates — Visualization 7.** Four trajectories for $\gamma$ — an
exogenous fade, a permanent step to the measured 1.56×, compounding at +44%/yr capped at 10×, and a 10×
efficiency jump against the finite reservoir — with the resulting $E$. Every path rises steeply from today's
704, to between 1,187 and 1,690 over thirty years, because the slow compartments are still filling whatever
discovery does. But three of the four land within **13% of one another**; only sustained compounding separates,
and the reservoir case turns over without any behavioural assumption. The choice of discovery future is worth
less than the fact that the backlog has not finished draining into exploitation.

**The system has two clocks — Visualization 8.** Each stock along the measured 2008–2026 publication history,
continued at today's rate for forty years, against its equilibrium target. The fast pools have overshot theirs:
hidden and disclosed sit at **115%** of target globally and **290%** for SharePoint, because a stock whose
residence time is weeks tracks a rising inflow instead of lagging it. The slow ones are nowhere near — the known
backlog is at **50%** of target and needs **8 more years** to reach 90% of it, and the residual exploited
compartment is at **58%**, needing **9**. SharePoint's backlog is at 72%, its residual at 78%. This is the
quantitative reason exploitation counts cannot evaluate a control introduced last quarter: most of the movement
still to come was already committed by publications that happened years ago.

**Effect and speed rank in nearly opposite orders — Visualization 9.** Five controls at an equal 30% relative
improvement, plotted as effect against time-to-90%. Patch delay acts within a year and moves $E^*$ by 0.4%;
the ever-patched share and decommissioning move it 10.5% and 22.6% but take **14 and 16 years**. Retirement is
worse on both counts — 3.4% over 22 years. Controls acting directly on the exploited compartments are fast and
weak; controls acting through stocks are slow and strong.

**The two levers programmes control move the outcome least — Visualization 10.** Realized exploitation over
patch delay and reachable surface. Across the full plausible plane the outcome varies less than a 3× change in
throughput produces, because $\tau$ acts only on the 26% remediable share and surface reduction removes supply
that was not being converted.

**One equilibrium, stable, in both ecosystems — Visualization 11.** The slow $(X, E_r)$ plane with the fast
states on their manifolds. The $\dot X = 0$ nullcline is vertical, because the backlog's inflow does not depend
on exploitation once $N$ is on its manifold; the $\dot E_r = 0$ nullcline rises and flattens as conversion
saturates. They cross once, establishing that no second equilibrium or threshold behaviour exists in this
structure.

**The reduction behind Visualization 11 is justified — Visualization 12.** Trajectories of the full system in
$(N, X, E_r)$, rotated through 360 viewpoints. Every orbit collapses onto the $\dot N = 0$ surface within weeks
and then travels along it. That the surface is independent of $X$ and $E_r$ is what licenses the plane portrait,
and is why its $\dot X = 0$ nullcline is a straight line.

## Limitations

1. **Mean-field.** One hazard per pool, against a top decile of vulnerabilities concentrating most exploitation
   and 22% of initial access running through edge devices and VPNs, up from 3%. Stratifying by exposure class is
   the extension most likely to change the results — Future work §1.
2. **$E$ counts vulnerabilities, not compromised systems.** A single vulnerability drawing 11.5M+ attack
   attempts scores as 1. A rise in breadth per vulnerability is invisible here — Future work §3.
3. **$C$ is calibrated, not measured**, so it absorbs every unmodelled mechanism, including defender
   interdiction — Future work §4.
4. **The 26% ever-patched figure is one survey median** and carries more of the result than any other value. At
   50%, $E^*$ is 806 rather than 1,193; at 75%, 403.
5. **KEV is a floor.** Exploitation is identified elsewhere a median 3 days and a mean 28 days earlier, in
   two-thirds of shared cases.
6. **No defender adaptation.** $f$, $\tau$ and $C$ are constants; coordinated disclosure programmes are attempts
   to move $f$ and $\delta_d$, and the model cannot represent their effect — Future work §4.
7. **Non-stationarity.** 2026 is running at 243.7 CVEs/day against 2025's 136.9, so equilibrium statements
   describe a moving target. Thirteen days of fresh data moved $\gamma$ by 7% and carried the backlog check
   from 5% low to 0.5% high.

## Future work

The four items below are ordered by dependency: the first two complete the present layer, the third builds a
layer above it, and the fourth builds a layer above that. Each later layer consumes the one beneath it, so the
value of the third depends on the first two being settled.

### 1. Stratify by exposure class

Every hazard in this model is a single population average. Exploitation is not distributed that way: a top
decile of vulnerabilities by exploit-prediction score concentrates most observed exploitation, and 22% of
initial access now runs through edge devices and VPNs, up from 3%. Averaging over that structure means the
model cannot express the distinction that matters most — the same total discovery, concentrated differently
across exposure classes, produces very different exploitation.

The change is to split each pool into two or three classes (internet-facing and pre-authentication;
network-reachable but authenticated; local or adjacent) with class-specific $\beta$, $\varepsilon$, and
possibly class-specific $f$ and $\lambda$. Classes are observable: CVSS attack vector and privilege
requirements assign them, and KEV membership per class supplies the exploitation rates. It admits a test that
the present model cannot attempt — a class-stratified calibration should reproduce the *composition* of the KEV
catalogue, which vendors and which classes dominate it, without being fitted to that composition.

### 2. Tighten the decommissioning rate, which the anchor no longer constrains

The near-factor-of-two anchor gap this section previously listed as unexplained — 1,245 against a state of 704
at this snapshot — was mostly an artifact of the anchor's definition, not a defect in the model. §2 gives the
correction: the naive anchor removes the 26% that are ever patched while removing none of the software that
leaves service, and once the catalogue's onset history is run through the model's own exit kernel the anchor
becomes 607 [572, 750] against 704 — a residual of 16%, inside the onset-proxy bracket, where the naive
comparison showed 77%. Of the four causes once listed, the accumulation-window mismatch accounts for all but
that 16%; positing a KEV-specific ever-patched share is no longer needed to explain anything. The remaining
overshoot and the argument for recalibrating $C$ point the same way, and §2's onset-history comparison
localizes it: the model's realized conversion runs about a quarter above observed KEV onsets in the current
window, which is the same discrepancy expressed as a rate.

What that leaves is a parameter with no tight constraint on it. $1/\lambda$ = 5.5 years rests on open-source
vulnerability age, and the corrected anchor cannot do better than exclude 12 years: it is consistent with
anything from 3 to 8. Since $\lambda$ sets the residual compartment's residence time, and that compartment holds
roughly forty times what the remediable one does, it remains the most load-bearing number in the model —
Visualization 5 sweeps it for that reason. **Fit it to how long KEV-listed vulnerabilities remain observable in
internet-exposure scans**, which measures removal from service directly rather than inferring it from the age of
flaws still present. Scan telemetry per CVE, tracked over years, is the input; the test is whether the fitted
horizon lands inside the 3-to-8-year window the anchor allows, and whether SharePoint's shorter horizon survives
against its own scan history.

### 3. A layer above: exploited systems

The present layer counts vulnerabilities. Harm accrues to systems, and the two are not proportional: one
vulnerability drew 11.5M+ attack attempts, and this model scores it as 1. That is the limitation named in the
executive summary, and the way to address it is a second layer that consumes this one's output rather than a
modification of it.

For each vulnerability in the exploited compartments, the second layer would carry a susceptible installed base
$S_i$ and a compromised count $Q_i$, with $\dot Q_i$ driven by scan-and-exploit contact against $S_i$ and
drained by instance-level remediation — an epidemic layer whose *number of simultaneous epidemics* is supplied
by the layer below. Aggregate harm becomes a weighted sum over $Q_i$ rather than a count of vulnerabilities.
Exposure counts per product, scanning telemetry and incident counts parameterize it. The reason this matters
for the conclusions already drawn: automation plausibly increases the breadth of exploitation per vulnerability
without changing the number of vulnerabilities exploited, which is a large movement in harm that the present
layer registers as no movement at all.

### 4. A layer above that: the economics of attack and defence

Both models above take effort as given. $C$ — attacker throughput, the parameter that dominates the response to
automation — is calibrated rather than explained, and the defender-side parameters $f$, $\tau$, $\rho$ and
$\lambda$ are constants, so neither side can adapt. A third layer would make them decisions.

On the attack side, throughput becomes a choice: spend on exploit production against expected return per
compromised system. Both terms are now approximately measurable — per-exploit production costs have been
reported from a few dollars for reproducing a known vulnerability to a few thousand for a chained privilege
escalation, and expected return follows from the second layer's compromise counts. On the defence side,
completeness, patch speed and retirement each carry a cost curve, and the equilibrium sits where marginal cost
equals marginal harm avoided. The questions this layer can answer and the others cannot: whether the observed
rise in throughput reflects falling production cost or rising expected return; whether an attacker's optimal
throughput scales with a hundredfold fall in exploit cost or saturates against target selection and
monetization; and whether a defender's best response shifts from speed toward completeness as attacker costs
fall — which the present layer hints at, since patch timing loses value once exploitation routinely precedes
disclosure. It would also settle a question the current model cannot pose: whether the historical stability of
exploitation rates is coincidence or an equilibrium between two adapting parties.
