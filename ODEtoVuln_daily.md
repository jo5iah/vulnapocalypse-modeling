
# Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model

This document models how vulnerabilities move from discovery to exploitation to removal. It fits public
vulnerability data to a compartment model of ordinary differential equations, and evaluates two populations:
the **global software ecosystem**, and **Microsoft SharePoint** as an instance of enterprise server software.
The model is explicable the way epidemiology models are. Every result traces to a named rate with a stated
source or assumption. A disagreement with a conclusion can therefore be located in a specific parameter, not
in a fitted predictor's weights. Time is in days throughout. Snapshot: **2026-11-16**.

The data behind every parameter are on a separate page,
[The Data Behind the Model](https://jo5iah.github.io/vulnapocalypse-data/). Data acquisition is in
`VulnData.ipynb`. The model and every figure here are computed in `ODEtoVuln_daily.ipynb`. This document is
the only written account of what the model shows.

## Executive summary

Security programs are measured on how fast they patch. This model asks a different question: what sets the
number of vulnerabilities under active exploitation at any moment? It answers with rates measured in public
data (NVD, the CISA KEV catalog and published incident telemetry), for the whole software ecosystem and for
Microsoft SharePoint. Four findings bear on where a program should spend.

- **Finishing remediation and shrinking reachable surface beat patching faster.** About a quarter of
  exploited vulnerabilities are ever fully patched. The rest stay exploitable until the software leaves
  service. A 30% cut in patch delay changes the standing count by **0.2%**. The same 30% applied elsewhere
  does far more: **16.1%** for reachable surface, **10.5%** for completed remediations, and **22.9%** for the
  rate at which exploited software is decommissioned.
- **Rising disclosure volume raises exploitation less than proportionally. How much less is the least
  certain number here.** A tenfold rise in disclosures raises exploitation **68%**. Tripling attacker capacity
  raises it **58%**. Both figures depend on how far weaponizable supply outruns attacker capacity, and no
  source measures that. The model sets the two equal, because that is where the catalog's growth sits. Across
  the plausible range the same two figures run from +126% and +34% to +35% and +90%. The divergence itself is
  measured. From 2025 to 2026 the disclosure rate rose **130%** and cataloged exploitation rose **38%**.
  Publications per cataloged exploit went from 204 to **339**, and to **414** over the last ninety days. Most
  of that widening is the five-year backlog lagging the surge in publications. It is not attackers running
  out of capacity.
- **The software with the most CVEs is not the software being exploited.** Over the past year the Linux
  kernel was second in CVE volume, with 3,338, and ranks **25th** in the exploitation catalog. Windows Server
  leads exploitation and is **fourth** by volume. Prioritizing by CVE counts points at the wrong software.
- **Nothing a program changes will show in these numbers for years.** The populations that drive
  exploitation turn over on a five-year clock. Today they sit at **37%** of the level that today's disclosure
  rate already implies: **727** exploited and unremediated vulnerabilities, against **1,981**. The exploited
  population needs 13 more years to reach 90% of that level, even if publication stops rising. Next quarter's
  exploited count cannot evaluate a control introduced last quarter.

The practical implication: move effort from response time toward completing remediations, reducing
reachable surface and retiring unsupported software. Expect none of them to register quickly. Section 2
states how far to trust these numbers.

Contents

- [1. The system](#1-the-system)
    - [Discovery, disclosure, and the known backlog](#discovery-disclosure-and-the-known-backlog)
    - [Conversion: from opportunity to exploitation](#conversion-from-opportunity-to-exploitation)
    - [Exploitation, and the two ways out of it](#exploitation-and-the-two-ways-out-of-it)
    - [Finite vulnerability supply, as a forcing layer](#finite-vulnerability-supply-as-a-forcing-layer)
- [2. How far to trust these numbers](#2-how-far-to-trust-these-numbers)
- [3. Results](#3-results)
    - [Visualization 1 — measured stocks and flows](#viz-1)
    - [Visualization 2 — what sets the level, and a test against the catalog](#viz-2)
    - [Visualization 3 — which parameters move the exploited population](#viz-3)
    - [Visualization 4 — defender completeness against attacker shocks](#viz-4)
    - [Visualization 5 — the patch-delay / attack-surface plane](#viz-5)
    - [Visualization 6 — discovery volume against attacker throughput](#viz-6)
    - [Visualization 7 — is finite vulnerability supply the binding constraint?](#viz-7)
    - [Visualization 8 — four futures for discovery, one of them mechanistic](#viz-8)
    - [Visualization 9 — where the system is, against where it is heading](#viz-9)
    - [Visualization 10 — five interventions at equal effort](#viz-10)
- [Limitations](#limitations)
- [Future work](#future-work)
- [Appendix: the slow-manifold reduction](#appendix-the-slow-manifold-reduction)
    - [Visualization 11 — phase portrait](#viz-11)
    - [Visualization 12 — the fast manifold in 3-D](#viz-12)
- [References](#references)
- [The Data Behind the Model](https://jo5iah.github.io/vulnapocalypse-data/) (separate page)

## 1. The system

Five stocks hold vulnerabilities. Three describe where a vulnerability sits before it is attacked. Two
describe what happens after.

![Five stocks and the flows between them, labeled with the terms used in the equations](figure:structure)

### Discovery, disclosure, and the known backlog

$$
\dot H = \gamma - \delta_d H - \mathrm{conv}\,\beta_h H
$$

$H$ is the **hidden pool**: vulnerabilities someone has found that are not yet public. It fills at the
discovery rate $\gamma$. It empties two ways: by disclosure at rate $\delta_d$, and by exploitation before
disclosure at hazard $\beta_h$. Its mean residence time, $1/(\delta_d + \mathrm{conv}\,\beta_h)$, is 45
days, so $H$ is a fast state.

$$
\dot N = \delta_d H - \mu N - \mathrm{conv}\,\beta_n N
$$

$N$ is the **freshly disclosed pool**. Its only inflow is disclosure from $H$, because nothing becomes public
without first being found. It empties two ways: by maturing into the standing backlog at rate
$\mu$ = 1/30 day⁻¹ (one patch cycle), and by exploitation at hazard $\beta_n$. It is also fast, at about 30
days.

$$
\dot X = \mu N - \phi X - \mathrm{conv}\,\beta_x X
$$

$X$ is the **known backlog**: disclosed, aged and mostly patch-available. It is by far the largest stock. It
empties by retirement at rate $\phi$, when the affected version leaves support, and by exploitation at hazard
$\beta_x$. Its residence time, $1/(\phi + \mathrm{conv}\,\beta_x)$, is 1,820 days. $X$ is therefore a
**slow** state: five years, against 45 days for $H$. That ratio produces most of the model's dynamic
behavior.

The per-vulnerability hazards differ by more than an order of magnitude. On a given day, a vulnerability in
$N$ is 24 times as likely to be attacked as one in $X$, and one in $H$ is 9 times as likely. $X$ still
supplies the most, because it is so much larger. At equilibrium $X$ supplies 62% of weaponizable
opportunity, $N$ 24% and $H$ 13%. Today the split is different. $X$ is at a third of its equilibrium size,
and the fast pools are swollen by the surge in publication. $X$ supplies 26%, $N$ 46% and $H$ 28%.

### Conversion: from opportunity to exploitation

$$
P = \beta_h H + \beta_n N + \beta_x X, \qquad
I = \frac{C\,P}{C + P}, \qquad
\mathrm{conv} = \frac{I}{P}
$$

$P$ is the **gross rate at which weaponizable opportunities arise**, the sum of the three hazard flows. It is
not the rate at which exploitation happens. Turning an opportunity into deployed exploitation takes attacker
effort, and that effort is finite. $C$ is the **throughput ceiling**, the maximum conversion rate. The
saturating form gives $I \approx P$ when opportunities are scarce relative to capacity, and $I \to C$ when
they are abundant.

The rest of the document depends on one consequence of this form. $I$ is concave in $P$, so **increases in
supply saturate but decreases do not**. Take $P = C$, the ratio assumed on today's state (§2). A tenfold rise
in $P$ raises $I$ by 82%. Cutting $P$ to 5% cuts $I$ by 90%. The elasticity of $I$ is $C/(C+P)$ with respect
to supply and $P/(C+P)$ with respect to capacity. Both are 1/2 at that ratio; they restate the assumed ratio.
At the equilibrium target the backlog has filled and $P = 1.23\,C$, so the two are 0.45 and 0.55.

$\mathrm{conv} = I/P$ is the converted share. It appears in all three pool equations for a conservation
reason. An opportunity attackers do not take is not destroyed. The vulnerability stays in its pool: still
disclosed, still unpatched, still available later. Only the converted share leaves. With this factor,
discovery equals retirement plus patching plus decommissioning exactly. Without it, the pools would lose
$P - I$ vulnerabilities a day to nothing. $\mathrm{conv}$ depends on the pools and the pools depend on
$\mathrm{conv}$, so the equilibrium is solved self-consistently.

### Exploitation, and the two ways out of it

$$
\dot E_p = f I - \left(\delta + \frac{1}{\tau + 1/\rho} + \lambda\right) E_p, \qquad
\dot E_r = (1-f) I - \lambda E_r, \qquad E = E_p + E_r
$$

Exploited vulnerabilities split into two compartments, because remediation is not universal. $E_p$ is the
**remediable** share. It drains three ways: through runtime mitigation at rate $\delta$, through patching,
and through decommissioning at rate $\lambda$. Patching waits $\tau$ days before adoption begins, then takes
$1/\rho$ days to complete. Its rate is therefore $1/(\tau + 1/\rho)$. Its mean time, $\tau + 1/\rho$, is 48
days, consistent with the measured 43-day median. The residence time of $E_p$ is 41 days.

$E_r$ is the **residual** share. It receives no patching. It drains only by decommissioning, at
$1/\lambda \approx 5.5$ years. This asymmetry sets the exploited population more than any other feature of
the model. The residual compartment holds influx × decommissioning horizon, 135 times what the remediable
compartment holds.

$f$ is the share of realized exploitation routed to $E_p$. A small part of $E_p$ still leaves by
decommissioning rather than patching. $f$ = 0.265 is therefore calibrated so that the *realized*
ever-patched share equals the measured 26%. The same leak caps the realized share at 98%, even when $f$ = 1.

Two structural consequences follow. First, there is **no ceiling on $E$**. The system is bounded because
$\lambda > 0$: the brake on exploitation is software leaving service, not attacker saturation. Second, the
system is **linear except for the conversion term**, which is monotone and saturating. Exactly one
equilibrium exists, and it is stable (Appendix).

### Finite vulnerability supply, as a forcing layer

A codebase contains finitely many vulnerabilities, so in principle discovery depletes a reservoir:

$$
\dot U = \sigma S - \psi U, \qquad \gamma = \psi U
$$

$U$ is the latent stock of undiscovered vulnerabilities. Discovery depletes it at efficiency $\psi$. New code
replenishes it at $\sigma S$. $U$ cannot be estimated from available data, and discovery is not currently
supply-limited (Visualization 7). Every figure therefore holds $\gamma$ at its measured value, except
Visualization 8, which evolves $U$ separately to generate $\gamma(t)$.

## 2. How far to trust these numbers

The sources, the measured quantities, how each parameter is obtained, the biases in the source data and the
checks against the catalog are on the [data page](https://jo5iah.github.io/vulnapocalypse-data/). This
section states what they mean for the results.

- **Read every exploitation figure as a floor.** The largest uncertainty cannot be resolved from public data.
  KEV records what CISA catalogs, not what attackers do. Its annual additions ran 555, 187 and 186 across
  2022 to 2024, driven by cataloging policy. Once the backlog's lag is removed, the gap between disclosure and
  cataloged exploitation still has three readings. Attackers may be modestly saturated. The rate of
  weaponization may itself be rising. Or the catalog may be falling behind, in which case every exploitation
  figure here is low by a growing margin. Only exploitation telemetry can separate them (Future work §5).
- **The absolute counts are orders of magnitude, not estimates.** Tested against the catalog on a consistent
  footing, today's count sits 13% above it. That is inside the range the catalog's dating allows
  ([anchor checks](https://jo5iah.github.io/vulnapocalypse-data/#checks-against-the-catalog-and-the-corpus)).
  Calibrating to every KEV addition since 2022, instead of since 2023, would raise the count 37%, because 2022
  holds the catalog's initial build-out.
- **Two assumed parameters carry the most weight.** The ratio of weaponizable supply to attacker throughput,
  $P/C$, sets every attacker-side sensitivity. Across its plausible range those responses move by a factor of
  two or more. The decommissioning horizon $1/\lambda$ sets the level: 3 to 10 years spans 1,092 to about
  3,600 exploited vulnerabilities.
- **Absolute figures have a shelf life of months.** Publication more than tripled within the trailing year
  the rates are read from.
- **The model counts vulnerabilities, not compromised systems.** One flaw exploited on a million hosts counts
  the same as one exploited once. That understates the scenario cheaper automated exploitation makes most
  likely.

The ranking of the defender levers survives all of these. Stratifying by exposure class and adding a layer of compromised systems are the extensions most likely to
change these conclusions (Future work §1 and §3).

## 3. Results

### Visualization 1 — measured stocks and flows

**The flow structure is thin at the point that matters.** This is the stock-and-flow diagram of §1 with
measured rates. Arrow widths scale with flow. Each box carries its target and today's value. At the target,
297.3 CVEs a day enter and 1.34 a day are converted: **1 in 222**. For SharePoint the ratio is 1 in 15,
consistent with its 7.0× higher KEV rate. Weaponizable supply reaches 2.99 a day against a throughput of
2.42. So 45% is converted, and the rest stays in the pools. The residual compartment holds 1,966 of the global
1,981 (99%), because it drains only through decommissioning. The pre-disclosure channel carries 13% of supply
at equilibrium and 28% today, while the backlog is still filling. A structure in which exploitation only
follows disclosure would omit this channel. KEV dates exploitation by its evidence, so 13% is a floor. Every
box balances.

![Visualization 1 — five stocks with measured flows for both ecosystems](figure:viz-1)

### Visualization 2 — what sets the level, and a test against the catalog

**The level is influx times residence time.** The model states it as $E = I \times T$: realized influx times
influx-weighted mean residence time.

$$
T = \frac{f}{\delta + 1/(\tau + 1/\rho) + \lambda} + \frac{1-f}{\lambda}, \qquad
E^* = 1.34/\text{day} \times 1{,}480\ \text{days} = 1{,}981
$$

$T$ rests on the measured remediation figures and the assumed decommissioning horizon. $I$ is the conversion
the system reaches once the backlog has filled at today's publication rate. It is calibrated on the KEV
history, but it is not itself a measured rate. It is above any rate the catalog has recorded (1.23/day over
the last ninety days), because the backlog that supplies 62% of it at equilibrium is a third full. Neither
term is fitted to $E$.

The upper panel factors the level one mechanism at a time. It starts from **123**, the level at full
conversion and full remediation. The throughput ceiling divides that by **2.2**, to **55**: the level if every
exploited vulnerability entered the remediable compartment. Incomplete remediation then multiplies it by
**36**. Routing 73% of the influx to a compartment that drains only by decommissioning stretches $T$ from the
41-day remediable residence to 1,480 days. Lifting the ceiling instead of applying it would give 4,424, which
is why the two steps are shown separately.

The equilibrium is a target, not today's state. Driven by the measured monthly 2008–2026 publication history,
today's global exploited population is **727**, 37% of the way there. The lower panel tests today's state
against the KEV catalog
([anchor checks](https://jo5iah.github.io/vulnapocalypse-data/#checks-against-the-catalog-and-the-corpus)).
It is 1.13× the global anchor, inside its bracket, and 1.42× SharePoint's. The naive anchor is marked for
comparison.

![Visualization 2 — the level as influx times residence time, factored one mechanism at a time, and tested against the KEV catalog](figure:viz-2)

### Visualization 3 — which parameters move the exploited population

**Which lever dominates depends on remediation completeness.** The figure shows elasticities of $E^*$ (±1%
central differences) for both ecosystems. Beside them is a counterfactual with $f$ = 1: all exploitation
enters the remediable compartment, and 98% is eventually patched.

At the measured 26%, decommissioning dominates at **−0.99**. Throughput follows at +0.55. Discovery, surface
and weaponization are at +0.45, and completeness at −0.35. Patch delay, adoption and mitigation are all at or
below ±0.01.

In the counterfactual, patch delay rises to **+0.77**, mitigation to −0.12 and adoption to −0.09.
Decommissioning falls to −0.02, and $E^*$ falls from 1,981 to 55. The patch-delay elasticity rises
monotonically with completeness: +0.016 at a 50% ever-patched share, +0.048 at 75%, +0.306 at 95%.

Both columns are the same model at different completeness. So a disagreement about whether patch timing or
software retirement matters more is, in this model, a disagreement about one number: the fraction of
exploited vulnerabilities an organization finishes remediating.

Throughput, discovery, surface and weaponization do not depend on completeness. They act on the influx, not
on either drain. The last three share one elasticity, +0.45, because each enters only through $P$. Their
split with throughput restates the assumed $P/C$.

The pale bars show the count five years out. Decommissioning (−0.49) stays on top. Surface and weaponization
(+0.40) are just ahead of throughput (+0.38), followed by discovery (+0.32) and completeness (−0.27).
Maturation (−0.12) passes retirement, which falls from −0.28 to −0.07. Maturation and patch delay are the
only levers not smaller at five years than at equilibrium.

![Visualization 3 — elasticities of the equilibrium exploited count, measured and at full remediation](figure:viz-3)

### Visualization 4 — defender completeness against attacker shocks

**Completeness and decommissioning move the target as far as the largest single attacker-side shocks.** The
figure plots $E^*$ against the realized ever-patched share at three decommissioning horizons. Attacker
scenarios appear as reference levels.

- Raising the ever-patched share from 26% to 75% cuts $E^*$ **66%**, to 669.
- Shortening the decommissioning horizon from 5.5 to 3 years cuts it **45%**.
- Cutting reachable surface 30% cuts it **16%**.
- Halving patch delay, from 43 to 21 days, cuts it 0.3%.

Against these, 10× discovery adds 68% and 3× throughput adds 58%. All three attacker shocks together (10×
discovery, 3× weaponization, 3× throughput) add 403%.

This figure also shows the model's largest sensitivity. At the measured 26%, moving the decommissioning
horizon across 3–10 years spans 1,092 to about 3,600, a factor of about three. At 50% ever patched, the
target is 1,338 rather than 1,981. The dashed curves show the count five years out. At high completeness they
sit above the equilibrium, because improving completeness cannot retire a backlog already present. The
horizontal axis ends at 98%, the most the model can realize.

![Visualization 4 — equilibrium exploited count against the ever-patched share at three decommissioning horizons, and a ranked comparison of levers and shocks](figure:viz-4)

### Visualization 5 — the patch-delay / attack-surface plane

**Of the two levers a program controls most directly, patch delay barely moves the outcome. Reachable
surface moves it substantially.** The figure contours $E^*$ over patch delay (0–180 days) and a multiplier on
the measured reachable share (0.05–1.0). The contours are nearly horizontal. Across the full range of $\tau$
the outcome changes by about 2%, because $\tau$ acts only on the remediable compartment. Reachable surface
spans **0.11× to 1.01×** of the target. That is a larger movement than tripling throughput produces (1.58×),
because cutting supply is not damped by saturation the way raising it is (§1). With no change, the count five
years from today is 0.68× the target (0.81× for SharePoint).

![Visualization 5 — equilibrium exploited count over patch delay and reachable surface](figure:viz-5)

### Visualization 6 — discovery volume against attacker throughput

**Neither discovery volume nor throughput moves the target in proportion. Which moves it more turns on an
assumed ratio.** The figure contours $E^*$ over a discovery multiplier and a throughput multiplier. A 10×
increase in discovery moves $E^*$ **+68%**. Tripling throughput moves it **+58%**, and both together move it
**4.4×**. These figures are the assumed $P/C$ at work (§1), not independent findings. At a ratio of 0.5 the
first two are +126% and +34%; at 2 they are +35% and +90%. The data therefore do not settle whether discovery
or throughput is the larger lever. What holds across the range is that discovery raises exploitation far
less than proportionally.

One vendor-level observation is consistent with that. Microsoft's July 2026 release shipped 621 CVEs, 6.6×
its 2025 monthly average [25], with 3 under active exploit. ZDI [7] counted 2 on release day, and Microsoft
flagged a third the next day [26].

The right panel pairs each scenario's eventual target with its value five years from today: 1,339 with no
change, 2,186 under 10× discovery and 1,847 under 3× throughput. No scenario delivers more than 60% of its
eventual movement within a planning horizon.

CVE counts measure one axis. Throughput has no published index. It is visibly moving: machine-generated
exploits land within an hour of a patch [9, 12, 13], and exploit reproduction costs a few dollars per CVE
[10]. The caveat is that these are reproductions, not production chains [11].

![Visualization 6 — equilibrium exploited count over discovery and throughput multipliers, and the five-year value of each scenario](figure:viz-6)

### Visualization 7 — is finite vulnerability supply the binding constraint?

**Finite vulnerability supply does not bind.** Depletion requires the cumulative discovery curve to
decelerate. Instead, annual counts have risen in every year from 2017 to 2026. Saturating fits cannot recover
the reservoir. Both forms now run $U$ to the fit's 10-billion upper bound, where the reported uncertainty
collapses to zero. That is the signature of a parameter the data do not constrain. Until the 2026-09-20
snapshot, the logistic form still returned an interior value, 5.5 million ± 128%. That value was dominated by
the 2017 CNA-expansion step, a bookkeeping change rather than a property of code. 2026's acceleration has
removed even that.

SharePoint shows the failure directly. Fits through 2022, 2023 and 2024 give asymptotes of **13,720 / 1,828 /
958**. They track the recent slope, not a stock. Those fits read the 2022–24 trough as exhaustion. 2026 then
annualizes to **202**, the product's highest year.

The conclusion is falsifiable: **per-product discovery must bend where code is not churning**. Mature
enterprise products are where that would appear first. It has not appeared. The fits are unweighted least
squares, with $U$ bounded below by the observed count. The covariance understates uncertainty, because the
residuals are strongly autocorrelated.

![Visualization 7 — annual and cumulative discovery with two saturating fits, and SharePoint's fitted asymptote at three cutoff years](figure:viz-7)

### Visualization 8 — four futures for discovery, one of them mechanistic

**The choice of discovery future barely propagates.** The figure runs four trajectories for $\gamma$:

- an exogenous fade;
- a permanent step to the measured 1.76× (most recent quarter against trailing year);
- compounding at that same figure, read as +76% a year and capped at 10×;
- a 10× efficiency jump against a finite reservoir.

The cap and the compounding rate are arbitrary. The measured 2021–2026 growth rate is 39% a year, so the
compounding case is an upper bound. The reservoir case uses $U_0$ = 1.0 million remaining. That is a lower
bound, since the reservoir is unidentified (Visualization 7). $\psi$ is pinned so that $\psi U_0$ equals
today's discovery rate, and replenishment is set equal to it. The surge then decays on a timescale of
$U_0/(10\gamma)$, about eleven months, without any assumption about behavior.

Starting from today's 727, every path rises over 25 years, to between 1,964 and 3,272. The slow compartments
are still filling, whatever discovery does. Three of the four end within **23%** of one another. Only
sustained compounding separates.

![Visualization 8 — four discovery trajectories and the exploited count each produces](figure:viz-8)

### Visualization 9 — where the system is, against where it is heading

**The system has two clocks.** The figure drives each stock along the measured 2008–2026 publication
history, continues it at today's rate, and compares it with its equilibrium target.

The fast pools have overshot their targets, at **153–169%** globally and **246–247%** for SharePoint. A stock
whose residence time is weeks tracks a rising inflow, here October's record month. Its target is computed at
the trailing-year rate, which the current quarter exceeds.

The slow pools are far short. The known backlog is at **34%** of target and needs **9 more years** to reach
90% of it. The residual exploited compartment is at **36%** and needs **13**. SharePoint's backlog is at 63%
and its residual at 64%.

Most of the movement still to come was committed by publications that happened years ago. That is why
exploitation counts cannot evaluate a recent control. Global publication history is the monthly series, with
each month's rate held constant within it. SharePoint's is interpolated linearly between annual rates. Both
are seeded in 2008 from the equilibrium that year's rate implies.

![Visualization 9 — each stock driven by measured history and continued at today's rate, against its target](figure:viz-9)

### Visualization 10 — five interventions at equal effort

**Effect and speed rank in nearly opposite orders.** Five controls each get the same 30% relative improvement
in one parameter, starting from today's history-driven state. The figure plots eventual effect against the
time to reach 90% of it. "Equal effort" is a normalization, not a cost model.

| Control (30% improvement) | Eventual change in $E^*$ | After 5 years | Time to 90% |
|---|---|---|---|
| decommissioning rate $\lambda$ | −22.9% | −13.2% | 18.8 yr |
| reachable surface $\varepsilon$ | −16.1% | −14.1% | 12.7 yr |
| ever-patched share | −10.5% | −8.1% | 14.7 yr |
| retirement rate $\phi$ | −7.0% | −2.1% | 22.6 yr |
| patch delay $\tau$ | −0.2% | −0.2% | 3.6 yr |

Patch delay acts on the remediable compartment directly. It is fast and weak. The other four act through
multi-year stocks. They are slow and, retirement excepted, strong. For SharePoint, retirement does not reach
90% of its effect within the 30 years integrated; the figure places it at that edge.

![Visualization 10 — five controls at equal relative effort, effect against time to take effect](figure:viz-10)

## Limitations

1. **Mean-field.** The model has one hazard per pool, but exploitation is concentrated. The 3.5% of
   vulnerabilities scoring 0.36 or more on the exploit-prediction score [14] hold 68% of observed exploitation
   [24]. Edge devices and VPNs were the target in 22% of breaches involving vulnerability exploitation, up
   from 3% the year before [22]. Stratifying is the extension most likely to change the results (Future
   work §1).
2. **$E$ counts vulnerabilities, not compromised systems.** CitrixBleed 2 (CVE-2025-5777) drew more than 11.5
   million attack attempts against thousands of sites within weeks of disclosure [23]. The model counts it
   once. A rise in breadth per vulnerability is invisible (Future work §3).
3. **$C$ is calibrated, not measured, and $P/C$ is assumed.** $C$ absorbs every unmodeled mechanism,
   including defender interdiction. $P/C$ fixes every attacker-side sensitivity (Future work §4). The
   catalog's growth places $P/C$ near 0.5 to 1 only if the per-vulnerability hazards are constant. A
   weaponization rate rising with automation would fit the same growth at higher saturation. The model cannot
   tell the two apart.
4. **The 26% ever-patched figure is one survey median.** It carries more of the result than any other
   measured value. At 50%, $E^*$ is 1,338 rather than 1,981; at 75%, 669.
5. **$\rho$ and $\delta$ are assumed without measurement.** They matter little at 26% completeness and a
   great deal at high completeness (Visualization 3).
6. **No defender adaptation.** $f$, $\tau$ and $C$ are constants. Coordinated disclosure programs, such as
   the Akrites letter [15], are attempts to move $f$ and $\delta_d$. The model cannot represent their effect
   (Future work §4).
7. **Non-stationarity.** 2026 is running at 315.0 CVEs a day, against 2025's 136.9. Equilibrium statements
   therefore describe a moving target, and the absolute figures here have a shelf life of months (see the
   [backlog check](https://jo5iah.github.io/vulnapocalypse-data/#3-backlog-size)). Today's state is
   calibrated along the measured monthly history and does not depend on the trailing-year rate. The target
   does. $C$ is tied to today's supply, which the newest pools carry at the latest month's rate.

## Future work

The first four items are ordered by dependency. The first two complete the present layer. The third builds a
layer above it, and the fourth a layer above that. Each later layer consumes the one beneath it. The fifth
depends on none of them. It replaces the lagging catalog measurements every layer reads, so doing it first
improves the inputs the other four consume. `plan.md` keeps the same structure.

### 1. Stratify by type, severity, product and exposure

Every hazard in the model is a single population average. Exploitation is not distributed that way.
`product_ranks.py` already measures a composition the present model cannot represent: the Linux kernel is
second in CVE volume and 25th in the exploitation catalog, while Windows Server leads exploitation and is
fourth by volume.

The change is to split each pool into classes with class-specific $\beta$ and $\varepsilon$, and, where the
data support it, class-specific $f$ and $\lambda$. Four axes are available in records the acquisition
notebook already pulls:

- **type** (CWE);
- **severity** (CVSS base score, and EPSS [14] where available);
- **product** (CPE `vendor:product`, rolled up to families);
- **exposure** (CVSS attack vector and privileges required: internet-facing and pre-authentication;
  network-reachable but authenticated; local or adjacent).

Severity and exposure are correlated through the CVSS vector, so they are not independent dimensions. Start
with exposure, add type, and treat severity as a check until the correlation is measured. CPE applicability
is missing from about half of recent records, which censors the latest months hardest. The test this admits
is one the present model cannot attempt. A class-stratified calibration should reproduce the *composition*
of the KEV catalog (which classes and vendors dominate it) without being fitted to that composition.

### 2. Tighten the decommissioning rate

$1/\lambda$ = 5.5 years rests on open-source vulnerability age. The corrected anchor
([data page](https://jo5iah.github.io/vulnapocalypse-data/#how-independent-the-checks-are)) excludes horizons
of a decade or more, but is consistent with anything from 3 to 8 years. $\lambda$ sets the residence time of
the compartment that holds 99% of the exploited population. It is therefore the most load-bearing number in
the model, which is why Visualization 4 sweeps it.

**Fit it to how long KEV-listed vulnerabilities remain observable in internet-exposure scans.** That measures
removal from service directly, instead of inferring it from the age of flaws still present. The input is
per-CVE scan telemetry tracked over years. The test is whether the fitted horizon lands inside the 3-to-8-year
window, and whether SharePoint's shorter horizon survives against its own scan history. The same work bears
on the discrepancy the anchor leaves. The stock runs 13% above the anchor, and a better $\lambda$ would either
remove that gap or confirm it.

### 3. A layer above: exploited systems

The present layer counts vulnerabilities. Harm accrues to systems, and the two are not proportional. One
vulnerability drew more than 11.5 million attack attempts [23], and this model scores it as 1.

The remedy is a second layer that consumes this one's output rather than modifying it. For each vulnerability
in the exploited compartments, it would carry a susceptible installed base $S_i$ and a compromised count
$Q_i$. $\dot Q_i$ would be driven by scan-and-exploit contact against $S_i$, and drained by instance-level
remediation. This is an epidemic layer whose *number of simultaneous epidemics* is supplied by the layer
below. Aggregate harm becomes a weighted sum over $Q_i$, not a count of vulnerabilities. It is parameterized
by exposure counts per product, scanning telemetry and incident counts. Two SharePoint cases are the worked
examples to read before specifying it: an authentication bypass [18], and a flaw exploited shortly after its
proof of concept was published [19].

It matters for the conclusions already drawn. Automation plausibly increases the breadth of exploitation per
vulnerability without changing the number exploited. That is a large movement in harm, and the present layer
registers it as none.

### 4. A layer above that: the economics of attack and defense

Both layers below take effort as given. $C$, the parameter that dominates the response to automation, is
calibrated rather than explained. The defender-side parameters $f$, $\tau$, $\rho$ and $\lambda$ are
constants. Neither side can adapt. A third layer would make them decisions.

On the attack side, throughput becomes a choice: spend on exploit production against expected return per
compromised system. Both terms are now roughly measurable. Reported per-exploit production costs run from a
few dollars for reproducing a known vulnerability [10] to about $2,000 for a chained privilege escalation [9].
Expected return follows from the second layer's compromise counts. On the defense side, completeness, patch
speed, surface and retirement each carry a cost curve. The equilibrium sits where marginal cost equals
marginal harm avoided, the framing of the security economics literature [16, 17].

Only this layer can answer three questions. Does rising throughput reflect falling production cost or rising
expected return? Does optimal attacker throughput scale with a hundredfold fall in exploit cost, or saturate
against target selection and monetization? Does a defender's best response shift from speed toward
completeness as attacker costs fall? It would also settle a question the current model cannot pose: is the
historical stability of exploitation rates a coincidence, or an equilibrium between two adapting parties?

### 5. Independent of all four: an exploitation signal ahead of the catalog

Every exploitation quantity in this document is a catalog entry, and catalogs lag events. The median
disclosure → KEV lag is 216 days (p90 2,577). VulnCheck lists exploitation before KEV in 67.6% of the CVEs
the two share, by a median of 3 days and a mean of 28 [21]. NVD keeps adding records to publication windows
that have already closed
([data page](https://jo5iah.github.io/vulnapocalypse-data/#biases-in-the-source-data)). Vendors, responders
and the press announce zero-days first, often before a CVE is published.

Vendor records move too. Microsoft published the SharePoint flaw CVE-2026-58644 on 2026-07-14 without its
exploited flag. It corrected the flag the next day, and CISA listed the flaw on 2026-07-16. July's exploited
count was therefore 2 on release day and 3 a day later. The fix had shipped in June, with the CVE left out of
that release [26]. For a month, the fix existed with no public record of the flaw it fixed.

The remedy is to read that earlier record directly. The sources are:

- structured vendor exploitation flags, such as the `Exploited` field of the Microsoft Security Update Guide
  [26] and the `exploit_status` threat category of CSAF 2.0 advisories [27];
- the fixed phrasings of browser, mobile and edge-device advisories ("may have been exploited", "aware that
  an exploit … exists in the wild");
- curated trackers, such as Project Zero's list of zero-days exploited in the wild [28];
- the trade press, which supplies first timestamps but not counts, since it over-samples prominent vendors.

Each claim reduces to a first public timestamp per vulnerability and a coded strength of claim. Beside it
goes the vendor's own patch statement: fix available, workaround only, no fix planned, or end of life.

Four measurements follow. Each replaces something the present layer assumes or brackets.

1. **The lag from first claim to CVE publication to KEV addition.** It replaces the onset bracket in the
   anchor test.
2. **Publications per exploitation claim, beside publications per KEV addition.** This separates the
   readings of the widening gap that remain once the backlog's lag is removed. If the advisory ratio widens
   as KEV's does, attackers are saturating or the catalog is keeping pace. If claims rise with disclosure
   while catalog additions do not, the catalog is falling behind, and every exploitation figure here is low
   by a growing margin. Dated per vulnerability, the same claims also show whether the share of newly
   published flaws that is exploited is rising. A rising weaponization rate predicts that; saturation does
   not.
3. **Claims for the current month, scaled by the measured claim-to-catalog ratio.** These estimate the
   influx $I$ before the catalog catches up.
4. **The share of exploited vulnerabilities whose vendor states no fix or end of life.** This is a direct
   lower bound on $1 - f$, which today rests on one survey median.

A fifth measurement extends the population rather than the timing. Vendors also fix security flaws without
issuing a CVE. Matching shipped fixes (release notes, changelogs, upstream commits) against the CVEs that
cite them measures attack surface absent from every rate here, $\gamma$ included.

The test is that advisory-derived onsets reproduce KEV's addition dates, shifted by a lag consistent with
VulnCheck's published median and mean, without being fitted to them. Vendor exploitation language is itself
policy, as KEV additions are. Each vendor's flag rate is therefore tracked over time, and a change of
phrasing is treated as a change of instrument.

## Appendix: the slow-manifold reduction

The uniqueness and stability of the equilibrium follow from the structure (§1). These two figures show the
geometry behind it and check the timescale separation numerically. No result above depends on them.

### Visualization 11 — phase portrait

$H$, $N$ and $E_p$ relax in 45, 30 and 41 days, against 1,820 days for $X$ and 2,000 for $E_r$. The slow
dynamics therefore reduce to the $(X, E_r)$ plane, with the fast states held at their equilibrium values.
The $\dot X = 0$ nullcline is **vertical**, because nothing in $\dot X$ depends on $E_r$. The backlog's
balance involves only $N$, $X$ and the conversion share, and conversion depends on the pools, not on the
exploited stock. The $\dot E_r = 0$ nullcline rises with $X$ and **flattens** as realized exploitation
saturates at $C$. They cross once, and the crossing is stable. The measured history, drawn from 2008, is
still travelling toward it: today the backlog is at 34% of target and the residual at 36%. The reduction's
error is bounded by the timescale ratio: at least 45:1 between $E_p$ and $E_r$, and wider for $H$ and $N$.

![Visualization 11 — the slow plane with nullclines, flow field and the measured path from 2008](figure:viz-11)

### Visualization 12 — the fast manifold in 3-D

The figure shows trajectories of the full global system in $(N, X, E_r)$. $H$ and $E_p$ start at their
equilibrium values, so the collapse of $N$ is isolated. Every orbit reaches the $\dot N = 0$ surface,
$N = \delta_d H^* / (\mu + \mathrm{conv}\,\beta_n)$, within weeks, then travels along it for decades. The
surface depends on $X$ only through $\mathrm{conv}$, and $\mathrm{conv}\,\beta_n$ is about a thousandth of
$\mu$. The surface is therefore flat to within that margin, and is drawn as a plane.

Along the measured history, $N$ departs from this relation by −34% to +23%. The monthly publication series
steps at each month boundary, and $N$ follows $H$ with a 30-day lag. $N$ returns within weeks of each step,
while $X$ and $E_r$ remain at 34% and 36% of target. Being on the nullcline means $N$ tracks $H$. It does not
mean the system has arrived anywhere. The notebook also writes the rotating view to
`ODEtoVuln_daily_phase3d.mp4`; the still below is one viewpoint.

![Visualization 12 — full-system trajectories collapsing onto the N-nullcline, one viewpoint of the rotating view](figure:viz-12)

## References

Numbers in brackets in the text refer to this list. The [data page](https://jo5iah.github.io/vulnapocalypse-data/)
uses the same numbers, and some sources are cited only there. Links were last checked on 2026-10-14.

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
