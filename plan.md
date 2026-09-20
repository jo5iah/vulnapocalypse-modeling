# Plan

Four steps. Step 1 is built; steps 2 to 4 are layers above it, each consuming the one below rather
than modifying it. The ordering is by dependency, not by appeal: step 4 needs the harm denominator
step 3 produces, and step 3 is far more useful once step 2 has split the population it counts.

`ODEtoVuln_daily.md` carries its own **Future work** section covering steps 2 to 4 in more technical
detail. That section and this file must be kept in step; where they disagree, this file is the plan
and that section is the specification.

---

## Step 1 — the vulnerability-count layer · **done**

A five-stock continuous-time model of how vulnerabilities move from discovery to exploitation to
removal, parameterized from public data for the global ecosystem and for Microsoft SharePoint, with
twelve visualizations establishing each result.

What it answers: what sets the standing count of exploited, unremediated vulnerabilities, and which
control moves it. Headline results at the 2026-09-20 snapshot — completeness of remediation beats
speed of patching by an order of magnitude; discovery volume is nearly inert because conversion is
capacity-limited; the measured state sits at 57% of the level today's inflow already implies.

Delivered alongside the model:

| Artifact | What it is |
|---|---|
| `ODEtoVuln_daily.{md,ipynb,html}` | the document, its figures, and the self-contained build |
| `VulnData.ipynb` | sole acquisition path; writes every model input |
| `anchor_gap.py` | the KEV anchor correction, reproduced in full |
| `product_ranks.py` → `product_ranks_<snapshot>.md` | per-product exploited-vs-vulnerable rankings |
| `build_html.py` | rebuilds the HTML from document, notebook and `vendor/` |

**What step 1 cannot express, which is what motivates the rest.** Every hazard is a population
average, so the model cannot say that the same discovery concentrated differently produces different
exploitation — step 2. It counts vulnerabilities and not compromised systems, so a flaw exploited
across a million hosts scores the same as one exploited once — step 3. Both attacker throughput and
every defender parameter are constants, so neither side can adapt — step 4.

**Open items that are not steps.** These run alongside and block nothing:

- **$1/\lambda$ has no tight constraint.** The corrected anchor excludes a decade-plus horizon but is
  consistent with anything from 3 to 8 years, and $\lambda$ sets the residence time of the compartment
  holding ~40× what the remediable one does. Fit it to how long KEV-listed CVEs stay observable in
  internet-exposure scans. This is Future work §2 in the document.
- **KEV measures cataloguing, not attacker behavior.** Its additions swung 555 / 187 / 186 across
  2022–2024 on policy alone, so the widening gap between disclosure and catalogued exploitation
  supports two readings that point opposite ways. Nothing public separates them.
- **$\gamma$ is not stationary.** Publication acceleration has been positive for 67 months and the
  recent quarter runs 1.7× the trailing year, so any equilibrium computed from a trailing-year rate
  has a shelf life of months. Re-snapshot before quoting absolute levels.

---

## Step 2 — stratify: vulnerability type, severity, product, exposure

**Ready to start. No new data source required.**

Split each pool from one population average into classes, with class-specific hazards $\beta$,
reachability $\varepsilon$, and where the data supports it class-specific completeness $f$ and
decommissioning $\lambda$. Four axes, all already present in records the acquisition notebook pulls:

| Axis | Source field | Why it should matter |
|---|---|---|
| **Type** | CWE | memory-safety, injection and auth-bypass classes are weaponized at very different rates and by different actors |
| **Severity** | CVSS base score, and EPSS where available | severity is the field every program already triages on, and the model currently says nothing about whether that is the right sort |
| **Product** | CPE `vendor:product`, rolled to families | exploitation concentrates in a handful of families that are *not* the volume leaders |
| **Exposure** | CVSS attack vector and privileges required | internet-facing pre-auth versus local/adjacent is the split most likely to dominate the others |

**The motivating evidence already exists.** `product_ranks.py` measures a composition mismatch the
present model cannot represent: the Linux kernel leads CVE volume at 3,413 and sits **25th** in the
exploitation catalog, while Windows Server leads exploitation and is only **fourth** by volume;
Firefox is 10th by volume and 47th by exploitation. A single population average cannot produce that,
and today the model simply does not try.

**The test that justifies the work.** A class-stratified calibration should reproduce the *composition*
of the KEV catalog — which classes and which vendors dominate it — without being fitted to that
composition. Step 1 has no test of this kind available to it; this is the first structural claim the
model could falsify rather than absorb.

**Watch for.** Severity and exposure are strongly correlated through the CVSS vector, so they are not
four independent axes and should not be modeled as if they were; start with exposure, add type, and
treat severity as a check rather than a dimension until the correlation is measured. CPE applicability
is missing from ~51% of records in the trailing year, censoring recent months hardest.

---

## Step 3 — model exploit-affected systems

**Depends on step 2 for per-class structure; needs data step 1 does not collect.**

The present layer counts vulnerabilities; harm accrues to systems, and the two are not proportional.
One vulnerability drew 11.5M+ attack attempts and this model scores it as 1.

A second layer consumes step 1's output rather than modifying it. For each vulnerability in the
exploited compartments, carry a susceptible installed base $S_i$ and a compromised count $Q_i$, with
$\dot Q_i$ driven by scan-and-exploit contact against $S_i$ and drained by instance-level remediation
— an epidemic layer whose *number of simultaneous epidemics* is supplied by the layer below. Aggregate
harm becomes a weighted sum over $Q_i$ rather than a count of vulnerabilities.

Inputs: exposure counts per product, scanning telemetry, incident counts. Two SharePoint cases are
recorded in the session notes as the worked examples to read before specifying this layer.

**Why it changes conclusions.** Automation plausibly raises the breadth of exploitation per
vulnerability without raising the number of vulnerabilities exploited — a large movement in harm that
step 1 registers as no movement at all. It also supplies the denominator step 4 needs.

---

## Step 4 — the economics of attack versus defense

**Depends on step 3 for expected return per compromise.**

Steps 1 to 3 take effort as given. Throughput $C$ — the parameter that dominates the response to
automation — is calibrated rather than explained, and the defender parameters $f$, $\tau$, $\rho$ and
$\lambda$ are constants. This layer makes them decisions.

On the attack side throughput becomes a choice: spend on exploit production against expected return
per compromised system. Both terms are now roughly measurable — production cost has been reported from
a few dollars for reproducing a known flaw to a few thousand for a chained privilege escalation, and
expected return follows from step 3's compromise counts. On the defense side, completeness, patch speed
and retirement each carry a cost curve, and the equilibrium sits where marginal cost equals marginal
harm avoided.

Questions only this layer can answer: whether rising throughput reflects falling production cost or
rising expected return; whether optimal attacker throughput scales with a hundredfold fall in exploit
cost or saturates against target selection and monetization; whether a defender's best response shifts
from speed toward completeness as attacker costs fall. And one the current model cannot even pose —
whether the historical stability of exploitation rates is coincidence or an equilibrium between two
adapting parties.
