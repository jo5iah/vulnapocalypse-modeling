# Plan

Four steps and one parallel track. Step 1 is built; the input tables for steps 2 and 3 were started on
2026-11-16 (status under each); steps 2 to 4 are layers above step 1, each consuming
the one below rather than modifying it. The ordering is by dependency, not by appeal: step 4 needs the
harm denominator step 3 produces, and step 3 is far more useful once step 2 has split the population it
counts. Track A replaces the lagging catalog measurements that every step reads and depends on none of
them, so it can be done before any of them; doing it first improves the inputs steps 2 to 4 consume.

`ODEtoVuln_daily.md` carries its own **Future work** section covering steps 2 to 4 (its §1, §3, §4), the
first open item below (§2) and track A (§5) in more technical detail. That section and this file must be kept in step; where they disagree, this file is the plan
and that section is the specification.

---

## Step 1 — the vulnerability-count layer · **done**

A five-stock continuous-time model of how vulnerabilities move from discovery to exploitation to
removal, parameterized from public data for the global ecosystem and for Microsoft SharePoint, with
twelve visualizations establishing each result.

What it answers: what sets the standing count of exploited, unremediated vulnerabilities, and which
control moves it. Headline results at the 2026-11-16 snapshot — completeness of remediation beats
speed of patching by more than an order of magnitude, and reducing reachable surface does too; discovery
volume raises exploitation far less than proportionally, though by how much turns on the assumed
supply/throughput ratio; the measured state, 727, sits at 37% of the level today's inflow already implies.

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
  holding 99% of the exploited population. Fit it to how long KEV-listed CVEs stay observable in
  internet-exposure scans. This is Future work §2 in the document.
- **KEV measures cataloging, not attacker behavior.** Its additions swung 555 / 187 / 186 across
  2022–2024 on policy alone. Most of the widening gap between disclosure and cataloged exploitation is
  the backlog lagging the publication surge; what remains supports readings that point different ways
  (saturation, rising weaponization, a lagging catalog). No catalog separates them; track A is the
  measurement designed to.
- **$\gamma$ is not stationary.** Publication acceleration was positive from 2018-12 for 69 months (the
  one-month dip at the filter's edge is not a turning point) and the recent quarter runs 1.76× the
  trailing year, so any equilibrium computed from a trailing-year rate has a shelf life of months.
  Re-snapshot before quoting absolute levels.
- **$P/C$ is assumed, and the attacker-side findings rest on it.** Set to 1 at 2026-11-16 (it was 2):
  with the model driven by the monthly publication series, KEV's compounded 2023–2026 growth (+81%) and
  the widening of publications per exploit (×1.66) sit at 1 (+82%, ×1.72) and between 0.5 and 1, while 2
  gives +59% and ×1.85. Results that depend on it are reported over 0.5–2: 10× discovery from +126% to
  +35%, 3× throughput from +34% to +90%. Constant hazards are assumed; a weaponization rate rising with
  automation fits the same growth at higher saturation. Track A's per-vulnerability claim dates are what
  would separate them. `anchor_gap.py` reproduces the comparison.
- **Calibration changed at 2026-11-16; the anchor drift it fixed.** Earlier editions calibrated the
  hazards and $C$ to an equilibrium at the trailing-year $\gamma$. The history-driven system is about a
  third of that equilibrium, so a surge in $\gamma$ lowered the conversion assigned to every past year,
  and today's state fell from 1.12× the KEV anchor (08-14) to 0.89×, below its bracket. The model now
  calibrates along the measured monthly history to KEV additions from 2023 (2022's build-out excluded;
  including it raises the level 37%) and sits at 1.13×, inside. The target is now the drifting quantity:
  $C$ follows today's supply, which the newest pools carry at the latest month's rate.

---

## Track A — an exploitation signal ahead of the catalog · independent; can be done first

**No dependency on steps 2 to 4; feeds all of them and step 1's calibration.** It needs only what
`VulnData.ipynb` already caches (the CVE records and the KEV catalog) as join keys. Its coverage
measurement can run by vendor and product family now, and by exposure class from the CVSS attack vector
already in those records, without waiting for step 2's model.

Every exploitation quantity the model reads is a catalog entry, and catalogs lag events. The median
disclosure → KEV lag is 216 days (p90 2,577); VulnCheck lists exploitation before KEV in 67.6% of the
CVEs the two share, by a median of 3 days and a mean of 28; NVD keeps ingesting records into closed
publication windows, and ~54% of the trailing year still lacks CPE applicability. Zero-days are
announced first by vendors, responders and the press, often before a CVE is published at all. The
present model therefore measures exploitation as it stood weeks to months ago, filtered by cataloging
policy.

**Sources, by how structured the exploitation claim is.**

| Tier | Source | Exploitation field or language |
|---|---|---|
| Structured vendor | Microsoft MSRC CVRF/CSAF API; CSAF 2.0 provider feeds (Cisco, Siemens, Red Hat and others) | MSRC "Exploited: Yes" and exploitability index; CSAF `threats[].category = exploit_status` |
| Semi-structured vendor | Apple security releases, Chrome Releases, Android and Pixel bulletins, Mozilla advisories, PSIRTs for edge devices (Fortinet, Ivanti, Citrix, Palo Alto, Cisco ASA) | fixed phrasings: "may have been exploited", "aware that an exploit … exists in the wild", "limited, targeted exploitation" |
| Curated trackers | Project Zero *0day In the Wild*; VulnCheck KEV; national CSIRT advisories | first-seen dates and exploitation references per CVE |
| Unstructured | trade press, vendor threat-intelligence blogs, researcher posts | free text, extracted to (CVE or pre-CVE identifier, product, claim, hedging level, first timestamp) |

Each claim is reduced to a first public timestamp per vulnerability, deduplicated across re-reporting,
and coded on an ordinal scale from "exploitation detected" through "limited, targeted" and "may have
been" to "PoC public" and "exploitation more likely". The same records carry the vendor's patch
statement: fix available, workaround or mitigation only, no fix planned, or end of life.

**What it measures.**

- **The onset distribution the anchor currently brackets.** The KEV anchor brackets unobserved onset
  between NVD publication and CISA's `dateAdded`. First public claim → CVE publication → NVD analysis →
  KEV addition, per CVE, replaces the bracket with a measured lag.
- **The divergence test.** Publications per exploitation claim, monthly, beside publications per KEV
  addition (204 for 2025 → 339 for 2026 → 414 over the last ninety days, which narrowed from 439 a
  month earlier as KEV additions accelerated). Most of KEV's widening is the backlog lagging the surge
  (the model gives ×1.49 with almost no saturation). If the advisory-derived ratio widens as KEV's does,
  attackers are saturating or the catalog is keeping pace; if advisory claims rise with disclosure while KEV
  additions do not, the catalog is falling behind and every exploitation figure is low by a growing margin.
  A rising share of newly published flaws claimed exploited would point to rising weaponization instead.
  This is the measurement the second open item says no catalog provides.
- *A first reading of the onset lag, as a by-product of the step-3 impact ledger (2026-11-16):* for 75 KEV entries added in
  2026 with a dated public exploitation claim from a source other than CISA, KEV followed by a median
  of 2 days and a mean of 24; 64% within 3 days, 89% within 28. Small, and not independent across
  chained CVEs, but close to VulnCheck's 3 and 28.
- **Catalog coverage by class.** The share of claimed-exploited vulnerabilities that never reach KEV, by
  vendor, product family and exposure class — a less policy-filtered composition target for step 2.
- **A nowcast of the influx $I$.** Claims for the current month, scaled by the measured claim → KEV
  ratio, estimate this month's influx before the catalog catches up; vendor advisory volume does the same
  for $\gamma$ ahead of NVD.
- **Completeness and decommissioning at the source.** The share of exploited vulnerabilities whose vendor
  states no fix or end of life is a direct lower bound on the residual share $1 - f$, which today rests on
  one survey median; "workaround only" bears on $\delta$, which today is assumed.
- **Silent patching.** Vendors fix security flaws without issuing a CVE or advisory. Matching shipped
  security fixes (release notes, changelogs, upstream commits, patch diffs) against the CVEs and
  advisories that cite them measures the share of fixed vulnerabilities that never enter the record —
  attack surface that every rate in this model, including $\gamma$, omits.

**The test that justifies the work.** Advisory-derived onsets should reproduce KEV's addition dates
shifted by a lag distribution consistent with VulnCheck's published 3-day median and 28-day mean, without
being fitted to them. If they do, the advisory stream is a calibrated leading indicator; if they do not,
the disagreement localizes which source is lagging.

**Watch for.** Vendor exploitation language is policy, exactly as KEV additions are: track each vendor's
flag rate over time and treat a change in phrasing as a change in instrument. Press coverage over-samples
high-profile vendors, so unstructured sources set first timestamps and never counts. Claims are retracted
and re-attributed; keep the claim history, not only the latest state. Pre-CVE announcements need a join
key that survives CVE assignment. Backfilling history needs archived copies of advisory pages, and
scraped sources carry terms-of-use constraints that structured feeds do not.

---

## Step 2 — stratify: vulnerability type, severity, product, exposure

**Input table built 2026-11-16; the model work is ready to start.**

`cve_strata.py` keeps one row per CVE (`data/cve_strata.csv.gz`: vendor, product families, CVSS exposure
fields, severity, CWE, CISA's SSVC decision points, KEV date) and refreshes incrementally with
`update`; `report` writes `cve_stratification_<date>.md`. What the first table says, for the 365 days
to 2026-11-16 (321 KEV additions against 107,720 publications, 3.0 per 1,000):

| Split | KEV additions per 1,000 published |
|---|---|
| Remote, no privileges, no user action / other remote / local | 5.6 / 1.8 / 2.4 |
| Microsoft / Google / Linux | 7.4 / 2.4 / 0.9 |
| Cisco / Fortinet / Ivanti / Citrix | 54 / 43 / 123 / 133 |
| Critical / High / Medium | 13.0 / 3.2 / 0.9 |

A single population rate puts 27% of KEV additions in the wrong exposure class, 39% in the wrong vendor
class and 45% in the wrong vendor × exposure cell. **That misallocation is the baseline the test below
has to beat.** The top 20 vendors by exploitation hold 56% of additions, so the design is top-N vendors
plus a rest bucket, crossed with three exposure classes; product-level top-N is too long-tailed (the top
50 products hold 54%).

Remaining work, in order: (1) reconcile assigner-supplied vendor names to CPE names, since rates for
vendors split across two spellings are overstated; (2) calibrate class-specific $\beta$ and
$\varepsilon$ on one period and predict KEV composition on another; (3) decide whether SSVC's `poc`
flag (19.6% of publications) should condition the hazard on fresh disclosures.

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
present model cannot represent: the Linux kernel is second in CVE volume at 3,338 and sits **25th** in the
exploitation catalog, while Windows Server leads exploitation and is only **fourth** by volume;
Firefox is 10th by volume and 49th by exploitation. A single population average cannot produce that,
and today the model simply does not try.

**The test that justifies the work.** A class-stratified calibration should reproduce the *composition*
of the KEV catalog — which classes and which vendors dominate it — without being fitted to that
composition. Step 1 has no test of this kind available to it; this is the first structural claim the
model could falsify rather than absorb.

**Watch for.** Severity and exposure are strongly correlated through the CVSS vector, so they are not
four independent axes and should not be modeled as if they were; start with exposure, add type, and
treat severity as a check rather than a dimension until the correlation is measured. CPE applicability
is missing from 57% of records in the trailing year, censoring recent months hardest; the assigner's
`affected` block supplies a vendor for most of those (92% of records have one or the other), at the cost
of a second, unreconciled naming scheme.

---

## Step 3 — model exploit-affected systems

**Depends on step 2 for per-class structure; needs data step 1 does not collect.**

The present layer counts vulnerabilities; harm accrues to systems, and the two are not proportional.
CitrixBleed 2 drew more than 11.5M attack attempts (Imperva) and this model scores it as 1.

A second layer consumes step 1's output rather than modifying it. For each vulnerability in the
exploited compartments, carry a susceptible installed base $S_i$ and a compromised count $Q_i$, with
$\dot Q_i$ driven by scan-and-exploit contact against $S_i$ and drained by instance-level remediation
— an epidemic layer whose *number of simultaneous epidemics* is supplied by the layer below. Aggregate
harm becomes a weighted sum over $Q_i$ rather than a count of vulnerabilities.

Inputs: exposure counts per product, scanning telemetry, incident counts. Two SharePoint cases are
recorded in the session notes as the worked examples to read before specifying this layer.

**Impact ledger, started 2026-11-16.** The inputs are being collected by walking KEV backwards by date
added and searching reputable sources, per entry, for exposed instances, compromised hosts, victim
organizations, attack volume and downtime (`impact_ledger.py`, `impact_ledger_<date>.md`; the research
brief and batches are under `_review/2026-11-16/impact/`). 96 of 2026's 297 entries are researched; 201
are stashed, blocked on a per-session web-search limit, not on method.

What the first 96 say about which inputs exist:

- **$S_i$ is often measurable, $Q_i$ rarely.** An exposure count exists for 22 campaigns (median
  13,850, from 300 to 34.4 million). A compromise count exists for 8 (median 14, maximum 471) and a
  victim-organization count for 6. Each is one observer's floor.
- **Downtime is not reported.** No entry has an outage duration; harm will have to be weighted by
  compromise breadth, not by time lost, unless older entries or regulatory filings supply it.
- **The unit is the campaign.** Chained CVEs share one figure, so $Q$ belongs to a campaign that maps
  onto several vulnerabilities in the layer below.
- **Breadth is heavy-tailed.** One campaign holds 57% of all counted compromises and one holds 90% of
  counted victim organizations, so aggregate harm will be set by a few campaigns.

Remaining work: finish 2026 (whether yield rises with entry age cannot be read yet: January to August
has 39 of about 200 entries); spot-check quotes against sources, since pages were read through a
summarizing tool; then extend to 2025.

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
