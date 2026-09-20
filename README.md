# Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model

A continuous-time model of how vulnerabilities move from discovery to exploitation to removal, parameterized
from public vulnerability data and evaluated for two populations: the **global software ecosystem** and
**Microsoft SharePoint** as an instance of enterprise server software. Time is in days throughout. Data
acquisition is in `VulnData.ipynb`; figures and their derivations are in `ODEtoVuln_daily.ipynb`. Snapshot:
**2026-09-20**.

## Executive summary

Security programs are measured on how fast they patch. This model asks what actually sets the number of
vulnerabilities under active exploitation at any moment, from rates measured in public data — NVD, the CISA KEV
catalog, and published incident telemetry — for the whole software ecosystem and for Microsoft SharePoint as
a stand-in for enterprise server software. Four findings bear on where a program should spend.

- **Completing remediation beats accelerating it.** Only about a quarter of exploited vulnerabilities are ever
  fully patched; the rest stay exploitable until the software is retired. Cutting patch delay by 30% changes the
  standing count by **0.4%**. Getting 30% more remediations to completion changes it by **10.5%**, and retiring
  old software 30% faster by **22.6%**. Speed is the metric most programs optimize and the one that matters
  least.
- **More disclosed vulnerabilities will not mean proportionally more exploitation.** Attackers already pass over
  roughly two of every three vulnerabilities they could weaponize: the binding constraint is their capacity to
  build and deploy exploits, not the supply of targets. A tenfold rise in disclosure volume would raise
  exploitation by **under half**, while tripling attacker capacity would **nearly double** it. That divergence
  is now measured rather than modeled: across 2025–2026 disclosure rose **95%** a year while additions to the
  exploitation catalog rose **31%**, so the vulnerabilities published per cataloged exploit went from 204 to
  **303**, and to **385** over the last ninety days. Nor will the flow taper on its own: no population examined
  here shows discovery slowing, including a product two decades old, whose 2026 is its heaviest year on record.
  Rising CVE counts are a poor alarm; attacker productivity is the thing to watch, and no public index of it
  exists.
- **The vulnerabilities you count are not the ones being exploited.** Over the past year the Linux kernel led
  CVE volume with 3,413 and sits **25th** in the exploitation catalog; Windows Server leads exploitation and is
  only **fourth** by volume. One product family appears in the top three of both lists. Prioritizing by counts,
  or by any single estate-wide average of risk, points at the wrong software.
- **Nothing you change will show up in these numbers for years.** The populations that drive exploitation turn
  over on a five-year clock and sit at roughly **57%** of the level today's disclosure rate already implies.
  Exploitation keeps climbing for years even if disclosure stops accelerating tomorrow — so next quarter's
  exploited count cannot evaluate a control introduced last quarter, and a rise in it is not evidence that a
  program is failing. Nor is the level they are climbing toward fixed. The standing count is, to within a
  tenth of a percent, the cataloged exploitation rate multiplied by a 1,480-day residence time, so a catalog
  rate rising 31% a year lifts the destination in step — from 1,206 to roughly **1,580** on a further year at
  that rate. Exploitation is growing; it is growing far more slowly than the vulnerability counts that get
  reported, and that gap is the whole of the good news.

The practical implication is to move effort from response time toward finishing remediations and retiring
unsupported software, and to expect neither to register quickly.

Two cautions on how far to push the numbers. The absolute counts are the least settled part of the result: the
standard sanity check on them — KEV's size discounted by the 26% ever-patched share — is arithmetically invalid,
and putting it on a consistent footing leaves the model 10% above the catalog rather than in agreement (§2).
The level also moved 20% on nothing more than a choice about how to average KEV additions since 2022. The
rankings above survive both; the absolute figures are orders of magnitude, not estimates. Separately, the model
counts vulnerabilities and not compromised systems, so one flaw exploited across a million hosts counts the same
as one exploited once — which understates precisely the scenario that cheaper automated exploitation makes more
likely. Exposure-weighted outcomes and stratification by exposure are the two extensions most likely to change
these conclusions, and the concentration in the third finding is already measurable, so the second no longer
waits on new data. Both are set out in the closing section on future work.

One ambiguity sits underneath the exploitation figures and cannot be settled from public data. KEV records what
CISA catalogs, not what attackers do; its annual additions ran 555, 187 and 186 across 2022 to 2024 on
cataloging policy rather than on anything in the world. The widening gap between disclosure and cataloged
exploitation is therefore consistent with two readings that point opposite ways: attackers saturating, which is
what this model assumes and what makes rising CVE counts tolerable, or the catalog falling behind, in which
case every exploitation figure here is low by a margin that is itself growing. Telling them apart needs
exploitation telemetry no public source provides, and until it exists the exploitation numbers should be read
as a floor that is rising at least as fast as stated.

## Contents of this repository

| File | Description |
|---|---|
| `index.html` | The complete document rendered as a single self-contained page — text, all twelve figures, the two inline document figures and the animation are inlined as base64 data URIs, so it makes no network requests and can be opened from disk or served as a GitHub Page. 8.9 MB. |
| `ODEtoVuln_daily.md` | The model document: the system of equations with each stock and flow described, the data and how every parameter is obtained, the results with the figure establishing each, limitations, and future work. This is the source of the text in `index.html`. |
| `ODEtoVuln_daily.ipynb` | The model itself and the twelve visualizations. Parses the document above, implements the five-stock system, drives it with measured publication history, and emits every figure. Each figure's section closes with a justification of the parameters it uses. Runs end to end in about 30 seconds. |
| `ODEtoVuln_daily_phase3d.mp4` | Full-quality version of the rotating three-dimensional phase portrait (Visualization 12): 360 frames, one per degree of azimuth, 30 fps. A smaller re-encode is embedded in `index.html`. |
| `VulnData.ipynb` | Data acquisition. Queries NVD for the CVE corpus, publication rates and the 2008-to-present history, CISA KEV for observed exploitation, and MITRE for disclosure timestamps; derives the parameter sets for both populations. Writes the three files the model notebook reads. Responses are cached, and the snapshot date is the single control at the top. |
| `build_html.py` | Assembles the self-contained page from the document, the notebook's figures and `vendor/`. `python build_html.py ODEtoVuln_daily index` regenerates `index.html`. |
| `product_ranks.py` | Top products by CVE count and by observed exploitation, both derived from NVD's CPE applicability data so the two rankings share one taxonomy, with a documented rollup that recovers product families from per-release CPE names. The exploited side reads the cached KEV mirror; the vulnerable side sweeps every CVE in a publication window and aggregates page by page rather than caching ~500 MB of responses. Writes `data/product_ranks_<snapshot>.json` and a standalone report, `product_ranks_<snapshot>.md`; `--report-only` rebuilds the report from the saved JSON without repeating the sweep. |
| `anchor_gap.py` | Diagnostics behind the exploited-stock anchor in §2 of the document: the decomposition of the discrepancy the naive anchor produced, how much of the corrected anchor lies inside the window that calibrates throughput, the KEV onset history against the model's realized conversion, and how weakly the anchor constrains the decommissioning rate. Imports the model by executing the notebook's first cell rather than restating it, so it cannot drift from the figures. |
| `data/` | Cached API responses and the three derived inputs: `derived_params.json` (parameters), `global_history.json` (per-year publication rates), `sharepoint_union.json` (the de-duplicated CVE set for the SharePoint CPE family). Included so the work reproduces without re-querying the sources; delete a file to refetch it. |
| `plan.md` | The four-step roadmap. Step 1 — the vulnerability-count layer in this repository — is built; steps 2 to 4 stratify the population, model exploit-affected systems, and close with the economics of attack versus defense. |
| `product_ranks_<snapshot>.md` | Standalone rankings report: top exploited and top vulnerable product families in one taxonomy, and where each volume leader sits in the exploitation catalog. |
| `vendor/` | Build inputs only, not needed to read anything: KaTeX with its web fonts, markdown-it, and the web-encoded animation. |
| `environment.yml` | Conda environment for running the notebooks. `conda env create -f environment.yml`, then register the kernel. |
| `environment.lock.yml` | Fully pinned export of the same environment, for byte-identical reproduction on linux-64. |

## Reproducing

```bash
conda env create -f environment.yml
conda activate aysu
python -m ipykernel install --user --name aysu --display-name "Python (aysu)"

jupyter lab VulnData.ipynb          # refresh the data; bump AS_OF for a new snapshot
jupyter lab ODEtoVuln_daily.ipynb   # run the model and regenerate every figure
python build_html.py ODEtoVuln_daily index   # rebuild index.html
```

`ffmpeg` is required by the notebook cell that renders the animation; without it that cell fails and the other
eleven figures are unaffected.
