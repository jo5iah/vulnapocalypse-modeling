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
low by a growing margin. Until exploitation telemetry separates them, read the exploitation numbers as a floor.
Beyond that, the absolute counts are orders of magnitude rather than estimates: tested against the catalog on a
consistent footing, the model runs 4% low (§2), and calibrating to 2025's KEV rate alone (0.671/day) rather
than the pooled 2022-onward rate (0.819/day) would lower the level by 18%, since the level scales in proportion
to the calibrated influx. The rankings survive both. Finally, the model counts vulnerabilities rather than
compromised systems, so one flaw exploited on a million hosts counts the same as one exploited once. That
understates the scenario cheaper automated exploitation makes most likely. Stratifying by exposure class and
adding a layer of compromised systems are the extensions most likely to change these conclusions (Future work).

## Contents of this repository

| File | Description |
|---|---|
| `index.html` | The complete document rendered as a single self-contained page — text and all fourteen figures are inlined as base64 data URIs, so it makes no network requests and can be opened from disk or served as a GitHub Page. |
| `ODEtoVuln_daily.md` | The model document: the system of equations with each stock and flow described, the data and how every parameter is obtained, the results with the figure establishing each, limitations, future work, and an appendix on the slow-manifold reduction. This is the only source of text in `index.html`; every figure is placed in it at a `figure:<name>` marker. |
| `ODEtoVuln_daily.ipynb` | The model itself and the twelve visualizations. Implements the five-stock system, drives it with measured publication history, and emits every figure. Its markdown cells only name each figure; the discussion and parameter provenance live in the document, so there is one written source for every number. Runs end to end in under a minute. |
| `ODEtoVuln_daily_phase3d.mp4` | Full-quality version of the rotating three-dimensional phase portrait (Visualization 12): 360 frames, one per degree of azimuth, 30 fps. Not embedded in `index.html`, which carries one still viewpoint. |
| `VulnData.ipynb` | Data acquisition. Queries NVD for the CVE corpus, publication rates and the 2008-to-present history, CISA KEV for observed exploitation, and MITRE for disclosure timestamps; derives the parameter sets for both populations. Writes the three files the model notebook reads. Responses are cached, and the snapshot date is the single control at the top. |
| `build_html.py` | Assembles the self-contained page from the document, the notebook's figures and `vendor/`. `python build_html.py ODEtoVuln_daily index` regenerates `index.html`. |
| `product_ranks.py` | Top products by CVE count and by observed exploitation, both derived from NVD's CPE applicability data so the two rankings share one taxonomy, with a documented rollup that recovers product families from per-release CPE names. The exploited side reads the cached KEV mirror; the vulnerable side sweeps every CVE in a publication window and aggregates page by page rather than caching ~500 MB of responses. Writes `data/product_ranks_<snapshot>.json` and a standalone report, `product_ranks_<snapshot>.md`; `--report-only` rebuilds the report from the saved JSON without repeating the sweep. |
| `anchor_gap.py` | Diagnostics behind the exploited-stock anchor in §2 of the document: the decomposition of the discrepancy the naive anchor produced, how much of the corrected anchor lies inside the window that calibrates throughput, the KEV onset history against the model's realized conversion, and how weakly the anchor constrains the decommissioning rate. Imports the model by executing the notebook's first cell rather than restating it, so it cannot drift from the figures. |
| `data/` | Cached API responses and the three derived inputs: `derived_params.json` (parameters), `global_history.json` (per-year publication rates), `sharepoint_union.json` (the de-duplicated CVE set for the SharePoint CPE family). Included so the work reproduces without re-querying the sources; delete a file to refetch it. |
| `plan.md` | The four-step roadmap. Step 1 — the vulnerability-count layer in this repository — is built; steps 2 to 4 stratify the population, model exploit-affected systems, and close with the economics of attack versus defense. |
| `product_ranks_<snapshot>.md` | Standalone rankings report: top exploited and top vulnerable product families in one taxonomy, and where each volume leader sits in the exploitation catalog. |
| `vendor/` | Build inputs only, not needed to read anything: KaTeX with its web fonts and markdown-it. |
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

`ffmpeg` is required by the notebook cell that renders the animation. The `aysu` environment provides it, but
only on `PATH` once the environment is activated. Without it that cell fails, the other eleven figures are
unaffected, and `build_html.py` stops because the same cell produces the still of Visualization 12.
