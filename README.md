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
reachable surface and retiring unsupported software. Expect none of them to register quickly. Section 2 of
the document states how far to trust these numbers.

## Contents of this repository

| File | Description |
|---|---|
| `index.html` | The complete document rendered as a single self-contained page — text and all thirteen of its figures are inlined as base64 data URIs, so it makes no network requests and can be opened from disk or served as a GitHub Page. |
| `ODEtoVuln_daily.md` | The model document: the system of equations with each stock and flow described, the data and how every parameter is obtained, how far to trust the numbers, the results with the figure establishing each, limitations, future work, and an appendix on the slow-manifold reduction. This is the only source of text in `index.html`; every figure is placed in it at a `figure:<name>` marker. |
| `ODEtoVuln_daily.ipynb` | The model itself and the twelve visualizations. Implements the five-stock system, drives it with measured publication history, and emits every figure, with the stock-and-flow diagram as Visualization 1. Its markdown cells only name each figure; the discussion and parameter provenance live in the document, so there is one written source for every number. Runs end to end in under a minute. |
| `ODEtoVuln_daily_phase3d.mp4` | Full-quality version of the rotating three-dimensional phase portrait (Visualization 12): 360 frames, one per degree of azimuth, 30 fps. Not embedded in `index.html`, which carries one still viewpoint. |
| `VulnData.md` | The data page, published at [jo5iah.github.io/vulnapocalypse-data](https://jo5iah.github.io/vulnapocalypse-data/): sources, measured quantities, every parameter and how it is obtained, biases in the source data, the shape of the inflow, and the checks against the catalog and the corpus. `python build_html.py VulnData` renders it to `VulnData.html`, which is published as that site's `index.html`. |
| `VulnData.ipynb` | Data acquisition. Queries NVD for the CVE corpus, publication rates and the 2008-to-present history, CISA KEV for observed exploitation, and MITRE for disclosure timestamps; derives the parameter sets for both populations. Writes the three files the model notebook reads, and draws the inflow figure on the data page. Responses are cached, and the snapshot date is the single control at the top. |
| `build_html.py` | Assembles the self-contained page from the document, the notebook's figures and `vendor/`. `python build_html.py ODEtoVuln_daily index` regenerates `index.html`. |
| `product_ranks.py` | Top products by CVE count and by observed exploitation, both derived from NVD's CPE applicability data so the two rankings share one taxonomy, with a documented rollup that recovers product families from per-release CPE names. The exploited side reads the cached KEV mirror; the vulnerable side sweeps every CVE in a publication window and aggregates page by page rather than caching ~500 MB of responses. Writes `data/product_ranks_<snapshot>.json` and a standalone report, `product_ranks_<snapshot>.md`; `--report-only` rebuilds the report from the saved JSON without repeating the sweep. |
| `anchor_gap.py` | Diagnostics behind the exploited-stock anchor checks on the data page: the decomposition of the discrepancy the naive anchor produced, how much of the corrected anchor lies inside the window that calibrates throughput, the KEV onset history against the model's realized conversion, and how weakly the anchor constrains the decommissioning rate, plus the two calibration choices the document reports: which KEV window sets the level, and where the catalog's growth places the assumed supply/throughput ratio. Imports the model by executing the notebook's first cell rather than restating it, so it cannot drift from the figures. |
| `data/` | Cached API responses and the three derived inputs: `derived_params.json` (parameters), `global_history.json` (per-year publication rates), `sharepoint_union.json` (the de-duplicated CVE set for the SharePoint CPE family). Included so the work reproduces without re-querying the sources; delete a file to refetch it. |
| `plan.md` | The four-step roadmap and one independent track. Step 1 — the vulnerability-count layer in this repository — is built; steps 2 to 4 stratify the population, model exploit-affected systems, and close with the economics of attack versus defense. Track A measures exploitation from vendor zero-day announcements ahead of the catalog, and silent patching, and can be done before any of the steps. |
| `product_ranks_<snapshot>.md` | Standalone rankings report: top exploited and top vulnerable product families in one taxonomy, and where each volume leader sits in the exploitation catalog. |
| `cve_strata.py` | Per-CVE stratification table (`data/cve_strata.csv.gz`): vendor, product families, CVSS exposure fields, severity, CWE, CISA's SSVC decision points and KEV date for every CVE of the trailing year. `build` sweeps NVD, `update` refetches only records modified since the last sync, `report` rebuilds the tables offline. |
| `cve_stratification_<snapshot>.md` | KEV additions per 1,000 CVEs published, by exposure class, vendor, vendor × exposure, weakness type, severity and SSVC value, and the share of KEV additions a single population rate misallocates. Input to plan step 2. |
| `impact_ledger.py` | Assembles the exploitation-impact ledger from the research results under `impact/`: published counts of exposed instances, compromised hosts, victim organizations, attack volume and downtime per KEV entry. |
| `impact_ledger_<snapshot>.md` | The ledger so far: yield by evidence type and month, lag from first public exploitation claim to KEV listing, and per-campaign figures. Partial (96 of 2026's 297 KEV additions); input to plan step 3. |
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
python build_html.py VulnData                # rebuild the data page, VulnData.html
```

`ffmpeg` is required by the notebook cell that renders the animation. The `aysu` environment provides it, but
only on `PATH` once the environment is activated. Without it that cell fails, the other eleven figures are
unaffected, and `build_html.py` stops because the same cell produces the still of Visualization 12.
