# Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model

A continuous-time model of how vulnerabilities move from discovery to exploitation to removal, parameterized
from public vulnerability data and evaluated for two populations: the **global software ecosystem** and
**Microsoft SharePoint** as an instance of enterprise server software. Time is in days throughout. Data
acquisition is in `VulnData.ipynb`; figures and their derivations are in `ODEtoVuln_daily.ipynb`. Snapshot:
**2026-08-14**.

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

## Contents of this repository

| File | Description |
|---|---|
| `index.html` | The complete document rendered as a single self-contained page — text, all twelve figures and the animation are inlined as base64 data URIs, so it makes no network requests and can be opened from disk or served as a GitHub Page. 7.8 MB. |
| `ODEtoVuln_daily.md` | The model document: the system of equations with each stock and flow described, the data and how every parameter is obtained, the results with the figure establishing each, limitations, and future work. This is the source of the text in `index.html`. |
| `ODEtoVuln_daily.ipynb` | The model itself and the twelve visualizations. Parses the document above, implements the five-stock system, drives it with measured publication history, and emits every figure. Each figure's section closes with a justification of the parameters it uses. Runs end to end in about 30 seconds. |
| `ODEtoVuln_daily_phase3d.mp4` | Full-quality version of the rotating three-dimensional phase portrait (Visualization 12): 360 frames, one per degree of azimuth, 30 fps. A smaller re-encode is embedded in `index.html`. |
| `VulnData.ipynb` | Data acquisition. Queries NVD for the CVE corpus, publication rates and the 2008-to-present history, CISA KEV for observed exploitation, and MITRE for disclosure timestamps; derives the parameter sets for both populations. Writes the three files the model notebook reads. Responses are cached, and the snapshot date is the single control at the top. |
| `build_html.py` | Assembles the self-contained page from the document, the notebook's figures and `vendor/`. `python build_html.py ODEtoVuln_daily index` regenerates `index.html`. |
| `product_ranks.py` | Top products by CVE count and by observed exploitation, both derived from NVD's CPE applicability data so the two rankings share one taxonomy, with a documented rollup that recovers product families from per-release CPE names. The exploited side reads the cached KEV mirror; the vulnerable side sweeps every CVE in a publication window and aggregates page by page rather than caching ~500 MB of responses. Writes `data/product_ranks_<snapshot>.json`. |
| `anchor_gap.py` | Diagnostics behind the exploited-stock anchor in §2 of the document: the decomposition of the discrepancy the naive anchor produced, how much of the corrected anchor lies inside the window that calibrates throughput, the KEV onset history against the model's realized conversion, and how weakly the anchor constrains the decommissioning rate. Imports the model by executing the notebook's first cell rather than restating it, so it cannot drift from the figures. |
| `data/` | Cached API responses and the three derived inputs: `derived_params.json` (parameters), `global_history.json` (per-year publication rates), `sharepoint_union.json` (the de-duplicated CVE set for the SharePoint CPE family). Included so the work reproduces without re-querying the sources; delete a file to refetch it. |
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
