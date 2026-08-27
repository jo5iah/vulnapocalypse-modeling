"""Diagnostics behind the exploited-stock anchor correction in ODEtoVuln_daily.md §2.

The anchor `1665 x (1 - 0.26) = 1,232` applies the completed limit for patching and the zero
limit for decommissioning at the same instant. The document replaces it with the same catalogue
run through the exit kernel the model integrates,

    implied(T) = SUM_i [ f e^{-(pr+lam) a_i} + (1-f) e^{-lam a_i} ],   a_i = T - onset_i

which puts both sides on one clock. That kernel and the onset proxies live in cell 1 of the
notebook, beside the model, and this script imports them rather than restating them. What it
adds is the reporting the document cites and the figure has no room for: the decomposition of
the original factor of two, how much of the corrected anchor sits inside the window that
calibrates C, the onset history against the model's own realized conversion, and how weakly the
anchor constrains lam.

    python3 anchor_gap.py
"""

import datetime as dt
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path

os.environ.setdefault("MPLBACKEND", "Agg")

import numpy as np

ROOT = Path(__file__).resolve().parent
KEV_LAUNCH = dt.date(2021, 11, 3)


def load_model():
    """Cell 1 of the notebook, exec'd verbatim: the model and the anchors, one source of truth."""
    nb = json.loads((ROOT / "ODEtoVuln_daily.ipynb").read_text())
    src = "\n".join(l for l in "".join(nb["cells"][1]["source"]).splitlines()
                    if not l.startswith("%config"))
    ns, cwd = {"__name__": "_model"}, Path.cwd()
    os.chdir(ROOT)                        # cell 1 reads data/ by relative path
    try:
        with redirect_stdout(io.StringIO()):
            exec(compile(src, "ODEtoVuln_daily.ipynb#cell1", "exec"), ns)
    finally:
        os.chdir(cwd)
    return ns


M = load_model()
GLOBAL, SHAREPOINT, ECOS = M["GLOBAL"], M["SHAREPOINT"], M["ECOS"]
TRANSIENT, MEAS, DPY = M["TRANSIENT"], M["MEAS"], M["DAYS_PER_YEAR"]
ANCHOR, ANCHOR_NAIVE, ANCHOR_BRACKET = M["ANCHOR"], M["ANCHOR_NAIVE"], M["ANCHOR_BRACKET"]
onset_ages, kernel_anchor, KEV_IDS = M["onset_ages"], M["kernel_anchor"], M["KEV_IDS"]
SNAPSHOT = M["SNAPSHOT_DATE"]

LAM, PR, F = GLOBAL.lam, GLOBAL.patch_rate, GLOBAL.f_fix
NAIVE = ANCHOR_NAIVE[GLOBAL.label]
KERNEL = ANCHOR[GLOBAL.label]
TODAY = TRANSIENT[GLOBAL.label]["state"]["E"]
TARGET = GLOBAL.fixed_point()["E"]
IDS = KEV_IDS[GLOBAL.label]


def catalogue_age():
    print("age of the catalogue, in days before the snapshot")
    for proxy in ("added", "published"):
        a = onset_ages(IDS, proxy)
        print(f"  onset = {proxy:<10} median {np.median(a):>7,.0f}   mean {a.mean():>7,.0f}   "
              f"max {a.max():>7,.0f}   share older than 1/lam: {(a > 1 / LAM).mean():>6.1%}")
    print(f"  KEV opened {KEV_LAUNCH}, {(SNAPSHOT - KEV_LAUNCH).days:,} days before the snapshot; "
          f"entries in its first 90 days: "
          f"{sum(1 for c in IDS if M['KEV_ADDED'][c] <= KEV_LAUNCH + dt.timedelta(days=90)):,}\n")


def anchors():
    print(f"{'anchor definition':<50}{'implied':>9}{'vs today':>10}{'vs naive':>10}")
    rows = [("naive: N x (1 - ever-patched), no decommissioning", NAIVE)]
    rows += [(f"kernel: onset = {p}", kernel_anchor(GLOBAL, IDS, p))
             for p in ("added", "mid", "published")]
    rows += [("model, transient state today", TODAY), ("model, equilibrium at today's gamma", TARGET)]
    for name, v in rows:
        print(f"{name:<50}{v:>9,.0f}{v / TODAY:>10.2f}{v / NAIVE:>10.2f}")
    lo, hi = ANCHOR_BRACKET[GLOBAL.label]
    print(f"\n  corrected anchor {KERNEL:,.0f} [{lo:,.0f}, {hi:,.0f}]; today {TODAY:,.0f} is "
          f"{'inside' if lo <= TODAY <= hi else 'OUTSIDE'} the bracket\n")

    gap = NAIVE - TODAY
    print("decomposition of the original factor of two")
    print(f"  naive anchor                                {NAIVE:>8,.0f}")
    print(f"  removed by applying the model's exit kernel  {NAIVE - KERNEL:>8,.0f}"
          f"   ({(NAIVE - KERNEL) / gap:>5.0%} of the gap)")
    print(f"  kernel-consistent anchor                    {KERNEL:>8,.0f}")
    print(f"  residual against the model                  {KERNEL - TODAY:>8,.0f}"
          f"   ({(KERNEL - TODAY) / gap:>5.0%} of the gap)")
    print(f"  model transient                             {TODAY:>8,.0f}\n")

    for e in ECOS[1:]:
        lo, hi = ANCHOR_BRACKET[e.label]
        tr, eq = TRANSIENT[e.label]["state"]["E"], e.fixed_point()["E"]
        n = len(KEV_IDS[e.label])
        print(f"{e.label}: {n} KEV entries, kernel anchor {ANCHOR[e.label]:,.1f} "
              f"[{lo:,.1f}, {hi:,.1f}] against today {tr:,.1f} (ratio {tr / ANCHOR[e.label]:.2f}) "
              f"and target {eq:,.1f} ({eq / ANCHOR[e.label]:.2f});\n  one Poisson standard error at "
              f"n = {n} is {1 / np.sqrt(n):.0%}. The naive anchor was {ANCHOR_NAIVE[e.label]:,.1f}, "
              f"whose apparent agreement with the target\n  came of two offsetting errors.\n")


def independence():
    """C is calibrated from the recent KEV rate, so the two sides share their current-era level."""
    a = onset_ages(IDS, "mid")
    pre = np.array([(SNAPSHOT - dt.timedelta(days=int(x))) < KEV_LAUNCH for x in a])
    k_pre, k_post = kernel(a[pre]), kernel(a[~pre])
    print("how much of the corrected anchor lies outside the calibration window")
    print(f"  onsets before KEV launched: {pre.sum():>5,} entries contributing "
          f"{k_pre:>6,.0f} of {KERNEL:,.0f} ({k_pre / KERNEL:.0%})")
    print(f"  onsets after:               {(~pre).sum():>5,} entries contributing "
          f"{k_post:>6,.0f} of {KERNEL:,.0f} ({k_post / KERNEL:.0%})\n")


def kernel(ages):
    return float(np.sum(F * np.exp(-(PR + LAM) * ages) + (1 - F) * np.exp(-LAM * ages)))


def influx():
    """The shape of the onset history is what the anchor tests independently, not the level."""
    d = TRANSIENT[GLOBAL.label]
    b_h, b_n, b_x = GLOBAL.hazards
    tr, yr = d["traj"], d["year"]
    P = b_h * tr["H"] + b_n * tr["N"] + b_x * tr["X"]
    I = GLOBAL.C * P / (GLOBAL.C + P)
    by_year = {}
    for x in onset_ages(IDS, "mid"):
        y = (SNAPSHOT - dt.timedelta(days=int(x))).year
        by_year[y] = by_year.get(y, 0) + 1
    print("onset history against the model's realized conversion I(t)")
    print(f"  {'window':<12}{'observed onsets/day':>21}{'model I(t)/day':>16}{'ratio':>8}")
    for lo, hi in ((2008, 2015), (2016, 2020), (2021, 2023), (2024, 2026)):
        obs = sum(v for y, v in by_year.items() if lo <= y <= hi)
        days = (min(dt.date(hi, 12, 31), SNAPSHOT) - dt.date(lo, 1, 1)).days
        m = float(np.mean(I[(yr >= lo) & (yr < hi + 1)]))
        print(f"  {f'{lo}-{hi}':<12}{obs / days:>21.3f}{m:>16.3f}{obs / days / m:>8.2f}")
    print(f"  onsets before 2008, excluded above: "
          f"{sum(v for y, v in by_year.items() if y < 2008)}")
    print(f"  C is calibrated to a realized rate of {GLOBAL.realized:.3f}/day\n")


def constrains_lam():
    """lam enters both sides, so check the agreement is not an identity."""
    replace, drive = M["replace"], M["drive_history"]
    print("how tightly does the corrected anchor constrain 1/lam?")
    print(f"  {'1/lam (yr)':<12}{'kernel anchor':>15}{'transient E':>13}{'ratio':>8}"
          f"{'equilibrium':>13}")
    for yrs in (3.0, 1 / LAM / DPY, 8.0, 12.0, 20.0):
        eco = replace(GLOBAL, lam=1.0 / (yrs * DPY)).calibrate()
        k = kernel_anchor(eco, IDS, "mid")
        t = drive(eco)["state"]["E"]
        note = "   <- measured" if abs(yrs - 1 / LAM / DPY) < 1e-9 else ""
        print(f"  {yrs:<12.2f}{k:>15,.0f}{t:>13,.0f}{k / t:>8.2f}"
              f"{eco.fixed_point()['E']:>13,.0f}{note}")
    print("  the ratio is flat from 3 to 8 years and degrades past 12, so the anchor excludes a")
    print("  decade-plus horizon but cannot pick a value inside the 3-to-8 window.")


if __name__ == "__main__":
    print(f"KEV entries {len(IDS):,}   f = {F:.5f}   1/(pr+lam) = {1 / (PR + LAM):.1f} d   "
          f"1/lam = {1 / LAM:,.0f} d = {1 / LAM / DPY:.2f} yr\n")
    catalogue_age()
    anchors()
    independence()
    influx()
    constrains_lam()
