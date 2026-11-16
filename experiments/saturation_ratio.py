"""Experiment: what if weaponizable supply ran at 1, 3, 5 or 10 times attacker capacity instead of 2?

SATURATION = P/C is assumed in the notebook ("the one free structural ratio"). Under the equilibrium
calibration it does not move the level, which is pinned to KEV x T, but it sets every attacker-side
sensitivity. Under the transient-matched calibration it also moves the level, because P = SATURATION x C
is imposed on today's history-driven state.

Measured evidence that bears on the ratio, all of it noisy:
  * the divergence: publications per KEV addition went 204 (2025) -> 339 (2026 to date), x1.66; a more
    saturated model converts a publication surge into less exploitation, so it widens the ratio more;
  * the KEV anchor and the onset history by window (anchor_gap.py's test);
  * the last 91 days: model conversion against KEV additions, fitted by neither calibration.
KEV additions are cataloging policy (555 / 187 / 186 for 2022-2024), so none of these is sharp.

    python experiments/saturation_ratio.py [--drive annual|monthly]   # repository root, 2026-11-16
"""
import contextlib
import datetime as dt
import io
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import window_matched_hazards as W  # noqa: E402
from transient_matched_hazards import (G, calibrate_transient, integral, kev_added,  # noqa: E402
                                       path_influx)

SNAP = "2026-11-16"
RATIOS = [1.0, 2.0, 3.0, 5.0, 10.0]
START = dt.date(2023, 1, 1)


def run_ratio(r, drive="annual"):
    return W.run(SNAP, "trailing", drive=drive, saturation=r)


def install(ns, e):
    ns["GLOBAL"] = e
    ns["ECOS"] = [e, ns["SHAREPOINT"]]
    ns["TRANSIENT"][e.label] = ns["drive_history"](e)


def year_mean(d, x, y0, y1):
    m = (d["year"] >= y0) & (d["year"] < y1)
    return float(np.mean(x[m]))


def metrics(ns, e, added):
    snap = ns["SNAPSHOT_DATE"]
    d, P, I = path_influx(ns, e)
    gam = np.array([ns["history_gamma"](e)(t) for t in d["t"]])
    fp, st = e.fixed_point(), ns["TRANSIENT"][e.label]["state"]
    lo, hi = ns["ANCHOR_BRACKET"][G]
    a = ns["ANCHOR"][G]
    q0 = snap - dt.timedelta(days=91)
    lev = W.levers(ns, e)
    # growth of the model's conversion, 2025 to 2026 to date, against KEV's measured growth. The model's
    # gamma(t) interpolates annual rates linearly, so its "2025" already carries half of 2026's surge;
    # the comparison is of the response, and the drive is smoother than the data on both sides.
    i_growth = year_mean(d, I, 2026, 2027) / year_mean(d, I, 2025, 2026) - 1
    g_growth = year_mean(d, gam, 2026, 2027) / year_mean(d, gam, 2025, 2026) - 1
    ages = ns["onset_ages"](ns["KEV_IDS"][G], "mid")
    by_year = {}
    for x in ages:
        y = (snap - dt.timedelta(days=int(x))).year
        by_year[y] = by_year.get(y, 0) + 1
    shape = []
    for wlo, whi in ((2008, 2015), (2016, 2020), (2021, 2023), (2024, 2026)):
        obs = sum(v for y, v in by_year.items() if wlo <= y <= whi)
        days = (min(dt.date(whi, 12, 31), snap) - dt.date(wlo, 1, 1)).days
        shape.append(obs / days / year_mean(d, I, wlo, whi + 1))
    return dict(today=st["E"], target=fp["E"], ratio=st["E"] / a, inside=lo <= st["E"] <= hi,
                pc_now=P[-1] / e.C, pc_eq=fp["supply"] / e.C, i_growth=i_growth, g_growth=g_growth,
                q=integral(ns, d, I, q0, snap), lev=lev, shape=shape)


def main(drive="annual"):
    added = kev_added(SNAP)
    snap_d = dt.date.fromisoformat(SNAP)
    q_kev = sum(1 for v in added.values() if snap_d - dt.timedelta(days=91) < v <= snap_d)
    k25 = sum(1 for v in added.values() if v.year == 2025)
    k26 = sum(1 for v in added.values() if v.year == 2026)
    hist = W.inputs_for(SNAP)[1]
    g25 = hist["2025"]["total"] / hist["2025"]["days"]
    g26 = hist["2026"]["total"] / hist["2026"]["days"]
    meas = (g26 / (k26 / hist["2026"]["days"])) / (g25 / (k25 / 365))
    adds = sum(1 for v in added.values() if START <= v <= snap_d)

    rows = []
    for r in RATIOS:
        ns = run_ratio(r, drive)
        rows.append((r, "equilibrium (main)", metrics(ns, ns["GLOBAL"], added)))
        e = calibrate_transient(ns, ns["GLOBAL"], START, adds)
        install(ns, e)
        rows.append((r, "transient 2023+", metrics(ns, e, added)))

    a = run_ratio(2.0, drive)["ANCHOR_BRACKET"][G]
    print(f"snapshot {SNAP}; anchor bracket {a[0]:.0f}-{a[1]:.0f}; measured publications per KEV "
          f"addition {g25 / (k25 / 365):.0f} (2025) -> {g26 / (k26 / hist['2026']['days']):.0f} "
          f"(2026), x{meas:.2f}; KEV additions per day {k25 / 365:.3f} -> "
          f"{k26 / hist['2026']['days']:.3f} ({k26 / hist['2026']['days'] / (k25 / 365) - 1:+.0%}); "
          f"KEV additions in the last 91 days {q_kev}")
    print(f"model drive ({drive}): publication rate 2025 -> 2026 {rows[0][2]['g_growth']:+.0%} "
          f"(measured {g26 / g25 - 1:+.0%})")
    print(f"\n{'P/C':>5} {'calibration':<20}{'today':>7}{'target':>8}{'/anchor':>9}{'in':>5}"
          f"{'P/C tgt':>9}{'I 25->26':>10}{'91-day':>8}   "
          f"{'10x disc':>9}{'3x thr':>8}{'surf-30':>8}{'patch+30':>9}   onsets/model by window")
    for r, name, m in rows:
        L = m["lev"]
        print(f"{r:>5.0f} {name:<20}{m['today']:>7.0f}{m['target']:>8,.0f}{m['ratio']:>9.2f}"
              f"{'yes' if m['inside'] else 'no':>5}{m['pc_eq']:>9.2f}{m['i_growth']:>+9.0%} {m['q']:>8.0f}   "
              f"{L['10x discovery']:>+8.0f}%{L['3x throughput']:>+7.0f}%{L['surface -30%']:>+7.1f}%"
              f"{L['ever-patched +30%']:>+8.1f}%   " + " ".join(f"{s:.2f}" for s in m["shape"]))


if __name__ == "__main__":
    main(sys.argv[sys.argv.index("--drive") + 1] if "--drive" in sys.argv else "annual")
