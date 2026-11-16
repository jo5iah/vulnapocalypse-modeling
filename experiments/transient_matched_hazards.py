"""Experiment: calibrate the hazards and C along the measured history, not at an equilibrium.

Every calibration tried so far (trailing, pooled, quarter in window_matched_hazards.py) sets the KEV
rate equal to the conversion an EQUILIBRIUM would produce, while the history-driven system sits at about
half its equilibrium. This one imposes both calibration conditions on the transient itself:

  (i)  P = SATURATION x C today, on the history-driven state (the stated meaning of P/C = 2);
  (ii) the model's realized conversion, integrated along the measured history over a window, equals the
       KEV additions in that window.

Unknowns are one scale on all three hazards (the split between H, N and X is kept) and C. The pools
barely feel the hazards (conv x beta_x is under 1% of phi), so the fixed-point iteration below converges
in a few steps.

The data are noisy, and in a known way: KEV additions are cataloging policy (555, 187, 186 a year for
2022-2024), the onset of each entry is bracketed rather than observed, and NVD's recent windows are
still filling. So the result is judged against that noise, not against a point:

  * three calibration windows, from 2022 (main's KEV window), 2023 (drops 2022's backfill-heavy 555)
    and 2024; how far they disagree is a floor on the calibration's own uncertainty;
  * the anchor bracket (onset proxy) and the Poisson error of the anchor's post-2021 count;
  * a quantity not used in the fit: the model's conversion over the last 91 days against the KEV
    additions in those 91 days, and the onset history by window.

    python experiments/transient_matched_hazards.py          # from the repository root
"""
import datetime as dt
import json
import sys
from dataclasses import replace
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from window_matched_hazards import SNAPSHOTS, elasticity, levers, run  # noqa: E402

G, S = "global ecosystem", "Microsoft SharePoint"
WINDOWS = {"from 2022": dt.date(2022, 1, 1), "from 2023": dt.date(2023, 1, 1),
           "from 2024": dt.date(2024, 1, 1)}


def kev_added(snap):
    kev = json.loads(Path(f"data/cisa_kev_{snap}.json").read_text())["vulnerabilities"]
    return {k["cveID"]: dt.date.fromisoformat(k["dateAdded"]) for k in kev}


def path_influx(ns, e):
    """Realized conversion I(t) along the history-driven path, with t in days since 2008-01-01."""
    d = ns["drive_history"](e)
    b_h, b_n, b_x = e.hazards
    tr = d["traj"]
    P = b_h * tr["H"] + b_n * tr["N"] + b_x * tr["X"]
    return d, P, e.C * P / (e.C + P)


def integral(ns, d, I, start, end):
    t0 = (start - dt.date(ns["HISTORY_START"], 1, 1)).days
    t1 = (end - dt.date(ns["HISTORY_START"], 1, 1)).days
    m = (d["t"] >= t0) & (d["t"] <= t1)
    return float(np.trapezoid(I[m], d["t"][m]))


def calibrate_transient(ns, e, start, adds, tol=1e-6, iters=50):
    sat = ns["SATURATION"]
    for _ in range(iters):
        d, P, I = path_influx(ns, e)
        J = integral(ns, d, I, start, ns["SNAPSHOT_DATE"])
        k = adds / J
        C_new = k * P[-1] / sat
        e = replace(e, b_h=e.b_h * k, b_n=e.b_n * k, b_x=e.b_x * k,
                    realized=C_new * sat / (sat + 1))         # Eco.C = realized (sat + 1) / sat
        if abs(k - 1) < tol and abs(P[-1] / (sat * C_new / k) - 1) < tol:
            break
    return e


def evaluate(snap, window):
    ns = run(snap, "trailing")
    added = kev_added(snap)
    snap_d = ns["SNAPSHOT_DATE"]
    ecos = {}
    if window is None:
        ecos = {e.label: e for e in ns["ECOS"]}
    else:
        start = WINDOWS[window]
        adds = sum(1 for v in added.values() if start <= v <= snap_d)
        ecos[G] = calibrate_transient(ns, ns["GLOBAL"], start, adds)
        sp_start = snap_d - dt.timedelta(days=5 * 365)
        sp_adds = sum(1 for c in ns["KEV_IDS"][S] if sp_start < added[c] <= snap_d)
        ecos[S] = calibrate_transient(ns, ns["SHAREPOINT"], sp_start, sp_adds)
    ns["GLOBAL"], ns["SHAREPOINT"] = ecos[G], ecos[S]
    ns["ECOS"] = [ecos[G], ecos[S]]
    ns["TRANSIENT"].clear()
    ns["TRANSIENT"].update({e.label: ns["drive_history"](e) for e in ns["ECOS"]})

    out = {}
    for e in ns["ECOS"]:
        d, P, I = path_influx(ns, e)
        fp, st = e.fixed_point(), ns["TRANSIENT"][e.label]["state"]
        lo, hi = ns["ANCHOR_BRACKET"][e.label]
        a = ns["ANCHOR"][e.label]
        q0 = snap_d - dt.timedelta(days=91)
        out[e.label] = dict(
            C=e.C, b_x=e.b_x, target=fp["E"], today=st["E"], anchor=a, lo=lo, hi=hi,
            ratio=st["E"] / a, inside=lo <= st["E"] <= hi, pc_now=P[-1] / e.C,
            pc_eq=fp["supply"] / e.C, I_now=I[-1], I_eq=fp["influx"],
            q_model=integral(ns, d, I, q0, snap_d),
            q_kev=sum(1 for c, v in added.items() if q0 < v <= snap_d and
                      (e.label == G or c in ns["KEV_IDS"][S])),
            el_gamma=elasticity(e, "gmult"), el_C=elasticity(e, "cmult"), levers=levers(ns, e))
        if e.label == G:
            ages = ns["onset_ages"](ns["KEV_IDS"][G], "mid")
            post = ages <= (snap_d - dt.date(2021, 11, 3)).days
            out[G]["anchor_post_n"] = int(post.sum())
            yr = d["year"]
            by_year = {}
            for x in ages:
                y = (snap_d - dt.timedelta(days=int(x))).year
                by_year[y] = by_year.get(y, 0) + 1
            shape = []
            for wlo, whi in ((2008, 2015), (2016, 2020), (2021, 2023), (2024, 2026)):
                obs = sum(v for y, v in by_year.items() if wlo <= y <= whi)
                days = (min(dt.date(whi, 12, 31), snap_d) - dt.date(wlo, 1, 1)).days
                m = float(np.mean(I[(yr >= wlo) & (yr < whi + 1)]))
                shape.append((f"{wlo}-{whi}", obs / days, m))
            out[G]["shape"] = shape
    return out


def main():
    variants = [("trailing (main)", None), ("transient 2022+", "from 2022"),
                ("transient 2023+", "from 2023"), ("transient 2024+", "from 2024")]
    rows = {(s, name): evaluate(s, w) for s in SNAPSHOTS for name, w in variants}
    names = [n for n, _ in variants]

    print("1. today's state against the corrected KEV anchor")
    print(f"{'snapshot':<11}{'calibration':<17}{'C':>7}{'today':>7}{'anchor [bracket]':>21}{'ratio':>7}"
          f"{'inside':>8}{'target':>8}{'today/tgt':>10}   SharePoint today/anchor")
    for (snap, name), o in rows.items():
        g, s = o[G], o[S]
        print(f"{snap:<11}{name:<17}{g['C']:>7.3f}{g['today']:>7.0f}{g['anchor']:>8.0f} "
              f"[{g['lo']:>4.0f}, {g['hi']:>4.0f}]{g['ratio']:>7.2f}{'yes' if g['inside'] else 'NO':>8}"
              f"{g['target']:>8,.0f}{g['today'] / g['target']:>10.0%}"
              f"   {s['today']:.1f} / {s['anchor']:.1f} = {s['ratio']:.2f}")
    g = rows[("2026-11-16", names[0])][G]
    print(f"   noise scale at 11-16: bracket {g['lo'] / g['anchor']:.2f}-{g['hi'] / g['anchor']:.2f} of the "
          f"anchor (onset proxy); Poisson error of the {g['anchor_post_n']:,} post-launch onsets "
          f"{1 / np.sqrt(g['anchor_post_n']):.1%}")

    print("\n2. snapshot-to-snapshot movement, global")
    for name in names:
        seq = [rows[(s, name)][G] for s in SNAPSHOTS]
        for key, fmt in (("today", "{:,.0f}"), ("target", "{:,.0f}"), ("ratio", "{:.2f}"),
                         ("C", "{:.3f}")):
            vals = [x[key] for x in seq]
            steps = [100 * (b / a - 1) for a, b in zip(vals, vals[1:])]
            print(f"   {name:<17}{key:<7}" + "  ".join(fmt.format(v) for v in vals)
                  + "    steps % " + " ".join(f"{s:+.1f}" for s in steps))

    print("\n3. attacker-side responses and the lever ranking, 11-16")
    for name in names:
        g = rows[("2026-11-16", name)][G]
        print(f"   {name:<17}P/C today {g['pc_now']:.2f}, at the target {g['pc_eq']:.2f}   "
              f"elasticity to gamma {g['el_gamma']:+.2f}, to C {g['el_C']:+.2f}")
        ranked = sorted(g["levers"].items(), key=lambda kv: kv[1])
        print("   " + " " * 17 + "  ".join(f"{k} {v:+.1f}%" for k, v in ranked))

    print("\n4. not fitted: the last 91 days, and the onset history by window (11-16)")
    for name in names:
        g = rows[("2026-11-16", name)][G]
        print(f"   {name:<17}model conversion over the last 91 days {g['q_model']:.0f} against "
              f"{g['q_kev']} KEV additions (Poisson error {np.sqrt(g['q_kev']):.0f}); "
              f"today {g['I_now']:.3f}/d")
        print("   " + " " * 17 + "observed onsets / model I(t): " + "  ".join(
            f"{w} {o:.3f}/{m:.3f} = {o / m:.2f}" for w, o, m in g["shape"]))


if __name__ == "__main__":
    main()
