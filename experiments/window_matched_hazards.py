"""Experiment: calibrate the hazards over the KEV influx window instead of the trailing year.

The hazards are beta_k = s_k * 2C / (gamma_cal * r_k) with C from the pooled-since-2022 KEV rate. On
main gamma_cal is the trailing-year publication rate; HAZARD_WINDOW = "pooled" in the notebook's first
cell sets it to the mean publication rate over the same 2022-to-snapshot window instead.

For every archived snapshot that carries its own KEV files (2026-08-14 to 2026-11-16) and for both
calibrations, this runs the notebook's first cell against that snapshot's inputs and reports:

  1. whether today's state sits inside the corrected KEV anchor bracket;
  2. how much each quantity moves from snapshot to snapshot;
  3. how far the attacker-side responses and the lever ranking move.

Inputs that main only keeps at the latest snapshot are rebuilt per snapshot: the 2026 publication total
from that snapshot's own 2026-08-11 window (earlier 2026 windows are closed and taken as now counted),
and the SharePoint CVE set filtered to publication on or before the snapshot.

    python experiments/window_matched_hazards.py          # from the repository root
"""
import contextlib
import copy
import datetime as dt
import io
import json
from dataclasses import replace
from pathlib import Path

import numpy as np

SNAPSHOTS = ["2026-08-14", "2026-08-27", "2026-09-20", "2026-10-14", "2026-11-16"]
MODES = ["trailing", "pooled", "quarter"]

NB = json.loads(Path("ODEtoVuln_daily.ipynb").read_text())
CELL1 = "".join(NB["cells"][1]["source"])
CELL1 = "\n".join(l for l in CELL1.splitlines() if not l.lstrip().startswith("%"))
for old, new in (
        ('DERIVED = json.loads(Path("data/derived_params.json").read_text())', "DERIVED = __DERIVED__"),
        ('HISTORY = json.loads(Path("data/global_history.json").read_text())', "HISTORY = __HISTORY__"),
        ('SHAREPOINT_CVES = json.loads(Path("data/sharepoint_union.json").read_text())["vulnerabilities"]',
         "SHAREPOINT_CVES = __SP__"),
        ('HAZARD_WINDOW = "pooled"', "HAZARD_WINDOW = __MODE__")):
    assert CELL1.count(old) == 1, old
    CELL1 = CELL1.replace(old, new)

HISTORY_NOW = json.loads(Path("data/global_history.json").read_text())
SP_NOW = json.loads(Path("data/sharepoint_union.json").read_text())["vulnerabilities"]


def inputs_for(snap):
    d = dt.date.fromisoformat(snap)
    hist = copy.deepcopy(HISTORY_NOW)
    w = hist["2026"]["windows"]
    late = json.loads(Path(f"data/hist_2026-08-11_{snap}.json").read_text())["totalResults"]
    total = w[0][2] + w[1][2] + late
    hist["2026"] = {"total": total, "days": d.timetuple().tm_yday,
                    "windows": [w[0], w[1], ["2026-08-11", snap, late]]}
    sp = [v for v in SP_NOW if dt.date.fromisoformat(v["cve"]["published"][:10]) <= d]
    derived = json.loads(Path(f"data/derived_params_{snap}.json").read_text())
    return derived, hist, sp


def run(snap, mode):
    derived, hist, sp = inputs_for(snap)
    ns = {"__DERIVED__": derived, "__HISTORY__": hist, "__SP__": sp, "__MODE__": mode}
    with contextlib.redirect_stdout(io.StringIO()):
        exec(CELL1, ns)
    return ns


def realized_today(e, state):
    b_h, b_n, b_x = e.hazards
    P = b_h * state["H"] + b_n * state["N"] + b_x * state["X"]
    return e.C * P / (e.C + P), P / e.C


def kev_rate_last(snap, days=91):
    d = dt.date.fromisoformat(snap)
    kev = json.loads(Path(f"data/cisa_kev_{snap}.json").read_text())["vulnerabilities"]
    return sum(1 for k in kev if 0 <= (d - dt.date.fromisoformat(k["dateAdded"])).days < days) / days


def pct(a, b):
    return 100.0 * (a / b - 1.0)


def levers(ns, e):
    """Eventual change in E* for the document's attacker shocks and its five equal-effort levers."""
    base = e.fixed_point()["E"]
    ps = e.patch_rate / (e.patch_rate + e.lam)
    realized = e.f_fix * ps
    return {
        "10x discovery": pct(e.fixed_point(gmult=10)["E"], base),
        "3x throughput": pct(e.fixed_point(cmult=3)["E"], base),
        "lam +30%": pct(e.fixed_point(lam=e.lam * 1.3)["E"], base),
        "surface -30%": pct(e.fixed_point(eps=0.7)["E"], base),
        "ever-patched +30%": pct(e.fixed_point(f_fix=min(1.0, realized * 1.3 / ps))["E"], base),
        "retirement +30%": pct(e.fixed_point(phi=e.phi * 1.3)["E"], base),
        "patch delay -30%": pct(e.fixed_point(tau=e.tau * 0.7)["E"], base),
    }


def elasticity(e, kw):
    base = e.fixed_point()["E"]
    return (e.fixed_point(**{kw: 1.01})["E"] - e.fixed_point(**{kw: 0.99})["E"]) / (0.02 * base)


rows = {}
for snap in SNAPSHOTS:
    for mode in MODES:
        ns = run(snap, mode)
        out = {}
        for e in ns["ECOS"]:
            fp, st = e.fixed_point(), ns["TRANSIENT"][e.label]["state"]
            lo, hi = ns["ANCHOR_BRACKET"][e.label]
            I_now, pc_now = realized_today(e, st)
            out[e.label] = dict(
                gamma=e.gamma, gamma_cal=e.gamma_cal or e.gamma, b_x=e.hazards[2], C=e.C,
                target=fp["E"], today=st["E"], anchor=ns["ANCHOR"][e.label], lo=lo, hi=hi,
                ratio=st["E"] / ns["ANCHOR"][e.label], inside=lo <= st["E"] <= hi,
                pc_eq=fp["supply"] / e.C, pc_now=pc_now, I_eq=fp["influx"], I_now=I_now,
                el_gamma=elasticity(e, "gmult"), el_C=elasticity(e, "cmult"),
                levers=levers(ns, e))
        out["kev91"] = kev_rate_last(snap)
        out["kev_pooled"] = ns["MEAS"]["kev_influx_per_day"]
        rows[(snap, mode)] = out

G, S = "global ecosystem", "Microsoft SharePoint"

print("1. today's state against the corrected KEV anchor")
print(f"{'snapshot':<11}{'mode':<10}{'gamma':>7}{'g_cal':>7}{'today':>7}{'anchor [bracket]':>21}"
      f"{'ratio':>7}{'inside':>8}{'target':>8}{'today/tgt':>10}   SharePoint today/anchor")
for (snap, mode), o in rows.items():
    g, s = o[G], o[S]
    print(f"{snap:<11}{mode:<10}{g['gamma']:>7.1f}{g['gamma_cal']:>7.1f}{g['today']:>7.0f}"
          f"{g['anchor']:>8.0f} [{g['lo']:>4.0f}, {g['hi']:>4.0f}]{g['ratio']:>7.2f}"
          f"{'yes' if g['inside'] else 'NO':>8}{g['target']:>8,.0f}{g['today'] / g['target']:>10.0%}"
          f"   {s['today']:.1f} / {s['anchor']:.1f} = {s['ratio']:.2f} {'in' if s['inside'] else 'OUT'}")

print("   KEV additions per day, last 91 days: " + "  ".join(
    f"{s} {rows[(s, 'trailing')]['kev91']:.3f}" for s in SNAPSHOTS))
print("\n2. snapshot-to-snapshot movement, global (08-14 -> 11-16)")
for mode in MODES:
    seq = [rows[(s, mode)][G] for s in SNAPSHOTS]
    for key, fmt in (("b_x", "{:.3e}"), ("today", "{:,.0f}"), ("ratio", "{:.2f}"), ("target", "{:,.0f}")):
        vals = [x[key] for x in seq]
        steps = [pct(b, a) for a, b in zip(vals, vals[1:])]
        print(f"   {mode:<9}{key:<7}" + "  ".join(fmt.format(v) for v in vals)
              + f"    steps % " + " ".join(f"{s:+.1f}" for s in steps))

print("\n3. attacker-side responses and the lever ranking, 11-16")
for mode in MODES:
    g = rows[("2026-11-16", mode)][G]
    print(f"   {mode:<9} P/C at equilibrium {g['pc_eq']:.2f}, today {g['pc_now']:.2f}   "
          f"elasticity to gamma {g['el_gamma']:+.2f}, to C {g['el_C']:+.2f}")
    print(f"   {'':<9} realized conversion: equilibrium {g['I_eq']:.3f}/d, today {g['I_now']:.3f}/d   "
          f"(KEV pooled {rows[('2026-11-16', mode)]['kev_pooled']:.3f}/d, last 91 days "
          f"{rows[('2026-11-16', mode)]['kev91']:.3f}/d)")
    ranked = sorted(g["levers"].items(), key=lambda kv: kv[1])
    print("   " + " " * 9 + "  ".join(f"{k} {v:+.1f}%" for k, v in ranked))
