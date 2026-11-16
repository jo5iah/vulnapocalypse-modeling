"""Experiment: drive the transient with the monthly publication series instead of annual rates.

The annual drive interpolates yearly rates linearly with each pinned to 1 January, so it runs about half a
year ahead of the data and spreads a surge over two years: it sees 2025 -> 2026 publication growth of
+40% where the data have +130%. HISTORY_DRIVE = "monthly" in the notebook's first cell holds each
month's measured rate constant within the month (VulnData section 6b; the totals match the annual
history exactly). Monthly series exist from the 2026-09-20 snapshot, so that is where this starts.

Reports:
  1. annual against monthly drive, for the equilibrium calibration (main) and the transient-matched one
     (window from 2023), P/C = 2, at each snapshot with a monthly series;
  2. the growth test the monthly drive makes usable: the model's conversion growth year on year against
     KEV's, for P/C = 0.1 to 10, and the widening of publications per exploit. KEV's year-on-year growth
     swings by about 20 points on cataloging policy, so the three single years are shown beside their
     compounded total. P/C = 0.1 is effectively unsaturated: whatever widening it shows comes from the
     slow backlog lagging the publication surge, not from attacker capacity.

    python experiments/monthly_drive.py          # from the repository root
"""
import datetime as dt
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import window_matched_hazards as W  # noqa: E402
from transient_matched_hazards import G, calibrate_transient, kev_added, path_influx  # noqa: E402

SNAPS = ["2026-09-20", "2026-10-14", "2026-11-16"]
START = dt.date(2023, 1, 1)
PAIRS = [(2023, 2024), (2024, 2025), (2025, 2026)]


def state(snap, drive, calibration, saturation=2.0):
    ns = W.run(snap, "trailing", drive=drive, saturation=saturation)
    e = ns["GLOBAL"]
    if calibration == "transient 2023+":
        added = kev_added(snap)
        adds = sum(1 for v in added.values() if START <= v <= ns["SNAPSHOT_DATE"])
        e = calibrate_transient(ns, e, START, adds)
        ns["GLOBAL"], ns["ECOS"] = e, [e, ns["SHAREPOINT"]]
        ns["TRANSIENT"][e.label] = ns["drive_history"](e)
    return ns, e


def main():
    print("1. annual against monthly drive, P/C = 2")
    print(f"{'snapshot':<12}{'calibration':<20}{'drive':<9}{'today':>7}{'target':>8}{'/anchor':>9}"
          f"{'in bracket':>12}")
    for snap in SNAPS:
        for cal in ("equilibrium (main)", "transient 2023+"):
            for drive in ("annual", "monthly"):
                ns, e = state(snap, drive, cal)
                st = ns["TRANSIENT"][G]["state"]["E"]
                lo, hi = ns["ANCHOR_BRACKET"][G]
                print(f"{snap:<12}{cal:<20}{drive:<9}{st:>7.0f}{e.fixed_point()['E']:>8,.0f}"
                      f"{st / ns['ANCHOR'][G]:>9.2f}{'yes' if lo <= st <= hi else 'no':>12}")

    snap = SNAPS[-1]
    added = kev_added(snap)
    hist = W.inputs_for(snap)[1]
    days = {y: hist[str(y)]["days"] for y in (2023, 2024, 2025, 2026)}
    kev = {y: sum(1 for v in added.values() if v.year == y) / days[y] for y in days}
    pub = {y: hist[str(y)]["total"] / days[y] for y in days}
    g = lambda x, a, b: x[b] / x[a] - 1
    print(f"\n2. year-on-year growth at {snap}, monthly drive, transient-matched calibration")
    print(f"   {'':<22}" + "".join(f"{f'{a}->{b}':>12}" for a, b in PAIRS) + f"{'2023->2026':>13}"
          + f"{'pubs per exploit 25->26':>26}")
    print(f"   {'publications':<22}" + "".join(f"{g(pub, a, b):>+12.0%}" for a, b in PAIRS)
          + f"{g(pub, 2023, 2026):>+13.0%}")
    print(f"   {'KEV additions':<22}" + "".join(f"{g(kev, a, b):>+12.0%}" for a, b in PAIRS)
          + f"{g(kev, 2023, 2026):>+13.0%}"
          + f"{'x' + format((pub[2026] / kev[2026]) / (pub[2025] / kev[2025]), '.2f'):>26}")
    for r in (0.1, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0):
        ns, e = state(snap, "monthly", "transient 2023+", r)
        d, P, I = path_influx(ns, e)
        m = {y: float(np.mean(I[(d["year"] >= y) & (d["year"] < y + 1)])) for y in days}
        print(f"   {f'model, P/C = {r:g}':<22}" + "".join(f"{g(m, a, b):>+12.0%}" for a, b in PAIRS)
              + f"{g(m, 2023, 2026):>+13.0%}"
              + f"{'x' + format((pub[2026] / m[2026]) / (pub[2025] / m[2025]), '.2f'):>26}")


if __name__ == "__main__":
    main()
