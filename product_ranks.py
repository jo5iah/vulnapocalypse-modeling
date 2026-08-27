"""Top products by CVE count and by observed exploitation, in one taxonomy.

Both questions are answered from NVD's CPE applicability data — `configurations[].nodes[].
cpeMatch[].criteria`, parsed for `vendor:product` — so the vulnerable and exploited rankings are
directly comparable. KEV's own free-text `vendorProject`/`product` strings are reported beside the
exploited ranking as a cross-check, since they are what CISA publishes.

Two biases worth stating with any result here:

  * A CVE lists every affected product, so one CVE contributes to several products. The counts are
    CVE-product pairs, not a partition of the corpus.
  * CPE applicability is added during NVD analysis, so records still awaiting analysis carry no
    configurations at all and drop out. That censors the most recent weeks hardest, and the
    analyzed share is printed so the size of it is visible.

The exploited side reads the cached KEV mirror. The vulnerable side needs a sweep of every CVE in
the window, which is ~36 NVD pages; those pages are aggregated as they arrive rather than cached,
since keeping them would cost ~500 MB for a table of counts. Only the aggregate is written.

    python3 product_ranks.py [--window-days 365] [--snapshot 2026-08-27]
"""

import argparse
import datetime as dt
import json
import re
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = {"User-Agent": "vulnapocalypse-research/1.0"}
NVD_GAP, PAGE = 6.6, 2000          # 5 requests / 30 s anonymous limit
NVD_MAX_RANGE = 110                # days; NVD rejects a range wider than 120, inclusive
_last = [0.0]


def get(url, retries=4):
    for attempt in range(retries):
        wait = NVD_GAP - (time.time() - _last[0])
        if wait > 0:
            time.sleep(wait)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180) as r:
                payload = json.loads(r.read())
            _last[0] = time.time()
            return payload
        except Exception as exc:                                    # noqa: BLE001
            print(f"    retry {attempt + 1}/{retries}: {type(exc).__name__} "
                  f"{getattr(exc, 'code', '')}", flush=True)
            _last[0] = time.time()
            time.sleep(15)
    raise RuntimeError(f"could not fetch {url}")


def products(record):
    """Distinct `vendor:product` strings a CVE record declares vulnerable."""
    out = set()
    for cfg in record.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    out.add(f"{parts[3]}:{parts[4]}")
    return out


# CPE treats each supported release as its own product, so `windows_10_1809` and
# `windows_server_2012` are distinct entries and no single row says "Windows". Stripping trailing
# version-like tokens recovers the family a person would name: plain versions (10, 8.1), year
# releases (2012), Microsoft's half-year tags (21h2), and service-pack/revision markers. Client
# and server Windows stay apart, which is a real distinction rather than an artifact, and so do
# genuine variants such as `windows_rt`.
VERSIONISH = re.compile(r"^(\d+(\.\d+)*|\d+h\d+|r\d+|sp\d+|v\d+|\d+[a-z]?)$")


def family(name):
    vendor, product = name.split(":", 1)
    toks = product.split("_")
    while len(toks) > 1 and VERSIONISH.match(toks[-1]):
        toks.pop()
    return f"{vendor}:{'_'.join(toks)}"


def tally(records):
    """Counts of CVEs per product and per family; a CVE counts once for each, never twice."""
    counts, fams, analyzed = Counter(), Counter(), 0
    for v in records:
        hits = products(v["cve"])
        analyzed += bool(hits)
        for p in hits:
            counts[p] += 1
        for f in {family(p) for p in hits}:
            fams[f] += 1
    return counts, fams, analyzed


def sweep(start, end):
    """Every CVE published in [start, end], aggregated page by page and not cached."""
    counts, fams, analyzed, total_seen = Counter(), Counter(), 0, 0
    win_start = start
    while win_start <= end:
        win_end = min(win_start + dt.timedelta(days=NVD_MAX_RANGE), end)
        index, total = 0, None
        while total is None or index < total:
            url = NVD + "?" + urllib.parse.urlencode(
                {"pubStartDate": f"{win_start}T00:00:00.000",
                 "pubEndDate": f"{win_end}T23:59:59.999",
                 "resultsPerPage": PAGE, "startIndex": index}, safe=":")
            payload = get(url)
            total = payload["totalResults"]
            c, f, a = tally(payload["vulnerabilities"])
            counts.update(c)
            fams.update(f)
            analyzed += a
            total_seen += len(payload["vulnerabilities"])
            index += PAGE
            print(f"  {win_start}..{win_end}  {min(index, total):>6,}/{total:<6,}  "
                  f"products so far {len(counts):,}", flush=True)
        win_start = win_end + dt.timedelta(days=1)
    return counts, fams, analyzed, total_seen


def show(title, counts, n_cves, top=10):
    print(f"\n{title}")
    print(f"  {'rank':<5}{'vendor:product':<44}{'CVEs':>8}{'share':>8}")
    for i, (name, n) in enumerate(counts.most_common(top), 1):
        print(f"  {i:<5}{name:<44}{n:>8,}{n / n_cves:>8.1%}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-days", type=int, default=365)
    ap.add_argument("--snapshot", default="2026-08-27")
    args = ap.parse_args()
    snap = dt.date.fromisoformat(args.snapshot)

    kev_path = DATA / f"nvd_kev_{args.snapshot}.json"
    kev_records = json.loads(kev_path.read_text())["vulnerabilities"]
    kev_counts, kev_fams, kev_analyzed = tally(kev_records)
    print(f"exploited: {len(kev_records):,} KEV CVEs, {kev_analyzed:,} with CPE applicability "
          f"({kev_analyzed / len(kev_records):.0%})")
    show("Top exploited product FAMILIES (CISA KEV, whole catalogue)", kev_fams, kev_analyzed)
    show("Top exploited products, CPE granularity (each release is its own product)",
         kev_counts, kev_analyzed)

    raw = json.loads((DATA / f"cisa_kev_{args.snapshot}.json").read_text())["vulnerabilities"]
    free = Counter(f"{e['vendorProject'].strip()} / {e['product'].strip()}" for e in raw)
    print("\n  cross-check in CISA's own free-text product names")
    for i, (name, n) in enumerate(free.most_common(5), 1):
        print(f"  {i:<5}{name:<44}{n:>8,}")

    start = snap - dt.timedelta(days=args.window_days)
    print(f"\nvulnerable: sweeping every CVE published {start}..{snap} "
          f"({args.window_days} days); pages are aggregated, not cached")
    counts, fams, analyzed, seen = sweep(start, snap)
    print(f"\nvulnerable: {seen:,} CVEs retrieved, {analyzed:,} with CPE applicability "
          f"({analyzed / seen:.0%})")
    show(f"Top vulnerable product FAMILIES (CVEs published in the {args.window_days} days "
         f"to {snap})", fams, analyzed)
    show("Top vulnerable products, CPE granularity", counts, analyzed)

    out = DATA / f"product_ranks_{args.snapshot}.json"
    out.write_text(json.dumps({
        "snapshot": args.snapshot, "window_days": args.window_days,
        "method": "distinct vendor:product from NVD configurations[].nodes[].cpeMatch[].criteria "
                  "where vulnerable=true; counts are CVE-product pairs",
        "exploited": {"cves": len(kev_records), "with_cpe": kev_analyzed,
                      "counts": dict(kev_counts.most_common(50)),
                      "families": dict(kev_fams.most_common(50)),
                      "cisa_free_text": dict(free.most_common(20))},
        "vulnerable": {"window_start": str(start), "cves": seen, "with_cpe": analyzed,
                       "counts": dict(counts.most_common(50)),
                       "families": dict(fams.most_common(50))},
    }, indent=1))
    print(f"\nwrote {out.relative_to(DATA.parent)}")
