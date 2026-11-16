"""Per-CVE stratification table, and the stratified exploitation rates built from it.

One row per CVE: publication date, vendor, product families, CVSS exposure fields, severity,
weakness types, CISA's SSVC decision points and the KEV addition date. Everything the model's
planned stratification needs (plan.md step 2) is a group-by over this table.

    python3 cve_strata.py build  --start 2025-11-16 --end 2026-11-16   # full sweep, ~1 h unkeyed
    python3 cve_strata.py update                                       # only what changed since
    python3 cve_strata.py report [--as-of 2026-11-16] [--window-days 365] [--top 20]

Files, all under data/ unless noted:

    cve_strata.csv.gz            the per-CVE table (gzip CSV, sorted by CVE id)
    cve_strata_meta.json         sweep floor, last sync time, row counts
    cve_stratification_<as-of>.csv   long-format cells: vendor x exposure -> counts
    ../cve_stratification_<as-of>.md the tables a person reads

`update` asks NVD only for records modified since the last sync (lastModStartDate), which covers
new publications, CVEs that gained CPE applicability or a CVSS score since, and new KEV flags, so
keeping the table current costs minutes rather than a full sweep. The KEV catalog is refetched
whole on every build and update, and KEV CVEs published before the sweep floor are kept as rows
so that additions in a window can be classified whatever their publication date.

Set NVD_API_KEY to use NVD's keyed rate limit (50 requests / 30 s instead of 5).

Three things to know when reading any rate from this table:

  * Vendor comes from NVD's CPE applicability when the record has it, else from the `affected`
    block the CVE's assigner supplied, else it is empty. `vendor_source` records which. The two
    taxonomies are not identical; assigner names are normalized but not reconciled to CPE names.
  * A CVE that lists several vendors is assigned one, so the table is a partition: the vendor
    with the most vulnerable CPE entries, ignoring distributions that repackage upstream code
    (REPACKAGERS) whenever another vendor is present. `families` keeps every vendor:product.
  * Exposure is read from the CVSS vector, preferring NVD's own (Primary) score within the
    newest CVSS version present. Unscored records form their own class rather than being dropped.
"""

import argparse
import csv
import datetime as dt
import gzip
import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
TABLE = DATA / "cve_strata.csv.gz"
META = DATA / "cve_strata_meta.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY = os.environ.get("NVD_API_KEY")
UA = {"User-Agent": "vulnapocalypse-research/1.0", **({"apiKey": KEY} if KEY else {})}
NVD_GAP, PAGE, MAX_RANGE = (0.7 if KEY else 6.6), 2000, 110
_last = [0.0]

FIELDS = ["cve", "published", "last_modified", "status", "source", "vendor", "vendor_source",
          "families", "cvss_version", "cvss_type", "base_score", "severity", "av", "pr", "ui",
          "exposure", "cwes", "ssvc_exploitation", "ssvc_automatable", "ssvc_impact", "kev_added"]

REPACKAGERS = {"debian", "fedoraproject", "redhat", "canonical", "opensuse", "suse", "netapp",
               "gentoo", "almalinux", "rockylinux", "amazon"}
VERSIONISH = re.compile(r"^(\d+(\.\d+)*|\d+h\d+|r\d+|sp\d+|v\d+|\d+[a-z]?)$")
CORP = re.compile(r"\b(the|inc|incorporated|corporation|corp|co|company|llc|ltd|limited|gmbh|ag|"
                  r"sa|plc|bv|pty|oy|ab|kk|srl|technologies|technology|software foundation|"
                  r"foundation|project|team|systems?)\b\.?")
EXPOSURES = ["remote, no privileges, no user action", "remote, other", "local or physical",
             "unscored"]


def get(url, retries=5):
    for attempt in range(retries):
        wait = NVD_GAP - (time.time() - _last[0])
        if wait > 0:
            time.sleep(wait)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=240) as r:
                payload = json.loads(r.read())
            _last[0] = time.time()
            return payload
        except Exception as exc:                                    # noqa: BLE001
            print(f"    retry {attempt + 1}/{retries}: {type(exc).__name__} "
                  f"{getattr(exc, 'code', '')}", flush=True)
            _last[0] = time.time()
            time.sleep(20)
    raise RuntimeError(f"could not fetch {url}")


def pages(flags=(), **params):
    """Every record matching an NVD query, one page at a time."""
    index, total = 0, None
    while total is None or index < total:
        url = NVD + "?" + urllib.parse.urlencode(
            {**params, "resultsPerPage": PAGE, "startIndex": index}, safe=":")
        for flag in flags:
            url += f"&{flag}"
        payload = get(url)
        total = payload["totalResults"]
        index += PAGE
        yield payload["vulnerabilities"], min(index, total), total


def family(vendor, product):
    """CPE gives each release its own product; strip trailing version tokens to get the family."""
    toks = product.split("_")
    while len(toks) > 1 and VERSIONISH.match(toks[-1]):
        toks.pop()
    return f"{vendor}:{'_'.join(toks)}"


def norm_vendor(name):
    """Assigner-supplied vendor text to a CPE-like token: 'Microsoft Corporation' -> 'microsoft'."""
    s = CORP.sub(" ", name.lower().replace(",", " "))
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s if s not in ("", "n_a", "na", "unknown", "none") else ""


def cpe_vendors(cve):
    counts, fams = Counter(), set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if match.get("vulnerable") and len(parts) > 4:
                    counts[parts[3]] += 1
                    fams.add(family(parts[3], parts[4]))
    return counts, fams


def pick_vendor(counts):
    """One vendor per CVE. Repackaging distributions lose to any other vendor present."""
    own = {v: n for v, n in counts.items() if v not in REPACKAGERS} or dict(counts)
    return max(own, key=lambda v: (own[v], v)) if own else ""


def cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        m = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        d = m["cvssData"]
        av = (d.get("attackVector") or d.get("accessVector") or "").upper()
        pr = (d.get("privilegesRequired") or d.get("authentication") or "").upper()
        ui = d.get("userInteraction")
        if ui is None and "userInteractionRequired" in m:          # CVSS v2 keeps it beside cvssData
            ui = "REQUIRED" if m["userInteractionRequired"] else "NONE"
        sev = d.get("baseSeverity") or m.get("baseSeverity") or ""
        return {"cvss_version": d.get("version", ""), "cvss_type": m.get("type", ""),
                "base_score": d.get("baseScore", ""), "severity": sev.upper(),
                "av": av, "pr": pr, "ui": (ui or "").upper()}
    return {"cvss_version": "", "cvss_type": "", "base_score": "", "severity": "",
            "av": "", "pr": "", "ui": ""}


def exposure(av, pr, ui):
    if not av:
        return EXPOSURES[3]
    if av in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT"):
        return EXPOSURES[0] if pr == "NONE" and ui in ("NONE", "") else EXPOSURES[1]
    return EXPOSURES[2]


def ssvc(cve):
    out = {"ssvc_exploitation": "", "ssvc_automatable": "", "ssvc_impact": ""}
    for m in cve.get("metrics", {}).get("ssvcV203", []):
        for opt in m.get("ssvcData", {}).get("options", []):
            for k, v in opt.items():
                key = {"exploitation": "ssvc_exploitation", "automatable": "ssvc_automatable",
                       "technicalImpact": "ssvc_impact"}.get(k)
                if key:
                    out[key] = v
    return out


def row(cve):
    counts, fams = cpe_vendors(cve)
    vendor, vsrc = pick_vendor(counts), "cpe"
    if not vendor:
        seen = Counter(norm_vendor(a.get("vendor") or "") for blk in cve.get("affected", [])
                       for a in blk.get("affectedData", []))
        seen.pop("", None)
        vendor, vsrc = (max(seen, key=lambda v: (seen[v], v)), "assigner") if seen else ("", "")
    c = cvss(cve)
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    return {"cve": cve["id"], "published": cve["published"][:10],
            "last_modified": cve["lastModified"][:19], "status": cve.get("vulnStatus", ""),
            "source": cve.get("sourceIdentifier", ""), "vendor": vendor, "vendor_source": vsrc,
            "families": "|".join(sorted(fams)), **c,
            "exposure": exposure(c["av"], c["pr"], c["ui"]), "cwes": "|".join(cwes), **ssvc(cve),
            "kev_added": cve.get("cisaExploitAdd", "")}


def read_table():
    if not TABLE.exists():
        return {}
    with gzip.open(TABLE, "rt", newline="") as fh:
        return {r["cve"]: r for r in csv.DictReader(fh)}


def cve_key(cve_id):
    _, year, num = cve_id.split("-")
    return int(year), int(num)


def write_table(rows, meta):
    tmp = TABLE.with_suffix(".tmp")
    with gzip.open(tmp, "wt", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for cid in sorted(rows, key=cve_key):
            w.writerow({k: rows[cid].get(k, "") for k in FIELDS})
    tmp.replace(TABLE)                       # a failed sweep never leaves a half-written table
    meta["rows"] = len(rows)
    meta["rows_kev"] = sum(1 for r in rows.values() if r["kev_added"])
    META.write_text(json.dumps(meta, indent=1))
    print(f"wrote {TABLE.relative_to(ROOT)}: {len(rows):,} rows, {meta['rows_kev']:,} in KEV")


def windows(start, end):
    while start <= end:
        stop = min(start + dt.timedelta(days=MAX_RANGE), end)
        yield start, stop
        start = stop + dt.timedelta(days=1)


def sweep_kev(rows):
    n = 0
    for vulns, done, total in pages(flags=("hasKev",)):
        for v in vulns:
            rows[v["cve"]["id"]] = row(v["cve"])
            n += 1
        print(f"  KEV {done:,}/{total:,}", flush=True)
    return n


def build(args):
    start, end = dt.date.fromisoformat(args.start), dt.date.fromisoformat(args.end)
    synced = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    rows = {} if args.fresh else read_table()
    for a, b in windows(start, end):
        for vulns, done, total in pages(pubStartDate=f"{a}T00:00:00.000",
                                        pubEndDate=f"{b}T23:59:59.999"):
            for v in vulns:
                rows[v["cve"]["id"]] = row(v["cve"])
            print(f"  published {a}..{b}  {done:>6,}/{total:<6,}  rows {len(rows):,}", flush=True)
    sweep_kev(rows)
    old = json.loads(META.read_text()) if META.exists() and not args.fresh else {}
    floor = min(str(start), old.get("floor", str(start)))
    write_table(rows, {"floor": floor, "last_sync": synced.isoformat(timespec="seconds"),
                       "source": NVD})


def update(args):
    meta = json.loads(META.read_text())
    rows = read_table()
    since = dt.datetime.fromisoformat(meta["last_sync"]) - dt.timedelta(hours=6)   # overlap
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    floor, changed, added = meta["floor"], 0, 0
    a = since
    while a < now:
        b = min(a + dt.timedelta(days=MAX_RANGE), now)
        for vulns, done, total in pages(lastModStartDate=a.isoformat(timespec="milliseconds"),
                                        lastModEndDate=b.isoformat(timespec="milliseconds")):
            for v in vulns:
                cve = v["cve"]
                if cve["published"][:10] < floor and cve["id"] not in rows:
                    continue                 # modified, but published before the table begins
                added += cve["id"] not in rows
                changed += 1
                rows[cve["id"]] = row(cve)
            print(f"  modified {a:%Y-%m-%d}..{b:%Y-%m-%d}  {done:>6,}/{total:<6,}", flush=True)
        a = b
    sweep_kev(rows)
    print(f"{changed:,} rows refreshed, {added:,} of them new")
    write_table(rows, {**meta, "last_sync": now.isoformat(timespec="seconds")})


# ---------------------------------------------------------------------------- report

def misallocation(cells):
    """Share of KEV additions a single population-wide rate puts in the wrong cell:
    half the summed |observed - expected|, over the total. 0 means composition is explained
    by volume alone; this is the quantity a stratified model exists to reduce."""
    n = sum(p for p, _ in cells.values())
    k = sum(x for _, x in cells.values())
    if not n or not k:
        return float("nan")
    return 0.5 * sum(abs(x - k * p / n) for p, x in cells.values()) / k


def report(args):
    meta = json.loads(META.read_text())
    rows = list(read_table().values())
    # reconcile assigner spellings to CPE vendors that differ only by separators
    # ('palo_alto_networks' -> 'paloaltonetworks'); anything else is left as the assigner wrote it
    squash = lambda v: v.replace("_", "").replace("-", "")
    cpe_names = {squash(r["vendor"]): r["vendor"] for r in rows if r["vendor_source"] == "cpe"}
    for r in rows:
        if r["vendor_source"] == "assigner":
            r["vendor"] = cpe_names.get(squash(r["vendor"]), r["vendor"])
    as_of = dt.date.fromisoformat(args.as_of or meta["last_sync"][:10])
    start = as_of - dt.timedelta(days=args.window_days)
    if str(start) < meta["floor"]:
        print(f"note: window starts {start}, before the table's floor {meta['floor']}")
    in_win = lambda d: bool(d) and str(start) < d <= str(as_of)
    pub = [r for r in rows if in_win(r["published"])]
    kev = [r for r in rows if in_win(r["kev_added"])]
    cohort = [r for r in pub if r["kev_added"]]
    N, K = len(pub), len(kev)

    top = [v for v, _ in Counter(r["vendor"] for r in kev if r["vendor"]).most_common(args.top)]
    vclass = lambda r: (r["vendor"] if r["vendor"] in top
                        else "(other vendors)" if r["vendor"] else "(no vendor recorded)")
    vendors = top + ["(other vendors)", "(no vendor recorded)"]

    def tally(key):
        cells = defaultdict(lambda: [0, 0, 0])
        for r in pub:
            cells[key(r)][0] += 1
        for r in kev:
            cells[key(r)][1] += 1
        for r in cohort:
            cells[key(r)][2] += 1
        return cells

    def table(cells, order, head):
        out = [f"| {head} | published | share | KEV additions | share | per 1,000 published "
               "| lift | published in window and in KEV |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for name in order:
            p, k, c = cells.get(name, (0, 0, 0))
            rate = 1000 * k / p if p else float("nan")
            lift = (k / K) / (p / N) if p and K else float("nan")
            out.append(f"| {name} | {p:,} | {p / N:.1%} | {k} | {k / K:.1%} | {rate:.1f} | "
                       f"{lift:.1f}× | {c} |")
        out.append(f"| **all** | {N:,} | 100% | {K} | 100% | {1000 * K / N:.1f} | 1.0× "
                   f"| {len(cohort)} |")
        return out

    share = lambda rs, f: sum(1 for r in rs if f(r)) / len(rs) if rs else float("nan")
    L = [f"# CVE stratification — {args.window_days} days to {as_of}", "",
         f"Built by `cve_strata.py report` from `data/cve_strata.csv.gz` (last synced with NVD "
         f"{meta['last_sync']} UTC, table floor {meta['floor']}). **Published**: {N:,} CVEs "
         f"with an NVD publication date in ({start}, {as_of}]. **KEV additions**: {K} CVEs "
         f"CISA added in the same window, whatever their publication date; {len(cohort)} of "
         f"them were also published in it. *Per 1,000 published* divides the two, the "
         f"stratified analogue of the model's conversion; *lift* is a class's share of KEV "
         f"additions over its share of publications.", "",
         "## Coverage of each field", "",
         "| field | published in window | KEV additions |", "|---|---:|---:|"]
    for name, f in [("vendor from NVD CPE applicability", lambda r: r["vendor_source"] == "cpe"),
                    ("vendor from the assigner's `affected` block",
                     lambda r: r["vendor_source"] == "assigner"),
                    ("any vendor", lambda r: bool(r["vendor"])),
                    ("CVSS vector (exposure class)", lambda r: bool(r["av"])),
                    ("… scored by NVD itself", lambda r: r["cvss_type"] == "Primary"),
                    ("weakness type (CWE)", lambda r: bool(r["cwes"])),
                    ("SSVC decision points (CISA)", lambda r: bool(r["ssvc_exploitation"]))]:
        L.append(f"| {name} | {share(pub, f):.1%} | {share(kev, f):.1%} |")

    ex, ve = tally(lambda r: r["exposure"]), tally(vclass)
    both = tally(lambda r: (vclass(r), r["exposure"]))
    L += ["", "## By exposure class", ""] + table(ex, EXPOSURES, "exposure (CVSS)")
    L += ["", f"## By vendor: the {len(top)} with most KEV additions, and the rest", "",
          "Vendors are chosen by exploitation, not volume. Rates for vendors whose CVEs are "
          "often unanalyzed are overstated to the extent their publications sit in "
          "*(no vendor recorded)*.", ""] + table(ve, vendors, "vendor")

    L += ["", "## Vendor × exposure: KEV additions / published, per 1,000", "",
          "| vendor | " + " | ".join(EXPOSURES) + " |", "|---|" + "---:|" * len(EXPOSURES)]
    for v in vendors:
        cells = []
        for e in EXPOSURES:
            p, k, _ = both.get((v, e), (0, 0, 0))
            cells.append(f"{k}/{p:,} = {1000 * k / p:.1f}" if p else (f"{k}/0" if k else "—"))
        L.append(f"| {v} | " + " | ".join(cells) + " |")

    by_cwe = defaultdict(lambda: [0, 0, 0])
    for rs, i in ((pub, 0), (kev, 1), (cohort, 2)):
        for r in rs:
            for c in (r["cwes"].split("|") if r["cwes"] else ["(none)"]):
                by_cwe[c][i] += 1
    cw_top = [c for c, _ in sorted(by_cwe.items(), key=lambda t: -t[1][1])[:15]]
    L += ["", "## By weakness type: the 15 with most KEV additions", "",
          "A CVE with several CWEs counts under each, so these rows overlap and do not sum.", ""]
    L += table(by_cwe, cw_top, "CWE")[:-1]

    sev = tally(lambda r: r["severity"] or "unscored")
    L += ["", "## By CVSS severity", ""] + table(
        sev, [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "unscored") if s in sev],
        "severity")
    sv = tally(lambda r: r["ssvc_exploitation"] or "(not assessed)")
    L += ["", "## By CISA's SSVC exploitation value", "",
          "CISA's own assessment at the time it enriched the record: `none`, `poc` (a public "
          "proof of concept) or `active`. KEV additions are `active` by construction; the "
          "useful rows are how many published CVEs carry `poc`, the supply a PoC-conditioned "
          "hazard would act on.", ""] + table(
        sv, [s for s in ("active", "poc", "none", "(not assessed)") if s in sv], "exploitation")
    auto = tally(lambda r: r["ssvc_automatable"] or "(not assessed)")
    L += ["", "## By SSVC automatable", ""] + table(
        auto, [s for s in ("yes", "no", "(not assessed)") if s in auto], "automatable")

    pk = lambda cells: {n: (c[0], c[1]) for n, c in cells.items()}
    L += ["", "## How much composition a single population rate misses", "",
          "Share of KEV additions that one population-wide rate assigns to the wrong class "
          "(half the summed absolute difference between observed and expected additions). "
          "This is the baseline a stratified calibration has to beat without being fitted "
          "to it.", "", "| partition | classes | misallocated |", "|---|---:|---:|",
          f"| exposure | {len(ex)} | {misallocation(pk(ex)):.1%} |",
          f"| vendor (top {len(top)} + 2) | {len(ve)} | {misallocation(pk(ve)):.1%} |",
          f"| vendor × exposure | {len(both)} | {misallocation(pk(both)):.1%} |",
          f"| severity | {len(sev)} | {misallocation(pk(sev)):.1%} |", ""]

    md = ROOT / f"cve_stratification_{as_of}.md"
    md.write_text("\n".join(L))
    out = DATA / f"cve_stratification_{as_of}.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["vendor", "exposure", "published", "kev_added_in_window",
                    "published_in_window_and_in_kev"])
        for v in vendors:
            for e in EXPOSURES:
                w.writerow([v, e, *both.get((v, e), (0, 0, 0))])
    print("\n".join(L))
    print(f"\nwrote {md.name} and {out.relative_to(ROOT)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="full sweep by publication date")
    b.add_argument("--start", required=True)
    b.add_argument("--end", required=True)
    b.add_argument("--fresh", action="store_true", help="discard the existing table first")
    sub.add_parser("update", help="refresh rows NVD modified since the last sync")
    r = sub.add_parser("report", help="write the stratification tables; no network")
    r.add_argument("--as-of")
    r.add_argument("--window-days", type=int, default=365)
    r.add_argument("--top", type=int, default=20)
    args = ap.parse_args()
    {"build": build, "update": update, "report": report}[args.cmd](args)
