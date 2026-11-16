"""Assemble the exploitation-impact ledger from per-batch research results.

Each KEV entry was researched for published counts of exposed instances, compromised hosts,
victim organizations, attack volume and downtime (brief: impact/<snapshot>/y2026/BRIEF.md).
This script merges the per-batch result files, validates them against the KEV feed, and writes

    data/impact_ledger_<snapshot>.json     every record, normalized
    impact_ledger_<snapshot>.md            yield by month, lag to KEV, campaign-level figures

    python3 impact_ledger.py --snapshot 2026-11-16

The ledger is evidence collected by web search and read through a summarizing fetch tool. Quotes
are near-verbatim, not verified against raw page text; `primary_opened` marks the figures whose
measuring organization's own page was read.
"""

import argparse
import datetime as dt
import json
import re
import statistics as st
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERDICTS = ["quantified_compromise", "exposure_only", "attack_volume_only", "qualitative_only",
            "nothing_found"]
KINDS = ["exposed", "compromised", "organizations", "attack_volume", "downtime", "other"]
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}")


def iso(value):
    """A date if the string starts with one, else None; researchers sometimes wrote prose."""
    if isinstance(value, str) and ISO.match(value):
        try:
            return dt.date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def number(value):
    """Leading numeric magnitude of an evidence value, or None for a qualitative string."""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    if ISO.search(text) or "%" in text:           # a date or a share is not a count
        return None
    m = re.search(r"(\d[\d,]*\.?\d*)\s*(million|billion|thousand|k|m)?\b", text, re.I)
    if not m:
        return None
    n = float(m.group(1).replace(",", ""))
    scale = {"thousand": 1e3, "k": 1e3, "million": 1e6, "m": 1e6, "billion": 1e9}
    return n * scale.get((m.group(2) or "").lower(), 1)


def load(snapshot):
    base = ROOT / "impact" / snapshot
    feed = {e["cveID"]: e for e in json.loads(
        (ROOT / "data" / f"cisa_kev_{snapshot}.json").read_text())["vulnerabilities"]}
    records, problems, incomplete = {}, [], set()
    for path in sorted(base.glob("result_*.json")) + sorted(base.glob("y2026/result_*.json")):
        try:
            rows = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            problems.append(f"{path.name}: invalid JSON ({exc})")
            continue
        for r in rows:
            cve = r.get("cve")
            if r.get("incomplete"):
                # written when a researcher ran out of search budget; counts as not researched
                incomplete.add(cve)
                continue
            if cve not in feed:
                problems.append(f"{path.name}: {cve} is not in the KEV feed")
                continue
            if cve in records:
                # a rerun supersedes an earlier pass only if it searched more
                if (r.get("searches_run") or 0) <= records[cve]["searches_run"]:
                    continue
            e = feed[cve]
            ev = [x for x in r.get("evidence") or [] if isinstance(x, dict)]
            for x in ev:
                if x.get("kind") not in KINDS:
                    x["kind"] = "other"
            verdict = r.get("verdict")
            if verdict not in VERDICTS:
                problems.append(f"{path.name}: {cve} verdict {verdict!r} -> qualitative_only")
                verdict = "qualitative_only"
            claim = r.get("first_exploitation_claim") or None
            records[cve] = {
                "cve": cve, "added": e["dateAdded"], "vendor": e["vendorProject"].strip(),
                "product": e["product"].strip(), "ransomware": e["knownRansomwareCampaignUse"],
                "campaign": (r.get("campaign") or "").strip(),
                "campaign_note": r.get("campaign_note") or "",
                "first_exploitation_claim": claim, "evidence": ev,
                "searches_run": r.get("searches_run") or 0, "verdict": verdict,
                "source_file": str(path.relative_to(base)),
            }
    left = sorted(incomplete - set(records))
    if left:
        problems.append(f"marked incomplete and not since rerun, excluded: {', '.join(left)}")
    return feed, records, problems


def campaign_key(r):
    """Chain-level figures are shared across CVEs, so the unit of impact is the campaign.
    Unnamed campaigns fall back to vendor + KEV date, which groups same-day chains."""
    return r["campaign"].lower() or f"{r['vendor'].lower()} {r['added']}"


def render(snapshot, feed, records, problems, year):
    snap = dt.date.fromisoformat(snapshot)
    in_year = sorted((c for c, e in feed.items() if e["dateAdded"].startswith(str(year))),
                     key=lambda c: feed[c]["dateAdded"])
    rows = [records[c] for c in in_year if c in records]
    missing = [c for c in in_year if c not in records]
    out = [f"# Exploitation-impact ledger — KEV additions in {year}, snapshot {snapshot}", ""]
    out += [f"{len(rows)} of {len(in_year)} KEV entries added in {year} researched "
            f"({sum(r['searches_run'] for r in rows):,} searches recorded). Each record is the "
            "best published evidence found for one CVE: exposed instances, compromised hosts, "
            "victim organizations, attack volume, downtime, and the earliest public claim of "
            "exploitation. Figures were collected by web search and read through a summarizing "
            "fetch tool, so quotes are near-verbatim and need checking against the source "
            "before publication.", ""]
    if missing:
        out += [f"Not researched: {len(missing)} entries (listed in the JSON).", ""]

    out += ["## Yield", "", "| best evidence | entries | share |", "|---|---:|---:|"]
    vc = Counter(r["verdict"] for r in rows)
    for v in VERDICTS:
        out.append(f"| {v.replace('_', ' ')} | {vc[v]} | {vc[v] / len(rows):.0%} |")
    kc = Counter(k for r in rows for k in {x["kind"] for x in r["evidence"]})
    out += ["", "Entries carrying at least one figure of each kind: "
            + ", ".join(f"{k.replace('_', ' ')} {kc[k]} ({kc[k] / len(rows):.0%})"
                        for k in KINDS if k != "other") + ".", ""]

    out += ["## Yield by month added", "",
            "| month | entries | compromise counted | exposure only | attack volume only "
            "| qualitative | nothing | any downtime figure |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    by_month = defaultdict(list)
    for r in rows:
        by_month[r["added"][:7]].append(r)
    for m in sorted(by_month):
        g = by_month[m]
        c = Counter(r["verdict"] for r in g)
        dn = sum(1 for r in g if any(x["kind"] == "downtime" for x in r["evidence"]))
        out.append(f"| {m} | {len(g)} | {c['quantified_compromise']} | {c['exposure_only']} | "
                   f"{c['attack_volume_only']} | {c['qualitative_only']} | {c['nothing_found']} "
                   f"| {dn} |")

    lags, undated = [], 0
    for r in rows:
        claim = r["first_exploitation_claim"]
        d = iso(claim.get("date")) if claim else None
        if d is None or (claim.get("source") or "").strip().upper().startswith("CISA KEV"):
            undated += 1
            continue
        lags.append(((dt.date.fromisoformat(r["added"]) - d).days, r["cve"]))
    out += ["", "## First public exploitation claim to KEV addition", ""]
    if lags:
        v = sorted(l for l, _ in lags)
        q = lambda p: v[min(len(v) - 1, int(p * len(v)))]
        out += [f"{len(v)} entries have a dated claim from a source other than CISA; "
                f"{undated} do not. Lag in days (KEV date − first claim): median "
                f"{st.median(v):.0f}, mean {st.mean(v):.1f}, p25 {q(.25)}, p75 {q(.75)}, "
                f"p90 {q(.9)}, max {v[-1]}. Within 3 days: {sum(x <= 3 for x in v) / len(v):.0%}; "
                f"within 28: {sum(x <= 28 for x in v) / len(v):.0%}; KEV first (negative lag): "
                f"{sum(x < 0 for x in v)}.", ""]

    camps = defaultdict(list)
    for r in rows:
        camps[campaign_key(r)].append(r)
    out += ["## Campaigns with a counted figure", "",
            f"{len(camps)} campaigns across {len(rows)} entries (chained CVEs share one "
            "campaign). Largest figure of each kind per campaign; a figure is repeated across "
            "the CVEs of a chain in the raw records and counted once here.", "",
            "| campaign | CVEs | KEV added | compromised | organizations | exposed | "
            "attack volume | downtime |", "|---|---:|---|---|---|---|---|---|"]

    def best(group, kind):
        cands = [(number(x.get("value")), x) for r in group for x in r["evidence"]
                 if x["kind"] == kind]
        if kind in ("downtime", "attack_volume") and cands:
            # durations and volumes come in mixed units; show the reported text, not a parse
            return str(cands[0][1].get("value")).replace("|", "/")[:48]
        nums = [(n, x) for n, x in cands if n is not None]
        if nums:
            n, x = max(nums, key=lambda t: t[0])
            who = (x.get("measured_by") or "").split(",")[0].split("(")[0].strip()[:28]
            return f"{n:,.0f} ({who})"
        return "stated" if cands else ""

    table = []
    for key, group in camps.items():
        cells = [best(group, k) for k in ("compromised", "organizations", "exposed",
                                          "attack_volume", "downtime")]
        if not any(cells):
            continue
        name = group[0]["campaign"] or f"{group[0]['vendor']} / {group[0]['product']}"
        table.append((min(r["added"] for r in group), name, len(group), cells))
    for added, name, n, cells in sorted(table, reverse=True):
        out.append(f"| {name[:60]} | {n} | {added} | " + " | ".join(cells) + " |")

    tot = lambda kind: sorted((number(x.get("value")) for g in camps.values()
                               for x in [max((x for r in g for x in r["evidence"]
                                              if x["kind"] == kind
                                              and number(x.get("value")) is not None),
                                             key=lambda x: number(x["value"]), default=None)]
                               if x), reverse=True)
    out += ["", "## Distribution across campaigns", ""]
    for kind in ("compromised", "organizations", "exposed"):
        v = tot(kind)
        if v:
            out.append(f"- **{kind}**: {len(v)} campaigns with a number; median "
                       f"{st.median(v):,.0f}, max {v[0]:,.0f}, min {v[-1]:,.0f}; the largest "
                       f"holds {v[0] / sum(v):.0%} of the sum.")
    prim = [x.get("primary_opened") for r in rows for x in r["evidence"]]
    if prim:
        out += ["", f"Evidence items: {len(prim)}; measuring organization's own page read for "
                f"{sum(1 for p in prim if p is True)}, quoted through a secondary for "
                f"{sum(1 for p in prim if p is False)}, not recorded for "
                f"{sum(1 for p in prim if p is None)} (the October–November pilot predates "
                "the field)."]
    if problems:
        out += ["", "## Validation notes", ""] + [f"- {p}" for p in problems]
    out.append("")
    return "\n".join(out), rows, missing


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--year", type=int, default=None)
    args = ap.parse_args()
    feed, records, problems = load(args.snapshot)
    year = args.year or int(args.snapshot[:4])
    md, rows, missing = render(args.snapshot, feed, records, problems, year)
    (ROOT / "data" / f"impact_ledger_{args.snapshot}.json").write_text(json.dumps(
        {"snapshot": args.snapshot, "year": year, "records": rows, "not_researched": missing,
         "validation": problems}, indent=1))
    (ROOT / f"impact_ledger_{args.snapshot}.md").write_text(md)
    print(md)
