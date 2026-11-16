# Stashed impact-ledger batches

201 KEV entries added in 2026 that have not been researched, in 13 batch files grouped by vendor.
Stashed 2026-11-16 because the session's web-search limit (200 calls, ~100/hour refill) could not
cover them; they need roughly 2-4 searches each.

To resume: move the batch files back up one directory and give each to a researcher with
`../BRIEF.md`, writing `result_<nn>.json` beside the batch. Then run
`python3 impact_ledger.py --snapshot 2026-11-16` from the repository root. Raise
`CLAUDE_CODE_MAX_WEB_SEARCHES_PER_SESSION` to about 1,000 first.
