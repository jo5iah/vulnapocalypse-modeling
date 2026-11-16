# Impact-ledger research inputs

One directory per snapshot. Each holds the KEV entries as they were handed to researchers
(`batch_*.json`), what came back (`result_*.json`), the research brief (`y2026/BRIEF.md`) and the
entries not yet researched (`y2026/stashed/`). `impact_ledger.py` in the repository root merges the
result files into `impact_ledger_<snapshot>.md` and `data/impact_ledger_<snapshot>.json`.

`result_0..3.json` are the October-November pilot and predate the `campaign` and `primary_opened`
fields. Records marked `"incomplete": true` were written when a researcher ran out of search budget;
the assembler ignores them, and a rerun (`result_r*.json`) supersedes an earlier record only if it
ran more searches. Quotes were read through a summarizing fetch tool and need checking against the
source before publication.
