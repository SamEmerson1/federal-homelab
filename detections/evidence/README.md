# Detection evidence

One folder per validated technique. Each holds:

| File | What it is |
|---|---|
| `<ID>-results.csv` / `.png` | The Splunk search over the test window, showing the detection events |
| `<ID>-alert-fired.csv` / `.png` | The scheduler log showing the saved alert firing (`result_count` > 0) |
| `<ID>-execution.csv` | The Atomic Red Team execution log for the test run |

Every number in the detection docs traces to one of these files.

**A note on the Atomic Red Team execution log:** its "Execution Time (Local)" column is labelled
with a `Z` (UTC) suffix but actually holds local time (America/Chicago, CDT). The adjacent
"Execution Time (UTC)" column is the correct UTC value. The Splunk timestamps in the results files
are CDT.
