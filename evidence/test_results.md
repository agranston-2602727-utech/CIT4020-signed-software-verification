# Formal Test Results (T1–T10)

> **Fill in ONLY from the formal run on the frozen code.** Never write "Actual" before running,
> never change "Expected" afterwards, never copy results from the automated tests or from AI output.
> A failed test is recorded as **Fail**, then re-tested in a separate row with the new commit hash.

- **Frozen code commit:** `‹git rev-parse --short HEAD›`
- **Run by:** ‹M3 name› · **Date/time (UTC):** ‹…› · **Machine:** ‹golden VM, OS, Python version, cryptography version›

| Test | Action (one line) | Expected result | Actual result | Pass/Fail | Figures |
|------|-------------------|-----------------|---------------|-----------|---------|
| T1 | setup from clean state; show key header; setup again | Header ENCRYPTED; second setup refused; sha256 identical | | | T1-1..3 |
| T2 | sign release_A; show manifest, sig size; verify; show log | ACCEPTED; sig 64 bytes; log lines written | | | T2-1..4 |
| T3 | copy; append 1 char to app.py; verify | REJECTED HASH_MISMATCH | | | T3-1..2 |
| T4a | copy; delete config/settings.ini; verify | REJECTED MISSING_FILE | | | T4-1 |
| T4b | copy; add config/extra.ini; verify | REJECTED EXTRA_FILE | | | T4-2 |
| T5 | copy; edit release_name, no re-sign; verify | REJECTED BAD_SIGNATURE | | | T5-1..2 |
| T6 | copy; change 1 byte of signature.sig; verify | REJECTED BAD_SIGNATURE | | | T6-1..2 |
| T7 | second publisher in scratch folders; sign copy; verify vs real registry | REJECTED UNKNOWN_PUBLISHER | | | T7-1..3 |
| T8 | enabled=false, verify; enabled=true, verify | PUBLISHER_DISABLED, then ACCEPTED | | | T8-1..2 |
| T9 | sign copy with wrong, then empty passphrase | Clear error, no crash, files unchanged | | | T9-1..3 |
| T10a | ‹your scenario› | ‹prediction, committed at ‹time/hash› before running› | | | T10-… |
| T10b | ‹your scenario› | ‹prediction› | | | T10-… |

## T10 prediction record (write and commit BEFORE running)

- **Scenario:**
- **Prediction (which check, which code, why):**
- **Prediction committed at:** ‹commit hash / time›
- **Actual output:**
- **Explanation / was the prediction right?:**

## Defects found and fixed

| Found in | Symptom | Fix (commit) | Re-test result |
|----------|---------|--------------|----------------|
| | | | |
