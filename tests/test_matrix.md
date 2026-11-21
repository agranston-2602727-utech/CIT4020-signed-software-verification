# Test Matrix (M3)

Maps every brief test to the check it targets, the expected outcome, the evidence, and the matching
automated regression test. Step-by-step commands: [../docs/TESTING_GUIDE.md](../docs/TESTING_GUIDE.md).

| Test | Scenario | Copy used | Targets | Expected | Screenshots | Automated test (dev aid) |
|------|----------|-----------|---------|----------|-------------|--------------------------|
| T1 | setup from clean state; second setup | n/a | Part A | ENCRYPTED header; second run refused, identical sha256 | T1_01..03 | `T1Setup.*` |
| T2 | sign release_A, verify | `release_A` | Parts B, C, D | 64-byte sig; manifest hashes = sha256sum; ACCEPTED; 2 log lines | T2_01..04 | `T2CleanRelease.*` |
| T3 | append one char to app.py | `scratch/release_T3` | check 5 | REJECTED HASH_MISMATCH (app.py) | T3_01..02 | `test_T3_*` |
| T4a | delete config/settings.ini | `scratch/release_T4a` | check 5 | REJECTED MISSING_FILE | T4_01 | `test_T4a_*` |
| T4b | add config/extra.ini | `scratch/release_T4b` | check 5 | REJECTED EXTRA_FILE | T4_02 | `test_T4b_*` |
| T5 | edit release_name, no re-sign | `scratch/release_T5` | check 3 | REJECTED BAD_SIGNATURE | T5_01..02 | `test_T5_*` |
| T6 | flip 1 byte of signature.sig | `scratch/release_T6` | check 3 | REJECTED BAD_SIGNATURE | T6_01..02 | `test_T6_*` |
| T7 | second publisher in scratch folders | `scratch/release_T7` | check 2 | REJECTED UNKNOWN_PUBLISHER; real registry unchanged | T7_01..03 | `test_T7_*` |
| T8 | enabled false → true | `release_A` | check 2 | PUBLISHER_DISABLED, then ACCEPTED | T8_01..02 | `test_T8_*` |
| T9 | wrong + empty passphrase at sign | `scratch/release_T9` | Part B | BAD_PASSPHRASE, no traceback, files unchanged, logged | T9_01..03 | `T9Passphrase.*` |
| T10a | attacker key claims harbourview | `scratch/release_T10a` | check 3 | *prediction first* | T10_01.. | `test_T10a_*` |
| T10b | validly signed `../outside.txt` | `scratch/release_T10b` | check 4 | *prediction first* | T10_0x | `test_T10b_*` |
| T10c | malformed JSON / missing sig | `scratch/release_T10c` | check 1 | *prediction first* | optional | `test_T10c_*` |
| T10d | swapped registry key (scratch verifier) | scratch | trust model | *prediction first* | optional | `test_T10d_*` |
| T10e | symlink in payload | scratch | check 4 | *prediction first* | optional | `test_symlink_policy` (Linux only) |

Extra automated cases (no formal test needed): passphrase rules at setup, registry missing or corrupt
(`REGISTRY_ERROR`), string `"true"` in `enabled`, truncated or empty signature, duplicate path, absolute/backslash
paths, empty payload, priority MISSING > EXTRA > HASH, usage error exit code 2.
