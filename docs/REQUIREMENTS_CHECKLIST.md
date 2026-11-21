# Requirements Checklist

Extracted from the assignment guide. "Code" ticks mean the requirement is implemented and covered by an
automated test. "Group" items can only be completed by the team.

## Tool: Part A (setup)

| Requirement | Where | Status |
|-------------|-------|--------|
| Ed25519 key pair via the library | `cmd_setup` | ✅ Code |
| Private key encrypted (PEM/PKCS8/BestAvailableEncryption) | `cmd_setup` | ✅ Code |
| Passphrase via hidden `getpass`, twice; empty and mismatch rejected | `prompt_new_passphrase` | ✅ Code (+ 8-char minimum) |
| Private key owner-only permissions | `write_new_file(..., 0o600)` | ✅ Code (Linux; not enforced on Windows) |
| Public key in the verifier folder; registry entry `enabled: true` | `cmd_setup` | ✅ Code |
| Existing registry entries preserved | `cmd_setup` | ✅ Code |
| Refuse to overwrite keys or an existing registration; check before asking | `cmd_setup` | ✅ Code |
| Never print the key or passphrase | `cmd_setup` | ✅ Code |

## Tool: Part B (sign)

| Requirement | Where | Status |
|-------------|-------|--------|
| SHA-256 of every file, including subfolders, in chunks | `sha256_file`, `scan_payload` | ✅ Code |
| Relative, forward-slash, sorted paths | `scan_payload`, `build_manifest_bytes` | ✅ Code |
| manifest.json with publisher_id, release_name, files[path, sha256] | `build_manifest_bytes` | ✅ Code |
| Serialise once; sign and write the same bytes | `build_manifest_bytes`, `cmd_sign` | ✅ Code |
| signature.sig = raw 64 bytes | `cmd_sign` | ✅ Code |
| Wrong/empty passphrase: clear error, nothing written | `load_private_key`, `cmd_sign` | ✅ Code |
| Symlink policy consistent with verify | `scan_payload` | ✅ Code (symlink test runs on Linux only) |

## Tool: Part C (verify)

| Requirement | Where | Status |
|-------------|-------|--------|
| Check 1: files exist, JSON valid, required fields → INVALID_MANIFEST | `check_1_manifest` | ✅ Code |
| Check 2: registry lookup, enabled → UNKNOWN_PUBLISHER / PUBLISHER_DISABLED | `check_2_publisher` | ✅ Code |
| Registry re-read every run; fail closed | `check_2_publisher` | ✅ Code (`REGISTRY_ERROR`, lecturer to confirm) |
| Check 3: registry key, raw bytes → BAD_SIGNATURE | `check_3_signature` | ✅ Code |
| Check 4: `..`, leading `/` → UNSAFE_PATH, before any payload file is read | `check_4_paths` | ✅ Code |
| Check 5: MISSING_FILE → EXTRA_FILE → HASH_MISMATCH | `check_5_payload` | ✅ Code |
| Stop at first failure; ACCEPTED only at the end; clear reasons | `cmd_verify`, `finish_verify` | ✅ Code |

## Tool: Part D (log)

| Requirement | Where | Status |
|-------------|-------|--------|
| One JSON line per sign/verify attempt, including failures | `log_event` | ✅ Code |
| Six fields; UTC ISO-8601 with offset | `log_event` | ✅ Code |
| No secrets logged; logging failure only warns | `log_event` | ✅ Code |

## Rules

| Rule | Status |
|------|--------|
| Payload never executed/imported/extracted | ✅ Code reads bytes only |
| Fabricated sample files only | ✅ `release_A/payload` |
| No private key/passphrase in Git or the ZIP | ✅ `.gitignore`; ☐ Group: grep check on the final ZIP |
| Library crypto only | ✅ |

## Deliverables (Group)

| Item | Status |
|------|--------|
| `release_A` signed on the golden VM (formal T2) and committed with `verifier/` | ☐ |
| Formal T1–T10 run with labelled screenshots | ☐ |
| PDF report (4–6 pages + cover + appendices) | ☐ |
| Source ZIP built with `git archive` and clean-room tested | ☐ |
| 3–5 min MP4 demo with the five required scenes | ☐ |
| Lecturer questions answered and recorded in the README | ☐ |
| Contribution statement and AI prompt log complete | ☐ |
| Every member can explain and trace the code | ☐ |
| Optional fingerprint bonus | Not implemented (attempt only if the freeze is clean) |

## Open decisions for the lecturer

1. Are extra reason codes allowed (`REGISTRY_ERROR`, `BAD_PASSPHRASE`, `MISSING_KEY`, `INVALID_RELEASE`)?
2. Is a single file required? (We use one file plus a test-only helper in `tests/`.)
3. Does the AI prompt appendix count towards the page limit?
4. Live demo format and date; submission portal and closing time; group number.
