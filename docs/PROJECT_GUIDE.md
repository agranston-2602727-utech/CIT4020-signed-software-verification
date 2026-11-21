# Project Guide

Start here. After reading this you should understand what the tool does, why it does it in this
order, and how the files and team roles fit together.

---

## 1. Purpose and objectives

HarbourView Business Systems Ltd. (fictional) used to accept software updates if "the folder name
looks right". That proves nothing: anyone can name a folder. `release_guard.py` replaces that with a
cryptographic check. The assignment (CIT4020, 20% of the course) asks the group to:

- build the tool (`setup`, `sign`, `verify`, plus a log);
- test it with T1–T10 and honest, labelled screenshots;
- write a 4–6 page report (risk analysis, design, results, reflection, contributions, AI declaration);
- submit a source ZIP and a 3–5 minute demo video;
- have **every member** explain the code in a live demo (20 individual marks).

## 2. How signed release verification works: three layers

| Layer | What it does | What it **cannot** do alone |
|-------|--------------|-----------------------------|
| **Hash (SHA-256)** | A 64-hex-character fingerprint of a file's exact bytes. Change one byte and the hash changes completely. | It has no secret, so an attacker can compute a matching hash for their altered file. |
| **Digital signature (Ed25519)** | The publisher's **private key** signs the manifest (the list of hashes). Anyone with the **public key** can check it, but only the private-key holder can produce it. | It cannot say whether the key belongs to someone you *should* trust; an attacker can sign with their own key. |
| **Trust decision (registry)** | The client's own list of approved publishers and their public keys, with an on/off switch. | It is only as safe as the registry file itself. |

Verification stacks the three: **is this publisher approved → did they really sign this manifest →
do the files match the manifest?**

### Key ideas in one line each

- **SHA-256**: a one-way function. It is easy to compute and practically impossible to find two files with the same hash.
- **Ed25519**: a modern elliptic-curve signature scheme with 64-byte signatures, fast and hard to misuse. We use the `cryptography` library's implementation, never our own.
- **Private key**: stays with the publisher, encrypted with a passphrase. Whoever holds it *is* the publisher.
- **Public key**: given to clients. It can only check signatures, not make them.
- **Trusted publisher**: a registry entry `{publisher_id, public_key_path, enabled}` on the client's side.
- **Manifest**: `manifest.json`, which lists every payload file with its SHA-256. Signing the manifest indirectly signs every file through its hash.

## 3. The workflow

```text
Publisher:  setup (once)  ->  sign release_A  ->  ship release_A/ (payload + manifest + signature)
Client:     (receives public key + registry entry out of band, once)  ->  verify release_A
```

## 4. The five verification checks

| # | Check | Rejection | Reads |
|---|-------|-----------|-------|
| 1 | `manifest.json` and `signature.sig` exist; JSON valid; fields and types correct | `INVALID_MANIFEST` | the two release files (raw bytes) |
| 2 | `publisher_id` is in the registry and `enabled` is `true` | `UNKNOWN_PUBLISHER` / `PUBLISHER_DISABLED` (`REGISTRY_ERROR` if the registry is unusable) | the registry |
| 3 | Signature valid over the raw manifest bytes using the **registry's** public key | `BAD_SIGNATURE` | the registry key and the manifest bytes |
| 4 | No path contains `..` or starts with `/` (plus `\`, drive letters, resolve check); no symlinks | `UNSAFE_PATH` | manifest text, and directory listing |
| 5 | All listed files present, none extra, every hash matches | `MISSING_FILE` / `EXTRA_FILE` / `HASH_MISMATCH` | payload bytes |

The first failing check wins. `ACCEPTED` is printed only after check 5 passes.
See [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) for the flowchart and the reasons for the order.

## 5. Folder structure

```text
release_guard.py            the tool
requirements.txt            cryptography==<tested version>
README.md                   exact commands, design decisions, reason codes
.gitignore / .gitattributes keep secrets out of Git; keep release bytes exact
publisher_keys/             PUBLISHER side - encrypted private key(s). SECRET. Not in Git or the ZIP
verifier/                   CLIENT side - trusted_publishers.json + keys/<id>_public.pem
release_A/                  the clean signed sample release - never edited after signing
  payload/                  app.py, config/settings.ini, release_notes.txt (fabricated data)
  manifest.json             written by sign
  signature.sig             written by sign (64 bytes)
tests/                      automated tests, test matrix, copy workflow, T10b helper
evidence/                   formal test results and screenshots (T1..T10)
docs/                       these guides
reports/                    final PDF / ZIP / MP4 before upload
scratch/                    throwaway test copies (ignored by Git)
release_log.jsonl           generated log (ignored by Git)
```

## 6. Who does what

| Member | Role | Owns |
|--------|------|------|
| **M1** | Developer A, "Signer" | Part A setup, Part B sign, Part D log helper, README, requirements, source ZIP |
| **M2** | Developer B, "Verifier" | Part C verify (all five checks), log wiring in verify, clean-room ZIP test, optional bonus |
| **M3** | Security tester | `release_A`, copy workflow, T1–T10 dry and formal runs, screenshots, demo video |
| **M4** | Risk & report lead, coordinator | Risk analysis, design and flowchart, reflection, PDF assembly, contributions, AI log, lecturer questions, submission |

Details: [ROLE_RESPONSIBILITIES.md](ROLE_RESPONSIBILITIES.md). **Everyone** must be able to explain
the whole tool and trace any check through the code.

## 7. How the components work together

- `cmd_setup` writes the key files and registry that `cmd_sign` (private key) and `cmd_verify` (public key + registry) later read.
- `cmd_sign` and `check_5_payload` both use `sha256_file` and `scan_payload`, so a file hashes the same way on both sides.
- `cmd_verify` runs `VERIFY_CHECKS` in order; each check stores what later checks need in `ctx`
  (raw manifest bytes → check 3, registry entry → check 3, present files → check 5).
- `finish_verify` and `cmd_sign`'s `fail()` both call `log_event`, so every attempt is logged.

## 8. Expected behaviour (quick reference)

| Situation | Result |
|-----------|--------|
| Clean signed release | `ACCEPTED` (exit 0) |
| One payload byte changed | `HASH_MISMATCH`, check 5 |
| File deleted / file added | `MISSING_FILE` / `EXTRA_FILE`, check 5 |
| Manifest edited | `BAD_SIGNATURE`, check 3 |
| Signature byte flipped | `BAD_SIGNATURE`, check 3 |
| Publisher not in registry | `UNKNOWN_PUBLISHER`, check 2 |
| `enabled: false` | `PUBLISHER_DISABLED`, check 2 |
| Wrong or empty passphrase at sign | `SIGN FAILED - BAD_PASSPHRASE`, nothing written |
| Second setup for the same id | `SETUP REFUSED`, nothing changed |

## 9. Security restrictions (non-negotiable)

1. Never run, import, install or extract the payload files. Only read their bytes.
2. Use fabricated files only.
3. The passphrase is entered only at the hidden prompt. It is never hard-coded, saved, logged, or passed as an argument.
4. The private key never goes into Git, the ZIP, screenshots or chat.
5. The verification key always comes from the registry, never from the release.
6. All cryptography comes from the library; no home-made algorithms.
7. Never fabricate test results or screenshots.
8. Log every AI prompt in [AI_PROMPT_LOG.md](AI_PROMPT_LOG.md).
