# Testing Guide: T1–T10

**Owner:** M3 (Security tester) · **Fixes:** M1 / M2 · **Rubric:** "Testing and evidence", 15 marks

This guide gives the exact commands for every test, using the real flags of
`release_guard.py`. Run everything from the project root on the **golden VM**
(Kali/Ubuntu), inside the activated venv (`source .venv/bin/activate`).

> **Honesty rule (from the brief):** never fabricate results or screenshots. Fill the
> "Actual" column only from what the terminal showed you. If a test fails, record
> **Fail**, explain why, get it fixed, and record the re-test as a separate row with the
> new commit hash. An honest failure followed by a fix earns more than a faked pass.

---

## 0. Before you start

### 0.1 Two kinds of test run

| Run | When | Code | Evidence? |
|-----|------|------|-----------|
| **Dry run** | During development, as features land | Latest commit | No. Produces a bug list for M1/M2 |
| **Formal run** | After the code freeze (G5) | The frozen commit only | **Yes**: screenshots plus results table |

Automated regression tests (`python3 -m unittest discover -s tests -v`) are a development aid.
They exercise the same scenarios but are **not** the formal evidence.

### 0.2 Evidence rules

- **Fresh copy per test:** `cp -a release_A scratch/release_T3`. Never edit `release_A/` after it is signed.
- **Screenshot names:** `T3_01_edit.png`, `T3_02_verify.png`, and so on, saved in `evidence/screenshots/T3/`.
- **Each screenshot shows the command and its full output**, terminal font at least 14 pt, cropped tight.
- **Show "before" evidence** (`cat`, `sha256sum`, `ls -l`) so the reader can see what changed.
- **Fill the results row immediately** in `evidence/test_results.md`. Never change "Expected" after seeing "Actual".
- **Record the frozen commit:** `git rev-parse --short HEAD` at the top of `evidence/test_results.md`.

### 0.3 Terminal set-up for screenshots

```bash
source .venv/bin/activate
export PS1='\$ '        # short prompt: keeps screenshots clean and hides user/host names
clear
```

### 0.4 Reset helpers

```bash
# remove all scratch test copies and scratch publishers (safe: scratch/ is not tracked)
rm -rf scratch/release_T* scratch/other_* scratch/attacker_* scratch/*.json scratch/*.orig
```

---

## T1: Setup and key generation

**Objective:** setup creates an encrypted Ed25519 key, the public key and a registry entry,
and a second run refuses without changing anything.

**Preconditions:** clean state (no keys, empty registry). For the formal run, do this once at the start:

```bash
rm -f publisher_keys/*.pem verifier/keys/*.pem release_log.jsonl
echo '[]' > verifier/trusted_publishers.json
rm -f release_A/manifest.json release_A/signature.sig
```

**Commands:**

```bash
python3 release_guard.py setup --publisher-id harbourview     # type the lab passphrase twice (no echo)
head -n 1 publisher_keys/harbourview_private.pem              # expect: -----BEGIN ENCRYPTED PRIVATE KEY-----
ls -l publisher_keys/ verifier/keys/                          # private key: -rw------- (0600)
cat verifier/trusted_publishers.json
sha256sum publisher_keys/harbourview_private.pem              # BEFORE
python3 release_guard.py setup --publisher-id harbourview     # second run: must refuse
echo "exit code: $?"                                          # expect 1
sha256sum publisher_keys/harbourview_private.pem              # AFTER: identical
```

**Expected:** first run `SETUP COMPLETE`; header says `ENCRYPTED`; second run
`SETUP REFUSED: ... already exists`, exit 1, identical hash before and after, and no passphrase prompt on the second run.

**Evidence:** `T1_01_setup.png` (hidden prompt plus result), `T1_02_header.png` (`head -n 1`, `ls -l`, registry),
`T1_03_refusal.png` (sha256sum before, refusal, sha256sum after).

**Optional extra cases:** empty passphrase, mismatched passphrases, and a passphrase under 8 characters. Each gives `SETUP REFUSED`.

---

## T2: Clean release: sign, then verify

**Objective:** signing produces a correct manifest and a 64-byte signature; verify gives ACCEPTED; both are logged.

```bash
python3 release_guard.py sign --publisher-id harbourview --release release_A \
        --release-name "HarbourView lab release 1.0"
cat release_A/manifest.json
sha256sum release_A/payload/app.py release_A/payload/config/settings.ini release_A/payload/release_notes.txt
wc -c release_A/signature.sig                                 # expect 64
python3 release_guard.py verify --release release_A
cat release_log.jsonl
```

**Expected:** `SIGNED`; the three hashes in the manifest equal the `sha256sum` output;
`64 release_A/signature.sig`; `ACCEPTED`; log has a `sign/SIGNED/OK` line and a `verify/ACCEPTED/OK` line.

**Evidence:** `T2_01_sign.png`, `T2_02_manifest_hashes.png`, `T2_03_verify.png`, `T2_04_log.png`.

> After the formal T2, `release_A/` and `verifier/` are the signed versions that go into the
> ZIP. Commit them (`git add release_A verifier && git commit -m "Sign release_A (formal run)"`).
> `.gitignore` keeps `publisher_keys/` out.

---

## T3: Modified payload file

```bash
cp -a release_A scratch/release_T3
tail -n 2 scratch/release_T3/payload/app.py
sha256sum scratch/release_T3/payload/app.py                   # BEFORE
echo "#" >> scratch/release_T3/payload/app.py                 # append one character
tail -n 2 scratch/release_T3/payload/app.py
sha256sum scratch/release_T3/payload/app.py                   # AFTER (different)
python3 release_guard.py verify --release scratch/release_T3
```

**Expected:** `REJECTED - HASH_MISMATCH (check 5): ... app.py`. Checks 1–4 print "passed", because the manifest and signature are untouched.

**Evidence:** `T3_01_edit.png`, `T3_02_verify.png`.

---

## T4: Missing file and extra file (two copies)

```bash
# T4a - missing file
cp -a release_A scratch/release_T4a
ls -R scratch/release_T4a/payload                             # BEFORE
rm scratch/release_T4a/payload/config/settings.ini
ls -R scratch/release_T4a/payload                             # AFTER
python3 release_guard.py verify --release scratch/release_T4a

# T4b - extra file, inside a subfolder
cp -a release_A scratch/release_T4b
ls -R scratch/release_T4b/payload                             # BEFORE
echo "unlisted" > scratch/release_T4b/payload/config/extra.ini
ls -R scratch/release_T4b/payload                             # AFTER
python3 release_guard.py verify --release scratch/release_T4b
```

**Expected:** T4a `REJECTED - MISSING_FILE (check 5): ... config/settings.ini`;
T4b `REJECTED - EXTRA_FILE (check 5): ... config/extra.ini`.

**Evidence:** `T4_01_missing.png`, `T4_02_extra.png`.

---

## T5: Modified manifest (not re-signed)

```bash
cp -a release_A scratch/release_T5
grep release_name scratch/release_T5/manifest.json            # BEFORE
sed -i 's/HarbourView lab release 1.0/HarbourView lab release 9.9/' scratch/release_T5/manifest.json
grep release_name scratch/release_T5/manifest.json            # AFTER
python3 release_guard.py verify --release scratch/release_T5
```

**Expected:** `REJECTED - BAD_SIGNATURE (check 3)`. Checks 1 and 2 pass. Every file hash is still correct, but the signed bytes changed.

**Evidence:** `T5_01_edit.png`, `T5_02_verify.png`.

---

## T6: One corrupted signature byte

```bash
cp -a release_A scratch/release_T6
cp scratch/release_T6/signature.sig scratch/T6_signature.orig
xxd -s 10 -l 1 scratch/release_T6/signature.sig               # see the current byte at offset 10
printf '\x00' | dd of=scratch/release_T6/signature.sig bs=1 seek=10 count=1 conv=notrunc
#   if the byte at offset 10 was already 00, use printf '\xff' instead
cmp -l scratch/T6_signature.orig scratch/release_T6/signature.sig   # exactly one differing byte
wc -c scratch/release_T6/signature.sig                        # still 64
python3 release_guard.py verify --release scratch/release_T6
```

**Expected:** `REJECTED - BAD_SIGNATURE (check 3)`.

**Evidence:** `T6_01_byte_change.png` (`xxd`/`cmp`), `T6_02_verify.png`.

---

## T7: Unknown publisher

A second publisher is set up in **scratch** folders, so the real registry is never touched.

```bash
sha256sum verifier/trusted_publishers.json                    # real registry BEFORE
python3 release_guard.py setup --publisher-id otherpub \
        --keys-dir scratch/other_keys --verifier-dir scratch/other_verifier
cp -a release_A scratch/release_T7
python3 release_guard.py sign --publisher-id otherpub --release scratch/release_T7 \
        --keys-dir scratch/other_keys
cat verifier/trusted_publishers.json                          # real registry: no otherpub
cat scratch/other_verifier/trusted_publishers.json            # otherpub only here
python3 release_guard.py verify --release scratch/release_T7  # against the REAL registry
sha256sum verifier/trusted_publishers.json                    # real registry AFTER: unchanged
```

Optional, and useful for the report: `python3 release_guard.py verify --release scratch/release_T7 --verifier-dir scratch/other_verifier`
gives ACCEPTED. The signature is valid, but the client doesn't trust that key.

**Expected:** `REJECTED - UNKNOWN_PUBLISHER (check 2): publisher 'otherpub' is not in the trusted registry`.

**Evidence:** `T7_01_second_publisher.png`, `T7_02_registries.png`, `T7_03_verify.png`.

---

## T8: Disabled publisher, then re-enabled

```bash
cp verifier/trusted_publishers.json scratch/registry_backup.json
sed -i 's/"enabled": true/"enabled": false/' verifier/trusted_publishers.json
cat verifier/trusted_publishers.json
python3 release_guard.py verify --release release_A           # expect PUBLISHER_DISABLED
sed -i 's/"enabled": false/"enabled": true/' verifier/trusted_publishers.json
cat verifier/trusted_publishers.json
python3 release_guard.py verify --release release_A           # expect ACCEPTED
cmp verifier/trusted_publishers.json scratch/registry_backup.json && echo "registry restored"
```

(You may edit the file with `nano` instead of `sed`. Either way, show `cat` each time.)

**Expected:** `REJECTED - PUBLISHER_DISABLED (check 2): ... enabled = false`, then `ACCEPTED`.
The registry is re-read on every run; there is no caching.

**Evidence:** `T8_01_disabled.png`, `T8_02_reenabled.png`.

---

## T9: Wrong and empty passphrase

```bash
cp -a release_A scratch/release_T9
ls -l --time-style=full-iso scratch/release_T9/manifest.json scratch/release_T9/signature.sig
sha256sum scratch/release_T9/manifest.json scratch/release_T9/signature.sig      # BEFORE
python3 release_guard.py sign --publisher-id harbourview --release scratch/release_T9   # type a WRONG passphrase
python3 release_guard.py sign --publisher-id harbourview --release scratch/release_T9   # just press Enter (empty)
ls -l --time-style=full-iso scratch/release_T9/manifest.json scratch/release_T9/signature.sig
sha256sum scratch/release_T9/manifest.json scratch/release_T9/signature.sig      # AFTER: identical
tail -n 2 release_log.jsonl                                                       # two FAILED / BAD_PASSPHRASE lines
```

**Expected:** `SIGN FAILED - BAD_PASSPHRASE: the private key could not be unlocked ... Nothing was written.`
There is no traceback, exit code is 1, timestamps and hashes are unchanged, and both attempts are logged.

**Evidence:** `T9_01_before.png`, `T9_02_wrong_and_empty.png`, `T9_03_after.png`.

---

## T10: Custom security test (write the prediction FIRST)

Before running anything, write your prediction in `evidence/test_results.md` and commit it
(`git commit -m "T10 prediction"`). The commit time is your timestamp. We recommend two variants.

### T10a: Attacker's own key claims to be `harbourview`

*Think first:* which public key does check 3 use? What does claiming the approved id actually get the attacker?

```bash
python3 release_guard.py setup --publisher-id harbourview \
        --keys-dir scratch/attacker_keys --verifier-dir scratch/attacker_verifier   # attacker's own folders
cp -a release_A scratch/release_T10a
echo "# attacker change" >> scratch/release_T10a/payload/app.py
python3 release_guard.py sign --publisher-id harbourview --release scratch/release_T10a \
        --keys-dir scratch/attacker_keys
grep publisher_id scratch/release_T10a/manifest.json          # claims harbourview
python3 release_guard.py verify --release scratch/release_T10a
```

**Our implementation gives:** `REJECTED - BAD_SIGNATURE (check 3)`. Check 2 passes because the id *is* approved,
but the registry's harbourview key does not validate the attacker's signature.

### T10b: Validly signed path traversal `../outside.txt`

*Prediction trap:* if you only edit the manifest, check 3 fires first (BAD_SIGNATURE). To reach check 4 the hostile manifest
must be **validly signed**, as if by a careless or compromised trusted publisher. The test-only helper
`tests/t10_sign_custom_manifest.py` does exactly that, with the same library calls as `sign`.

```bash
cp -a release_A scratch/release_T10b
python3 -c "import json; m=json.load(open('release_A/manifest.json')); m['files'].append({'path':'../outside.txt','sha256':'0'*64}); open('scratch/T10b_manifest.json','w').write(json.dumps(m, indent=2)+'\n')"
grep -n outside scratch/T10b_manifest.json
python3 tests/t10_sign_custom_manifest.py --publisher-id harbourview \
        --release scratch/release_T10b --manifest-in scratch/T10b_manifest.json
python3 release_guard.py verify --release scratch/release_T10b
```

**Our implementation gives:** checks 1–3 pass, then `REJECTED - UNSAFE_PATH (check 4): manifest path '../outside.txt' contains '..'`.
No payload file is opened.

### Other options (T10c–e)

| Variant | Commands (on a fresh copy) | Our implementation gives |
|---------|----------------------------|--------------------------|
| T10c malformed JSON | `echo '{oops' > scratch/release_T10c/manifest.json` | INVALID_MANIFEST (check 1), `publisher_id` null in log |
| T10c missing signature | `rm scratch/release_T10c/signature.sig` | INVALID_MANIFEST (check 1) |
| T10d swapped registry key | In a **scratch copy** of `verifier/`, replace `keys/harbourview_public.pem` with the attacker's, then verify T10a's release with `--verifier-dir` pointing at the copy | **ACCEPTED**: the registry is the root of trust (residual risk) |
| T10e symlink | `ln -s ../../../etc/hostname scratch/release_T10e/payload/link.txt` | UNSAFE_PATH (check 4) |

Record for each: **prediction → actual output → explanation (which check, why the earlier ones passed) → was the prediction right?**

---

## After testing

- Fill every row in `evidence/test_results.md` and copy it into the report (Section 4).
- Put the screenshots into Appendix A in test order, captioned "Figure T3-1: ...".
- Clean up: `rm -rf scratch/release_T* scratch/other_* scratch/attacker_*`.
- If **any** code changes after the formal run, re-run **all** of T1–T10 and re-check the video.

## Verifying the final application after the freeze

```bash
git status                       # clean working tree
git rev-parse --short HEAD       # record this hash in the report
python3 -m unittest discover -s tests -v
python3 release_guard.py verify --release release_A   # ACCEPTED with the committed registry
```
