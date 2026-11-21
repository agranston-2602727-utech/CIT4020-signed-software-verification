# release_guard: Signed Software Release Verification

CIT4020 Computer Security · Group Lab Project (Assignment 2) · Group **XX** *(fill in)*

`release_guard.py` is a Python 3 command-line tool for the fictional client
**HarbourView Business Systems Ltd.** It replaces the old update check ("the folder
name looks right") with a real one:

| Command  | Who runs it | What it does |
|----------|-------------|--------------|
| `setup`  | Publisher, once | Creates an Ed25519 key pair. The private key is saved **encrypted** (passphrase typed at a hidden prompt) in `publisher_keys/`. The public key and a registry entry (`enabled: true`) go into the client's `verifier/` folder. Refuses to overwrite existing keys. |
| `sign`   | Publisher, per release | Hashes every file in `<release>/payload/` (SHA-256), writes `manifest.json`, and signs the exact bytes of that manifest into `signature.sig` (raw 64-byte Ed25519 signature). |
| `verify` | Client (HarbourView) | Runs five checks **in order** and prints `ACCEPTED` only if all pass; otherwise `REJECTED - <REASON>` with details. |

Every `sign` and `verify` attempt, including failures, is appended to `release_log.jsonl`.

---

## 1. Requirements and installation (Kali / Ubuntu)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 release_guard.py --help
```

`requirements.txt` pins `cryptography==50.0.2`. If your VM installs another version, re-run
the tests and update the pin to the version you actually tested.

## 2. Exact commands

```bash
# Part A - create the publisher key pair and register it (run ONCE)
python3 release_guard.py setup --publisher-id harbourview

# Part B - sign a release folder that contains payload/
python3 release_guard.py sign --publisher-id harbourview --release release_A \
        --release-name "HarbourView lab release 1.0"

# Part C - verify a release
python3 release_guard.py verify --release release_A

# Part D - read the log
cat release_log.jsonl
```

All flags:

| Command | Flag | Default | Meaning |
|---------|------|---------|---------|
| setup | `--publisher-id` (required) | | Publisher id: letters, digits, `_`, `-` |
| setup | `--keys-dir` | `publisher_keys` | Publisher-side folder for the encrypted private key |
| setup | `--verifier-dir` | `verifier` | Client-side folder for `trusted_publishers.json` and `keys/` |
| sign | `--publisher-id` (required) | | Whose private key signs |
| sign | `--release` (required) | | Release folder containing `payload/` |
| sign | `--release-name` | release folder name | Value stored as `release_name` |
| sign | `--keys-dir` | `publisher_keys` | Where the private key is |
| sign | `--log` | `release_log.jsonl` | Log file |
| verify | `--release` (required) | | Release folder to check |
| verify | `--verifier-dir` | `verifier` | Which registry to trust |
| verify | `--log` | `release_log.jsonl` | Log file |

Passphrases are **never** command-line arguments. They are only typed at the hidden `getpass` prompt.

### Sample output

```text
$ python3 release_guard.py verify --release release_A
Verifying 'release_A' against registry 'verifier/trusted_publishers.json'
  check 1 passed: manifest.json and signature.sig present, JSON valid, required fields present
  check 2 passed: publisher is in the trusted registry and enabled
  check 3 passed: signature is valid under the REGISTRY's public key
  check 4 passed: no unsafe paths in the manifest; no symlinks/special files in payload/
  check 5 passed: all listed files present, no extra files, every hash matches
ACCEPTED: 'release_A' from publisher 'harbourview' passed all five checks.

$ python3 release_guard.py verify --release scratch/release_T3
  ...
  check 4 passed: no unsafe paths in the manifest; no symlinks/special files in payload/
REJECTED - HASH_MISMATCH (check 5): contents differ from the signed manifest: app.py
```

## 3. Quick start for the marker

The ZIP contains the signed `release_A/` and the **public** side of the trust store
(`verifier/trusted_publishers.json` + `verifier/keys/harbourview_public.pem`). It does **not**
contain the private key.

### Path A: verify the included signed release (no keys needed)

```bash
python3 release_guard.py verify --release release_A          # expect ACCEPTED
cp -a release_A /tmp/release_check
echo "#" >> /tmp/release_check/payload/app.py
python3 release_guard.py verify --release /tmp/release_check # expect HASH_MISMATCH
```

### Path B: start from scratch with your own publisher

The included registry already lists `harbourview`, so `setup` for that id is (correctly)
refused. Use separate folders instead:

```bash
mkdir -p /tmp/rg/myrelease && cp -a release_A/payload /tmp/rg/myrelease/
python3 release_guard.py setup  --publisher-id marker --keys-dir /tmp/rg/keys --verifier-dir /tmp/rg/verifier
python3 release_guard.py sign   --publisher-id marker --release /tmp/rg/myrelease --keys-dir /tmp/rg/keys --log /tmp/rg/log.jsonl
python3 release_guard.py verify --release /tmp/rg/myrelease --verifier-dir /tmp/rg/verifier --log /tmp/rg/log.jsonl
```

## 4. Design decisions (the group's "contract")

| Decision | What we chose |
|----------|---------------|
| CLI | `argparse` sub-commands `setup` / `sign` / `verify`; location flags so tests can use scratch folders. |
| Key files | `publisher_keys/<id>_private.pem` (PEM, PKCS8, encrypted with `BestAvailableEncryption`, mode 0600). `verifier/keys/<id>_public.pem` (PEM, SubjectPublicKeyInfo). |
| Passphrase | Hidden `getpass` prompt, asked twice at setup; empty or shorter than 8 characters refused. Never stored, printed, logged or accepted as an argument. |
| Registry | `verifier/trusted_publishers.json`: a JSON list of `{publisher_id, public_key_path, enabled}`. `public_key_path` is relative to the verifier folder. Re-read on every verify. `enabled` must be the JSON boolean `true` (the string `"true"` is not enough). |
| Manifest | `{publisher_id, release_name, files:[{path, sha256}]}`; paths relative to `payload/` with `/`, sorted; serialised once with `json.dumps(indent=2, sort_keys=True)` + newline, UTF-8. Those exact bytes are signed and written. |
| signature.sig | Raw 64-byte Ed25519 signature (nothing to decode). |
| Check order | 1 manifest -> 2 publisher -> 3 signature -> 4 paths -> 5 payload. First failing check wins. Inside check 5: `MISSING_FILE`, then `EXTRA_FILE`, then `HASH_MISMATCH`. |
| Path rule | Reject any manifest path that contains `..` (literal rule from the brief, so `notes..txt` is also rejected), starts with `/`, contains `\`, or starts with a drive letter. As defence in depth, the resolved path must stay inside `payload/`. |
| Symlinks | Not allowed. `sign` refuses a payload that contains symlinks or special files; `verify` rejects it with `UNSAFE_PATH` (check 4). |
| Empty payload / duplicates | `sign` refuses an empty payload. A manifest with an empty `files` list or a duplicate path is `INVALID_MANIFEST`. |
| Fail closed | Missing or corrupt registry -> `REGISTRY_ERROR` (never accept). Missing or corrupt public key -> `BAD_SIGNATURE`. |
| Exit codes | 0 = success / ACCEPTED, 1 = REJECTED / refused / failed, 2 = usage error. |
| Log | `release_log.jsonl`, one JSON object per line: `time_utc` (ISO-8601 UTC with offset), `operation`, `release`, `publisher_id` (null if unreadable), `result`, `reason`. Results: `SIGNED`/`FAILED` for sign, `ACCEPTED`/`REJECTED` for verify. Reason `OK` on success. |
| Line endings | `.gitattributes` stops Git rewriting `release_A/` line endings, which would break the hashes. |

### Reason codes

| Code | Command / check | Meaning |
|------|-----------------|---------|
| `INVALID_MANIFEST` | verify, check 1 | manifest.json or signature.sig missing, unreadable, bad JSON, wrong or missing fields, duplicate path |
| `UNKNOWN_PUBLISHER` | verify, check 2 | publisher_id not in the registry |
| `PUBLISHER_DISABLED` | verify, check 2 | in the registry but `enabled` is not `true` |
| `BAD_SIGNATURE` | verify, check 3 | signature does not verify under the registry key (or that key cannot be loaded) |
| `UNSAFE_PATH` | verify, check 4 / sign | path could escape `payload/`, or payload contains a symlink |
| `MISSING_FILE` | verify, check 5 | listed file not present |
| `EXTRA_FILE` | verify, check 5 | file present (any subfolder) but not listed |
| `HASH_MISMATCH` | verify, check 5 | file bytes differ from the signed hash |
| `REGISTRY_ERROR` *(extra)* | verify, check 2 | registry missing, corrupt, or lists the id twice: fail closed |
| `BAD_PASSPHRASE` *(extra)* | sign | wrong or empty passphrase; nothing written |
| `MISSING_KEY` *(extra)* | sign | no private key for this publisher id |
| `INVALID_RELEASE` *(extra)* | sign | no `payload/`, empty payload, or unreadable file |

The extra codes still need the lecturer's approval (see section 6). If extras are not allowed,
`REGISTRY_ERROR` would become `UNKNOWN_PUBLISHER`, a one-line change in `check_2_publisher`.

## 5. Tests

```bash
python3 -m unittest discover -s tests -v     # automated regression tests (development aid)
```

The **formal** T1–T10 evidence is captured by hand on the frozen code, following
[docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md). The automated tests are not a substitute for it.

## 6. Answers from the lecturer *(M4: fill in, see guide section 1.5)*

| Question | Answer |
|----------|--------|
| Live demo date / time / format, per person or per group | *TBC* |
| Submission portal and exact closing time on Nov 23 | *TBC* |
| Are extra reason codes (REGISTRY_ERROR, BAD_PASSPHRASE, ...) allowed? | *TBC* |
| Is a single file required (we use one: `release_guard.py`)? | *TBC* |
| Does the AI prompt appendix count towards the 4–6 pages? | *TBC* |
| Our group number (XX) | *TBC* |

## 7. Known limitations (honest)

- **The registry is the root of trust.** Anyone who can edit `verifier/` can add themselves or swap a public key, and their releases will be accepted (demonstrated as T10d). The bonus key fingerprint is not implemented.
- **No rollback protection.** The manifest has no version number or expiry, so an older, validly signed release is still accepted.
- **A stolen private key plus its passphrase** lets the thief sign releases that pass every check. The only response is to disable or remove the publisher and issue a new key.
- **The log is not tamper-evident.** It is a plain append-only text file that anyone with write access can edit.
- **A valid signature proves who and unchanged, not safe.** It says nothing about whether the software is harmless.
- On Windows, `0600` permissions on the private key are not enforced. Use the Linux VM.

## 8. Project layout

```text
release_guard.py            the whole tool (setup | sign | verify | log)
requirements.txt            pinned cryptography
release_A/                  sample signed release (payload/, manifest.json, signature.sig)
verifier/                   client trust store: trusted_publishers.json + keys/ (public only)
publisher_keys/             SECRET private keys - ignored by Git, never in the ZIP
tests/                      unittest suite, test matrix, workflow, T10b helper
evidence/                   test results + screenshots from the formal run
docs/                       project, build, testing, design, security, demo and report guides
reports/                    final deliverables (PDF, ZIP, MP4) before upload
scratch/                    throwaway test copies - ignored by Git
```
