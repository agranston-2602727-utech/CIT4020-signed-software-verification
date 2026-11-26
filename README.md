# release_guard: Signed Software Release Verification

CIT4020 Computer Security · Group Lab Project (Assignment 2) · Group **6** *(Anthony x Quan) +3*

## 1. Overview

`release_guard.py` is a Python 3 command-line tool for the fictional client **HarbourView Business Systems Ltd.** It lets a software publisher sign a release, and lets the client check that the release really came from a trusted publisher and has not been changed since it was signed. Every `sign` and `verify` attempt, including failures, is appended to `release_log.jsonl`.

| Command  | Who runs it | Purpose |
|----------|-------------|---------|
| `setup`  | Publisher, once | Creates an Ed25519 key pair. The private key is saved **encrypted** (passphrase typed at a hidden prompt) in `publisher_keys/`. The public key and a registry entry (`enabled: true`) go into the client's `verifier/` folder. Refuses to overwrite existing keys. |
| `sign`   | Publisher, per release | Hashes every file in `<release>/payload/` (SHA-256), writes `manifest.json`, and signs the exact bytes of that manifest into `signature.sig`. |
| `verify` | Client (HarbourView) | Runs five checks **in order** and prints `ACCEPTED` only if all pass; otherwise `REJECTED - <REASON>` with details. |

---

## 2. Requirements and setup

Python 3.9 or newer on **Kali Linux or Ubuntu**, run from a terminal inside a virtual environment.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd CIT4020-signed-software-verification   # the project root (where release_guard.py is)
python3 -m venv .venv                     # create the environment (once)
source .venv/bin/activate                 # activate it (every new terminal); prompt shows (.venv)
pip install -r requirements.txt           # installs the pinned cryptography version
```

`requirements.txt` pins `cryptography==50.0.2`.

---

## 3. Commands and expected output

### setup (once per publisher)

```text
$ python3 release_guard.py setup --publisher-id harbourview
New passphrase for the private key:
Repeat the passphrase:
SETUP COMPLETE for publisher 'harbourview'
  encrypted private key : publisher_keys/harbourview_private.pem   (SECRET - never share or commit)
  public key            : verifier/keys/harbourview_public.pem
  registry entry added  : verifier/trusted_publishers.json  (enabled: true)
```

### sign

```text
$ python3 release_guard.py sign --publisher-id harbourview --release release_A
Passphrase for the 'harbourview' private key:
SIGNED 'release_A' as publisher 'harbourview'
  files hashed : 3
  manifest     : release_A/manifest.json
  signature    : release_A/signature.sig (64 bytes)
```

### verify

```text
$ python3 release_guard.py verify --release release_A
Verifying 'release_A' against registry 'verifier/trusted_publishers.json'
  check 1 passed: manifest.json and signature.sig present, JSON valid, required fields present
  check 2 passed: publisher is in the trusted registry and enabled
  check 3 passed: signature is valid under the REGISTRY's public key
  check 4 passed: no unsafe paths in the manifest; no symlinks/special files in payload/
  check 5 passed: all listed files present, no extra files, every hash matches
ACCEPTED: 'release_A' from publisher 'harbourview' passed all five checks.

$ python3 release_guard.py verify --release scratch/release_T5
Verifying 'scratch/release_T5' against registry 'verifier/trusted_publishers.json'
  check 1 passed: manifest.json and signature.sig present, JSON valid, required fields present
  check 2 passed: publisher is in the trusted registry and enabled
REJECTED - BAD_SIGNATURE (check 3): signature.sig does not match the bytes of manifest.json under the registered key of 'harbourview'
```

`ACCEPTED` appears only when all five checks pass. A rejection names the failing reason code and check number.

---

## 4. Quick start for the marker

The ZIP contains the signed `release_A/` and the **public** side of the trust store
(`verifier/trusted_publishers.json` + `verifier/keys/harbourview_public.pem`). It does **not**
contain the private key. After the setup in section 2, choose one of the two paths below.

### Path A: verify the included signed `release_A` (no keys needed)

```bash
python3 release_guard.py verify --release release_A          # expect ACCEPTED
cp -a release_A /tmp/release_check
echo "#" >> /tmp/release_check/payload/app.py
python3 release_guard.py verify --release /tmp/release_check # expect REJECTED - HASH_MISMATCH (check 5)
```

### Path B: start from scratch (setup → sign → verify)

The included registry already lists `harbourview`, so running `setup --publisher-id harbourview`
is **refused** (`SETUP REFUSED: ... already exists`). That is the overwrite protection working, not a bug.
To start from scratch, use a different publisher id and separate folders, so the shipped registry is left untouched:

```bash
mkdir -p /tmp/rg/myrelease && cp -a release_A/payload /tmp/rg/myrelease/
python3 release_guard.py setup  --publisher-id marker --keys-dir /tmp/rg/keys --verifier-dir /tmp/rg/verifier
python3 release_guard.py sign   --publisher-id marker --release /tmp/rg/myrelease --keys-dir /tmp/rg/keys --log /tmp/rg/log.jsonl
python3 release_guard.py verify --release /tmp/rg/myrelease --verifier-dir /tmp/rg/verifier --log /tmp/rg/log.jsonl   # expect ACCEPTED
```

`setup` and `sign` both ask for a passphrase at a hidden prompt; use the same one for both.
To remove everything afterwards, run `rm -rf /tmp/rg /tmp/release_check`.

---

## 5. Design decisions

| Decision | What we chose |
|----------|---------------|
| Signature format | `signature.sig` is the raw 64-byte Ed25519 signature (nothing to decode), made over the exact bytes of `manifest.json` as written to disk. |
| Multi-failure policy | Checks run in a fixed order: 1 manifest -> 2 publisher -> 3 signature -> 4 paths -> 5 payload. The first failing check wins, and only that reason is reported. Inside check 5 the order is `MISSING_FILE`, then `EXTRA_FILE`, then `HASH_MISMATCH`. |
| Symlink policy | Not allowed. `sign` refuses a payload that contains symlinks or special files; `verify` rejects it with `UNSAFE_PATH` (check 4). |

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

The extra codes still need the lecturer's approval. If extras are not allowed,
`REGISTRY_ERROR` would become `UNKNOWN_PUBLISHER`, a one-line change in `check_2_publisher`.

---

## 6. Known limitations

- **The registry is the root of trust.** Anyone who can edit `verifier/` can add themselves or swap a public key, and their releases will be accepted. The bonus key fingerprint is not implemented.
- **No rollback protection.** The manifest has no version number or expiry, so an older, validly signed release is still accepted.
- **A stolen private key plus its passphrase** lets the thief sign releases that pass every check. The only response is to disable or remove the publisher and issue a new key.
- **The log is not tamper-evident.** It is a plain append-only text file that anyone with write access can edit.
- **A valid signature proves who and unchanged, not safe.** It says nothing about whether the software is harmless.
- On Windows, `0600` permissions on the private key are not enforced. Use the Linux VM.
