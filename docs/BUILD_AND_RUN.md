# Build and Run Guide

Target: **Python 3** on **Kali Linux or Ubuntu**, run from a terminal inside a virtual environment.
Every command below uses the real flags of `release_guard.py` (check with `--help`).

---

## 1. Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

- `python3`: the interpreter. Any 3.9 or newer works. We developed on 3.15 and you should test on your VM's version.
- `python3-venv`: creates an isolated environment, which avoids the "externally-managed-environment" pip error on Kali/Debian.
- `git`: version control. The ZIP is also built from it.

## 2. Check the Python version

```bash
python3 --version          # e.g. Python 3.12.x
```

## 3–6. Create and activate a virtual environment, then install dependencies

```bash
cd Signed-Release-Verification     # the project root (where release_guard.py is)
python3 -m venv .venv              # create the environment (once)
source .venv/bin/activate          # activate it (every new terminal); prompt shows (.venv)
pip install -r requirements.txt    # installs the pinned cryptography version
```

`.venv/` is in `.gitignore`. Never commit it or put it in the ZIP.

## 7. Verify the cryptography installation

```bash
pip show cryptography | head -n 2
python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; print('ok')"
```

If the installed version differs from `requirements.txt`, run the tests and update the pin to what you tested.

## 8. Application help

```bash
python3 release_guard.py --help
python3 release_guard.py setup --help
python3 release_guard.py sign --help
python3 release_guard.py verify --help
```

## 9. setup (Part A, once per publisher)

```bash
python3 release_guard.py setup --publisher-id harbourview
```

- Asks for a passphrase twice at a **hidden** prompt. Nothing is shown as you type, which is normal.
- The passphrase must be at least 8 characters, and both entries must match.
- Creates `publisher_keys/harbourview_private.pem` (encrypted, owner-only permissions),
  `verifier/keys/harbourview_public.pem`, and a registry entry with `"enabled": true` in `verifier/trusted_publishers.json`.
- Running it again for the same id is **refused** and changes nothing.

Optional flags: `--keys-dir DIR` (where the private key goes) and `--verifier-dir DIR` (where the registry and public key go).

## 10. sign (Part B)

```bash
python3 release_guard.py sign --publisher-id harbourview --release release_A \
        --release-name "HarbourView lab release 1.0"
```

- Asks for the passphrase (hidden) and unlocks the key **before** writing anything.
- Hashes every file in `release_A/payload/`, including subfolders, then writes `release_A/manifest.json` and `release_A/signature.sig` (64 bytes).
- A wrong or empty passphrase prints `SIGN FAILED - BAD_PASSPHRASE` and writes nothing.

Optional flags: `--release-name` (defaults to the folder name), `--keys-dir DIR`, `--log FILE`.

## 11. verify (Part C)

```bash
python3 release_guard.py verify --release release_A
echo $?            # 0 = ACCEPTED, 1 = REJECTED
```

Optional flags: `--verifier-dir DIR` (which registry to trust) and `--log FILE`.

## 12. Where the generated files are

| File | Created by | Side | Secret? |
|------|-----------|------|---------|
| `publisher_keys/<id>_private.pem` | setup | Publisher | **Yes**: encrypted, never committed or shipped |
| `verifier/keys/<id>_public.pem` | setup | Client | No |
| `verifier/trusted_publishers.json` | setup (then edited by the client admin) | Client | No, but must be protected from tampering |
| `<release>/manifest.json` | sign | Travels with the release | No |
| `<release>/signature.sig` | sign | Travels with the release | No |
| `release_log.jsonl` | sign and verify | Wherever you run the tool | No secrets inside |

## 13. Understanding the output

**verify** prints one line per check as it passes, then exactly one result line:

```text
Verifying 'release_A' against registry 'verifier/trusted_publishers.json'
  check 1 passed: manifest.json and signature.sig present, JSON valid, required fields present
  check 2 passed: publisher is in the trusted registry and enabled
REJECTED - BAD_SIGNATURE (check 3): signature.sig does not match the bytes of manifest.json under the registered key of 'harbourview'
```

- The "check N passed" lines show how far verification got. They are **not** acceptance.
- `ACCEPTED` appears only when all five checks pass.
- `REJECTED - <CODE> (check N): <detail>` names the failing check and says what was wrong (which file, which path).

**Log line** (`cat release_log.jsonl`):

```json
{"time_utc": "2026-11-20T19:13:08+00:00", "operation": "verify", "release": "release_T3", "publisher_id": "harbourview", "result": "REJECTED", "reason": "HASH_MISMATCH"}
```

## 14. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `error: externally-managed-environment` from pip | You are not in the venv. Run `source .venv/bin/activate`. |
| `ModuleNotFoundError: No module named 'cryptography'` | The venv isn't active, or `pip install -r requirements.txt` was not run. |
| `SETUP REFUSED: ... already exists` | Working as designed: keys are never overwritten. To start again on purpose, follow TESTING_GUIDE T1 "clean state" (this destroys the old key). |
| `SIGN FAILED - MISSING_KEY` | No private key for that id in `--keys-dir`. Run setup, or pass the right `--keys-dir`. |
| `SIGN FAILED - BAD_PASSPHRASE` | Wrong or empty passphrase. If it is lost, the key is unusable: re-run setup **in a clean state** and re-sign, but only before the code freeze. |
| `SIGN FAILED - UNSAFE_PATH` | The payload contains a symlink, which is not allowed. Replace it with a real file. |
| `REJECTED - REGISTRY_ERROR` | `verifier/trusted_publishers.json` is missing or not valid JSON. The tool fails closed. Fix the registry. |
| `release_A` verifies on Windows but gives `HASH_MISMATCH` on Linux | Git converted line endings. `.gitattributes` prevents this; re-clone after it is committed. |
| `ImportError: DLL load failed ... filename or extension is too long` (Windows) | The project path is too long for Windows. Create the venv in a short path such as `C:\venvs\rg`. |
| Passphrase prompt shows a warning "Can not control echo" | You are running inside an IDE output pane, not a real terminal. Use a real terminal; never record a demo that way. |
| The private key is readable by others (`ls -l` is not `-rw-------`) | It was created on a filesystem without Unix permissions (e.g. a shared folder). Run on the VM's own disk. |

## 15. Running the automated tests

```bash
python3 -m unittest discover -s tests -v
```

These run every T1–T10 scenario in temporary folders with a stubbed passphrase and never touch your real keys.
They are a development aid only. The formal evidence comes from [TESTING_GUIDE.md](TESTING_GUIDE.md).
