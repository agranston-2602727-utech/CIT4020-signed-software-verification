# Demo Video Guide (3–5 minutes) and Live-Demo Preparation

**Lead:** M3 · **Narration:** M1, M2 · **Script review:** M4 · **Record only after the code freeze.**

Required on screen (from the brief): **clean acceptance, modified-file rejection, unknown-publisher
rejection, disabled-publisher rejection, and the log file.**

---

## 1. Pre-stage everything (before you press record)

Run this off camera so the recording is one smooth take:

```bash
source .venv/bin/activate
export PS1='\$ '
rm -rf scratch/release_T* scratch/other_* && rm -f release_log.jsonl
# second publisher in scratch folders, plus its signed copy (for the unknown-publisher scene)
python3 release_guard.py setup --publisher-id otherpub --keys-dir scratch/other_keys --verifier-dir scratch/other_verifier
cp -a release_A scratch/release_other
python3 release_guard.py sign --publisher-id otherpub --release scratch/release_other --keys-dir scratch/other_keys
rm -f release_log.jsonl            # start the on-camera log clean
cp verifier/trusted_publishers.json scratch/registry_backup.json
clear
```

Large terminal font, 1080p, notifications off, nothing private visible (no usernames, no passphrase).

## 2. Shot list and suggested narration (about 4:15)

| Time | Scene | On screen | Say (in your own words) |
|------|-------|-----------|-------------------------|
| 0:00–0:20 | Intro | `ls`, `ls release_A/payload -R` | "Group XX. release_guard checks HarbourView updates with three commands: setup, sign, verify." |
| 0:20–1:00 | Clean acceptance | `python3 release_guard.py sign --publisher-id harbourview --release release_A --release-name "HarbourView lab release 1.0"` (hidden prompt) → `cat release_A/manifest.json` → `wc -c release_A/signature.sig` → `python3 release_guard.py verify --release release_A` | "The passphrase prompt shows nothing. The manifest lists each file's SHA-256, the signature is 64 bytes, and all five checks pass: ACCEPTED." |
| 1:00–1:50 | Modified file | `cp -a release_A scratch/release_T3` → `echo "#" >> scratch/release_T3/payload/app.py` → verify | "The signature still matches the manifest, so check 3 passes. But app.py's bytes no longer match its hash: HASH_MISMATCH at check 5." |
| 1:50–2:40 | Unknown publisher | `cat verifier/trusted_publishers.json` → `cat scratch/release_other/manifest.json \| grep publisher_id` → `python3 release_guard.py verify --release scratch/release_other` | "This release is validly signed, but by otherpub, who is not in our registry. A valid signature is not enough: UNKNOWN_PUBLISHER at check 2." |
| 2:40–3:30 | Disabled publisher | `sed -i 's/"enabled": true/"enabled": false/' verifier/trusted_publishers.json` → `cat` → verify `release_A` → `sed -i 's/"enabled": false/"enabled": true/' ...` → verify again | "Disabling harbourview rejects even its genuine release with PUBLISHER_DISABLED, before the signature is checked. Re-enabled: ACCEPTED." |
| 3:30–4:05 | The log | `cat release_log.jsonl` | "One line per attempt with six fields: time in UTC, operation, release, publisher, result, reason. No keys or passphrases." |
| 4:05–4:20 | Wrap-up | — | "Hash: did it change? Signature: who made it? Registry: do we trust them? M1 built setup and sign, M2 verify, M3 tested, M4 the report." |

After recording: `cmp verifier/trusted_publishers.json scratch/registry_backup.json` should confirm the registry was restored.

## 3. Recording checklist

- [ ] Recorded on the **frozen** commit (`git rev-parse --short HEAD` matches the report).
- [ ] Rehearsed twice with a timer.
- [ ] Screen recorder: OBS Studio, the VM's recorder, or a meeting app. Export **MP4**. If you get MKV: `ffmpeg -i in.mkv -c copy CIT4020_GroupXX_Demo.mp4`.
- [ ] Duration check: `ffprobe -v error -show_entries format=duration -of csv=p=0 CIT4020_GroupXX_Demo.mp4` gives 180–300.
- [ ] Narration is audible; the terminal text is readable at 1080p.
- [ ] No passphrase typed into a command line, no private key content shown.
- [ ] If the code changes after recording: **re-record**.

## 4. Live demo: your own two minutes (8 marks)

Each member prepares answers to: *What did I build or write? Which functions or sections? Why did we design it that way?
What bug or mistake did I hit, and how did I fix it? What would I improve?*

## 5. Question drills (6 marks): predict, then run to check

| If the examiner… | What happens, which check, and why |
|------------------|------------------------------------|
| changes one character in `app.py` | HASH_MISMATCH, check 5. The manifest and signature are untouched, so checks 1–4 pass |
| edits `release_name` | BAD_SIGNATURE, check 3. The signed bytes changed even though the hashes are right |
| deletes `signature.sig` | INVALID_MANIFEST, check 1, with no traceback |
| drops their public key into the release folder | No effect. Keys come only from the registry |
| sets `enabled: false` | PUBLISHER_DISABLED, check 2, before the signature is examined |
| sets `enabled: "true"` (a string) | PUBLISHER_DISABLED. The code uses `is True`, not truthiness |
| replaces the registry's public key with theirs and signs | ACCEPTED. The registry is the root of trust (residual risk, T10d) |
| deletes or corrupts the registry | REGISTRY_ERROR, check 2. Fails closed |
| asks why check 4 comes after check 3 | Authenticate the manifest before trusting its contents; sanitise paths before opening any payload file |
| asks what happens if two things are wrong | The first failing check wins; within check 5, MISSING > EXTRA > HASH |
| asks where the private key is and how it is protected | `publisher_keys/`, encrypted PKCS8 PEM, mode 0600; passphrase only at the hidden prompt, never stored |
| asks what the hashes add if the manifest is signed | The signature covers the manifest; the hashes tie it to the actual file contents |

Answer in three beats: **claim → reason → which check/line in the code.**
