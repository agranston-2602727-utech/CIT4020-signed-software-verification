## Cover Page
--- 
# Project Overview
HarbourView Business Systems Ltd project is a command-line tool, `release_guard.py`. The tool lets a software publisher sign a release, and lets a client check that the release really came from a trusted publisher and hasn't been changed since it was signed

### The Workflow has three steps:
1. `setup` creates an Ed25519 key pair for a publisher. The private keys is encrypted with a passphrase and stays on the publisher's side. The public key and a registry entry go into the client's trust store. 
2. `sign` computes a SHA-256 hash of every file in the release's `payload/` folder. It writes the hashes to `manifest.json` and signs those exact bytes into `signature.sig`. 
3. `verify` runs five checks in order and stops at the first failure: 
	1. The manifest and signature exist and are valid. 
	2. The publisher is in the registry and enabled.
	3. The signature is valid under the public key from the registry, never a key shipped with the release. 
	4. No manifest path can escape `payload/`, and the folder has no symlinks or special files 
	5. Every listen file is present, there are no extra files, and every hash matches.

>**NOTE THAT:**
>The release is marked ACCEPTED only if all five pass. Otherwise it is strict safety rules: payload file are only read, never run; the passphrase is never stored or logged; and if the registry can't be read, verify rejects the release instead of accepting it.

--- 
# Risk Analysis

| #   | Threat                                                                                                                          | Security control the tool uses                                                                                                                                                                                                                                                                                                                                                                      | Remaining Risk                                                                                                                                                                                                                                                                                                               |
| --- | :------------------------------------------------------------------------------------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Fake Publisher:** <br>An attacker ships a release signed with their own key, or includes their own public key in the release. | Check 2 accepts only publishers listen and `enabled: true` in the client's registry. The test is `is true`, so a string like `"false"` doesn't count as enabled. Check 3 verifies the signature using the public key named the public key named in the **registry**, never a key that comes with the release. Unknown publishers get `UNKNOWN_PUBISHER` and disabled ones get `PUBLISHER_DISABLED`. | Trust depends on how the public key first reached the registry. If an attacker's key is registered during setup, or someone registers the wrong key by mistake, their releases will pass. Nothing checks the key's fingerprint out of band.                                                                                  |
| 2   | **Modified, added or removed payload files:** <br>For example malware is slipped into a release after signing.                  | `sign` hashes every file with SHA-256 and sign the exact bytes of the manifest using Ed25519. <br>Check 5 rejects with `MISSING_FILE`, `EXTRA_FILE` or `HASH_MISMATCH`, and compares hashes with `hmac.compare_digest`. <br>Check 4 blocks `..`, absolute paths, backslashes, drive letters and symlinks (`UNSAFE_PATH`).                                                                           | **Time-of-check to Time-of-use:**<br>A file could swapped after verify accepts it but before it is installed. Verify also can't tell whether the publisher signed bad code on purpose or by accident. And an old, validly signed release can be replayed, because there is no version or expiry check.                       |
| 3   | **Stolen Private Key:**<br>Someone copies the key file from the publisher's machine.                                            | The private key is encrypted with a passphrase of at least 8 characters, entered at a hidden `getpass` prompt and never stored or logged. The key files is created with `0o600` permissions using `0_EXCL`, so it is never overwritten. Setup also refuses to put the keys folder inside the verifier folder.                                                                                       | Anyone with the file can try to guess the passphrase using offline cracking methods, and 8 characters may be weak. If the passphrase is also leaked, the attacker can sign releases until the publisher is set to disabled by hand. There is no revocation list and no key rotation. On Windows, `0o600` is largely ignored. |
| 4   | **Tampered or corrupted registry:**<br>An attacker edits `trusted_publishers.json` to add their key or re-enable a publisher.   | The registry is re-read from disk on every verify, with no caching. If it is missing, corrupt or the wrong shape, verify **fails closed** with `REGISTRY_ERROR`, and it does the same for duplicate publisher entries. Setup refuses to modify a registry it can't read.                                                                                                                            | The registry itself isn't signed or integrity-protected. Anyone who can write to the verifier folder can add a trusted publisher or swap a public key, and verify will then accept their releases. Its security rests entirely on the client machine's file permissions.                                                     |

--- 
# Design 

The three commands of `release_guard.py` are shown below as flowcharts. Each one follows the same pattern: run every check in order, stop at the first failure, and pass through a single exit point that sets the exit code (and, for `sign` and `verify`, writes one line to the log).

### 1. Setup

`release_guard.py setup`: CHECK, then ASK, then WRITE, so a refusal changes nothing.

```mermaid
flowchart TD
    START(["START<br>setup --publisher-id &lt;id&gt;"])
    U1{"keys folder outside<br>the verifier folder?"}
    U2{"no existing private or<br>public key for this id?"}
    U3{"registry missing, or<br>a readable JSON list?"}
    U4{"publisher not already<br>in the registry?"}
    U5{"passphrase (hidden, twice)<br>long enough and matching?"}
    GEN["Generate Ed25519 key pair (library)<br>Encrypt private key with passphrase (PKCS8 PEM)"]
    WRITE["Write private key to publisher_keys/ (mode 600)<br>Write public key to verifier/keys/<br>Add registry entry: publisher_id, public_key_path, enabled: true"]
    OK(["SETUP COMPLETE"])

    X1["private key must never<br>sit on the client side"]
    X2["keys never overwritten"]
    X3["registry unreadable,<br>left unchanged"]
    X4["already registered"]
    X5["bad passphrase"]

    REF(["SETUP REFUSED<br>(any red box above)"])
    EXIT["Exit 0 = complete, 1 = refused<br>Passphrase never echoed, saved or logged"]
    END(["END"])

    START --> U1
    U1 -- yes --> U2 -- yes --> U3 -- yes --> U4 -- yes --> U5
    U5 -- yes --> GEN --> WRITE --> OK

    U1 -- no --> X1
    U2 -- no --> X2
    U3 -- no --> X3
    U4 -- no --> X4
    U5 -- no --> X5

    X1 ~~~ X2 ~~~ X3 ~~~ X4 ~~~ X5 ~~~ REF

    OK --> EXIT
    REF -. "every refusal" .-> EXIT
    EXIT --> END

    classDef term fill:#dbe8f5,stroke:#333,color:#000
    classDef check fill:#fff2cc,stroke:#333,color:#000
    classDef step fill:#ffffff,stroke:#333,color:#000
    classDef reject fill:#f8d7da,stroke:#333,color:#000
    classDef ok fill:#d5f0d9,stroke:#333,color:#000
    classDef exit fill:#e6e6e6,stroke:#333,color:#000
    class START,END term
    class U1,U2,U3,U4,U5 check
    class GEN,WRITE step
    class X1,X2,X3,X4,X5,REF reject
    class OK ok
    class EXIT exit
```

### 2. Sign

`release_guard.py sign`: nothing is written unless every step passes.

```mermaid
flowchart TD
    START(["START<br>sign --publisher-id &lt;id&gt; --release &lt;folder&gt;"])
    S1{"payload/ is a real<br>folder (not a symlink)?"}
    S2{"private key file exists<br>for this publisher?"}
    S3{"payload/ free of symlinks<br>and special files?"}
    S4{"payload/ has at<br>least one file?"}
    ASK["Ask passphrase at hidden prompt (getpass)"]
    S5{"private key unlocks<br>with passphrase?"}
    S6{"every file read and<br>SHA-256 hashed?"}
    BUILD["Build manifest bytes once (sorted)"]
    WRITE["Sign those exact bytes with Ed25519<br>Write manifest.json (same bytes)<br>Write signature.sig (raw 64 bytes)"]
    OK(["SIGNED"])

    F1["INVALID_RELEASE"]
    F2["MISSING_KEY"]
    F3["UNSAFE_PATH"]
    F4["INVALID_RELEASE<br>(empty payload)"]
    F5["BAD_PASSPHRASE<br>(nothing written)"]
    F6["INVALID_RELEASE<br>(unreadable file)"]

    FAIL(["SIGN FAILED<br>(any red box above)"])
    LOG["Log one line to release_log.jsonl<br>(SIGNED / OK, or FAILED / reason)<br>Exit 0 = signed, 1 = failed<br>Passphrase and keys never logged"]
    END(["END"])

    START --> S1
    S1 -- yes --> S2 -- yes --> S3 -- yes --> S4 -- yes --> ASK --> S5
    S5 -- yes --> S6 -- yes --> BUILD --> WRITE --> OK

    S1 -- no --> F1
    S2 -- no --> F2
    S3 -- no --> F3
    S4 -- no --> F4
    S5 -- no --> F5
    S6 -- no --> F6

    F1 ~~~ F2 ~~~ F3 ~~~ F4 ~~~ F5 ~~~ F6 ~~~ FAIL

    OK --> LOG
    FAIL -. "every failure" .-> LOG
    LOG --> END

    classDef term fill:#dbe8f5,stroke:#333,color:#000
    classDef check fill:#fff2cc,stroke:#333,color:#000
    classDef step fill:#ffffff,stroke:#333,color:#000
    classDef reject fill:#f8d7da,stroke:#333,color:#000
    classDef ok fill:#d5f0d9,stroke:#333,color:#000
    classDef exit fill:#e6e6e6,stroke:#333,color:#000
    class START,END term
    class S1,S2,S3,S4,S5,S6 check
    class ASK,BUILD,WRITE step
    class F1,F2,F3,F4,F5,F6,FAIL reject
    class OK ok
    class LOG exit
```


### 3. Verify: the five checks

`release_guard.py verify`: five checks in order (first failing check wins, then stop).

```mermaid
flowchart TD
    START(["START<br>verify --release &lt;folder&gt;"])
    C1a{"1a · manifest.json and<br>signature.sig exist?"}
    C1b{"1b · manifest is<br>valid UTF-8 JSON?"}
    C1c{"1c · required fields<br>well formed, no<br>duplicate paths?"}
    RAW["Keep RAW manifest bytes + signature<br>Read publisher_id (not yet trusted)"]
    C2a{"2a · registry readable<br>and a JSON list?"}
    C2b{"2b · publisher_id<br>in registry?"}
    C2c{"2c · exactly one<br>entry for it?"}
    C2d{"2d · enabled is True?<br>(strict, not truthy)"}
    C3a{"3a · registry public key<br>loads as Ed25519?"}
    C3b{"3b · signature valid over<br>RAW manifest bytes?"}
    C4a{"4a · every manifest<br>path safe?"}
    C4b{"4b · payload/ free of<br>symlinks / special files?"}
    SETS["listed = paths in manifest<br>present = regular files in payload/"]
    C5a{"5a · every listed<br>file present?"}
    C5b{"5b · no unlisted<br>files in payload/?"}
    C5c{"5c · every SHA-256<br>matches manifest?"}
    ACC(["ACCEPTED<br>(only place it is produced)"])

    R1a["INVALID_MANIFEST<br>(file is missing)"]
    R1b["INVALID_MANIFEST<br>(not valid JSON)"]
    R1c["INVALID_MANIFEST<br>(wrong or missing field)"]
    R2a["REGISTRY_ERROR<br>(fail closed)"]
    R2b["UNKNOWN_PUBLISHER"]
    R2c["REGISTRY_ERROR<br>(duplicate entry)"]
    R2d["PUBLISHER_DISABLED"]
    R3a["BAD_SIGNATURE<br>(trusted key unusable)"]
    R3b["BAD_SIGNATURE"]
    R4a["UNSAFE_PATH<br>(.., leading /, backslash,<br>drive letter, escapes payload/)"]
    R4b["UNSAFE_PATH<br>(symlink or special file)"]
    R5a["MISSING_FILE"]
    R5b["EXTRA_FILE"]
    R5c["HASH_MISMATCH<br>(names the file)"]

    REJ(["REJECTED<br>(any red box above)"])
    FIN["finish_verify() — single exit point<br>Print ACCEPTED / REJECTED + reason + check no.<br>Append one line to release_log.jsonl<br>Exit 0 = ACCEPTED, 1 = REJECTED"]
    END(["END"])

    START --> C1a
    C1a -- yes --> C1b -- yes --> C1c -- yes --> RAW --> C2a
    C2a -- yes --> C2b -- yes --> C2c -- yes --> C2d -- yes --> C3a
    C3a -- yes --> C3b -- yes --> C4a -- yes --> C4b -- yes --> SETS --> C5a
    C5a -- yes --> C5b -- yes --> C5c -- yes --> ACC

    C1a -- no --> R1a
    C1b -- no --> R1b
    C1c -- no --> R1c
    C2a -- no --> R2a
    C2b -- no --> R2b
    C2c -- no --> R2c
    C2d -- no --> R2d
    C3a -- no --> R3a
    C3b -- no --> R3b
    C4a -- no --> R4a
    C4b -- no --> R4b
    C5a -- no --> R5a
    C5b -- no --> R5b
    C5c -- no --> R5c

    R1a ~~~ R1b ~~~ R1c ~~~ R2a ~~~ R2b ~~~ R2c ~~~ R2d ~~~ R3a ~~~ R3b ~~~ R4a ~~~ R4b ~~~ R5a ~~~ R5b ~~~ R5c ~~~ REJ

    ACC --> FIN
    REJ -. "every failure" .-> FIN
    FIN --> END

    classDef term fill:#dbe8f5,stroke:#333,color:#000
    classDef check fill:#fff2cc,stroke:#333,color:#000
    classDef step fill:#ffffff,stroke:#333,color:#000
    classDef reject fill:#f8d7da,stroke:#333,color:#000
    classDef ok fill:#d5f0d9,stroke:#333,color:#000
    classDef exit fill:#e6e6e6,stroke:#333,color:#000
    class START,END term
    class C1a,C1b,C1c,C2a,C2b,C2c,C2d,C3a,C3b,C4a,C4b,C5a,C5b,C5c check
    class RAW,SETS step
    class R1a,R1b,R1c,R2a,R2b,R2c,R2d,R3a,R3b,R4a,R4b,R5a,R5b,R5c,REJ reject
    class ACC ok
    class FIN exit
```


--- 
# Test Results 

---

### Group (6) Main Objective
 - Build the tool (`setup`, `sign`, `verify`, followed by logging);
 - Test the tool with 10 Tiers ranging from Tier 1 - Tier 10, document screenshot based on these test.
 - Write a report inclusive of (risk analysis, design, results, reflection, contributions, AI declaration);
 - Submit a source ZIP and a 3 - 4 Minute DEMO Video;
 - **Every Member** explain the code in a live demo 
 
--- 

## How signed release verifications works three layers 

| Layer                           | What it does                                                                                                                                                       | What it cannot do Alone                                                                                |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------- |
| **HASH (SHA-256)**              | A 64-hex-character fingerprint of a file's exact bytes. Change one byte and the hash changes completely.                                                           | It has no secret, so an attacker can compute a matching hash for their altered file.                   |
| **Digital Signature (Ed25519)** | The publisher's private key signs the manifest (the list of hashes). Anyone with the **public  key** can check it, but only the private-key holder can produce it. | It cannot say whether the key belongs to someone you should trust; an attacker can with their own key. |
| **Trust Decision (Registry)**   | The Client's own list of approved publishers and their public keys, with an on/off switch.                                                                         | It is only as safe as the registry file itself.                                                        |
## Key ideas in one line each

 - **SHA-256:** A one-way function. It is easy to compute and practically impossible to find two files with the same hash. 
 - **Ed25519:** A modern elliptic-curve signature scheme with 64-byte signatures, fast and hard to misuse. We use the `cryptography` (based on recommendations from Claude) library's implementation, never or our own library.
 - **Private Key:** Stays with the publisher, encrypted with a passphrase. Whoever holds it is the publisher.
 - **Public Key:** Given to clients. It can only check signatures, not make them.
 - **Trusted Publisher:** A registry entry `{publisher_id, public_key_path, enables}` on the client's side. 
 - **Manifest:** `manifest.json`, which lists every payload file with its SHA-256. Signing the manifest indirectly signs every file through its hash. 

## Project Workflow
 
```text
Publisher: setup (once) => sign release_A/ (payload + manifest + signature)
Client: (receives public key + registry entry out of band) => verify release_A
```

### Part A: Setup & Keys

**GOAL:**
A one-time command that create an ED25519 key pair, saves the encrypted private key using a passphrase from a hidden prompt), then saves the public key in verifier folder, that creates `trusted_publishers.json` and refuses to overwrite Existing keys.

**Why Does this matters:**
The private key is the publisher's identity. Whoever holds it can sign anything the client will accept. Encrypting the private key means a stolen file alone isn't enough, and refusing to overwrite means a slip of the keyboard can't destroy the only key create by the publisher.

### Part B: Sign a Release 

**What is the Release** 
A release is a folder that holds a software version a publisher wants to ship to the client (HarbourView)

``` text 
release_A/
├── payload/              ← the publisher's actual files (e.g. app.py)
├── manifest.json         ← created by 'sign'
└── signature.sig         ← created by  'sign'
```

**GOAL:**


**Why does this matters:**
The manifest turns "a folder of files" into one small, signable statement. Once the manifest is sign every file through it's hash is also signed. The catch is that the signature is over bytes, not over "The same JSON".

### Part C: Verify a Release 

**GOAL:**
Run five checks **in order.** Print **Accepted** only if every check passes; otherwise print **REJECTED** and the reason, and stop at the first failure.

**The Five(5) Checks 'In order':**

| #   | Check                                                                           |             Rejection Reason              | What it protects, and what it reads                                                                                        |
| :-- | ------------------------------------------------------------------------------- | :---------------------------------------: | :------------------------------------------------------------------------------------------------------------------------- |
| 1   | `mainfest.json` and `signture.sig` exit; JSON readable; required fields present |             INVALID_MANIFEST              | `release_guard.py`: The junk input must produce a clean rejection, not a crash. Reads the two release files as raw bytes.  |
| 2   | `publisher_id` is in the registry and `enabled`                                 |  UNKNOWN_PUBLISHER / PUBLISHER_DISABLED   | **Whose** key to trust, a client-side decision. Reads the registry.                                                        |
| 3   | Signature valid using the public key **from the registry**                      |               BAD_SIGNATURE               | That the manifest is unchanged and was made by the key holder. Reads the registry's public key and the raw manifest bytes. |
| 3   | No manifest path contains `..` or starts with  `/`                              |                UNSAFE_PATH                | Stops the tool reading files outside `payload/` even if the manifest is validly signed. Reads only manifest text.          |
| 5   | Every listed files exists, no extras, every recomputed hash matches             | MISSING_FILE / EXTRA_FILE / HASH_MISMATCH | That the real payload matches what was signed. The only check that touches **`payload/`**                                  |
**The logic of the order:**
Structure comes first, because if the data isn't parsed then the data can't be used. 
- Identity comes before the signature check, because the registry's key is needed to check the signature. 
- Authenticity comes before trusting the manifest's contents (**`an unauthenticated manifest is an attcker-controlled text`**). Path safety comes before any payload file is opened. (Edit here and check the project plan document).

## Part D: Log 
**GOAL:**
Append one line to `release_log.json` for **every sign or verify attempt:** UTC time, operation, release folder, `publisher_id`, result, reason. Publishers should never log keys or passphrases.