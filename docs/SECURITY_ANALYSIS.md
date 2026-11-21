# Security Analysis

Reference material for M4's risk analysis. **The report must be written in the group's own
words** and backed by your own test evidence. Use this document to check facts, not as text
to paste in.

---

## 1. Security objectives

1. **Authenticity**: accept a release only if it was signed by a publisher the client has approved.
2. **Integrity**: accept it only if every payload file is byte-for-byte what was signed, with nothing missing or added.
3. **Key confidentiality**: the publisher's private key is useless to someone who only steals the file.
4. **Safe handling**: hostile input (junk manifests, traversal paths, symlinks) is rejected cleanly. Payload files are never executed.
5. **Accountability**: every sign and verify attempt leaves a log record.

## 2. Threat model

| Actor | Can | Cannot (assumed) |
|-------|-----|------------------|
| Network / distribution attacker | Change, add or remove anything inside a release folder in transit; create their own key pairs | Write to the client's `verifier/` folder; read the publisher's passphrase |
| Malicious or careless *trusted* publisher | Sign anything with a valid key | Escape `payload/` (check 4 stops this) |
| Thief of the private-key file | Copy `harbourview_private.pem` | Use it without the passphrase (except by guessing it offline) |
| Local admin on the client | Edit the registry and the log | Nothing stops them. They are inside the trust boundary |

## 3. Security controls in the tool

| Control | Where | Stops |
|---------|-------|-------|
| SHA-256 of every payload file | sign; verify check 5 | Modified, missing or extra files |
| Ed25519 signature over the exact manifest bytes | sign; verify check 3 | Edited manifest (including edited hashes); forged releases |
| Public key taken **only** from the client registry | verify checks 2–3 | An attacker shipping their own key with the release |
| `enabled` flag, checked with `is True` | verify check 2 | Releases from a revoked or suspended publisher |
| Path rules plus resolve-inside-payload | verify check 4 | `../` traversal, absolute paths, Windows paths |
| Symlink / special-file refusal | sign; verify check 4 | Reading outside `payload/` through a link |
| Strict manifest validation | verify check 1 | Crashes or confusion on malformed input |
| Fail closed on registry errors | verify check 2 | Accepting when trust cannot be established |
| Encrypted PKCS8 private key, hidden prompt, 8-character minimum, mode 0600 | setup | Use of a stolen key file without the passphrase; shoulder-surfing; shell-history leaks |
| Refuse to overwrite keys (`O_EXCL`) | setup | Accidentally destroying the only key |
| Read-only byte access to payload | everywhere | Executing hostile code during verification |
| Append-only JSON Lines log, no secrets | sign, verify | Silent attempts (when the log is intact) |

## 4. Specific areas

**Key protection.** `BestAvailableEncryption` encrypts the PKCS8 key with a passphrase-derived key.
Its strength depends on the passphrase: an attacker with the file can guess offline at their own pace.
The 8-character minimum is a floor, not a guarantee.

**Publisher authentication.** It rests entirely on the registry. Anyone can generate a key and *claim*
`publisher_id: harbourview` (T10a), but only the registry's key can validate the signature.

**Signature verification.** The library checks the signature over the raw bytes. Any change to the manifest,
even one added newline, or to the signature (flipped, truncated or extended bytes) raises `InvalidSignature`.

**Hash verification.** The hashes tie the signature to the actual file contents. Without them, signing the
manifest would say nothing about the files.

**Path traversal prevention.** Check 4 runs after authentication (so the paths come from a signed manifest) and before any
payload file is opened. It is still needed after check 3, because a careless or compromised trusted
publisher could sign `../../etc/shadow` (T10b).

**Symlink policy.** Symlinks are refused because `is_file()` follows links, and hashing a link would read
a file outside `payload/`.

**Registry trust assumptions.** The registry and `verifier/keys/` are assumed to be protected by the client's operating system.
The tool does not and cannot verify the registry itself.

**Logging limitations.** The log is plain text. An attacker with write access can delete or edit lines.
It records attempts; it does not prove them.

## 5. Candidate threats for the report (choose at least 4)

| Threat | Control in the tool | Remaining risk (what is still possible) |
|--------|---------------------|-----------------------------------------|
| Fake publisher / impersonation | Registry key only; check 3 (T10a); unknown ids rejected at check 2 (T7) | If the attacker can add themselves to the registry or swap a key, they are trusted (T10d) |
| Files modified in transit | SHA-256 per file (check 5, T3/T4); manifest signed (check 3, T5) | None for the bytes, as long as the key and registry are safe. A legitimately signed but harmful file is still accepted |
| Stolen private key | Encrypted at rest; hidden passphrase prompt | With the passphrase (or after guessing it), the thief's releases pass all five checks. Response: set `enabled: false` (T8), issue a new key, re-sign. Releases already accepted stay exposed |
| Tampered registry | Fail closed if corrupt; `is True` for enabled | Valid edits (add a publisher, swap a key) are undetectable by the tool (T10d). The bonus fingerprint would only help until the fingerprint is edited too |
| Path traversal via the manifest | Check 4 before any file is opened (T10b) | Rule is lexical plus resolve; exotic filesystem tricks (e.g. Windows junctions) are not specifically handled |
| Old release replayed (rollback) | None | The manifest has no version, timestamp or expiry, so an older vulnerable release still verifies |
| Weak passphrase | 8-character minimum | Offline guessing against a stolen key file is still possible for weak choices |
| Log tampering | Append mode; one record per attempt | No integrity protection. Lines can be removed by anyone with write access |
| Signed but malicious software | Out of scope: signature proves who and unchanged, not safe | Compromised publisher or build system; needs code review, scanning, sandboxing |

## 6. Residual risks (summary)

1. The registry is the root of trust and is not itself protected by the tool.
2. There is no protection against rollback or replay.
3. A stolen key plus its passphrase is indistinguishable from the real publisher.
4. The log is not tamper-evident.
5. A valid signature says nothing about whether the software is safe.
6. On Windows, private-key file permissions are not enforced (use the Linux VM).
