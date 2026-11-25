# !/usr/bin/env python3
"""
release_guard.py - Signed Software Release Verification
CIT4020 Computer Security, Group Lab Project (Assignment 2)
Client (fictional): HarbourView Business Systems Ltd.

Three commands:

    setup   Create an Ed25519 key pair for a publisher. The private key is saved
            encrypted (passphrase typed at a hidden prompt) on the PUBLISHER side;
            the public key and a registry entry are saved on the CLIENT side.
    sign    Hash every file in <release>/payload/, write <release>/manifest.json
            and sign the exact bytes of that manifest into <release>/signature.sig.
    verify  Run five checks in a fixed order and print ACCEPTED only if all pass.

Every sign and verify attempt is appended to a JSON Lines log.

Security rules this file follows (from the brief):
  * Payload files are only READ as bytes. They are never run, imported or extracted.
  * The passphrase comes from getpass only. It is never a CLI argument, never
    stored and never logged.
  * verify takes the public key from the client's registry, never from the release.
  * All cryptography comes from the 'cryptography' library (Ed25519, SHA-256).

Exit codes: 0 = success / ACCEPTED, 1 = REJECTED or refused, 2 = usage error.

Sections:
  ---- Constants and reason codes ----
  ---- Shared helpers (hashing, payload scan, registry, JSON) ----
  ---- Part D: Log ----
  ---- Part A: Setup and keys ----
  ---- Part B: Sign a release ----
  ---- Part C: Verify a release (five checks) ----
  ---- Command-line interface ----
"""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# =============================================================================
# ---- Constants and reason codes ----
# =============================================================================

DEFAULT_KEYS_DIR = "publisher_keys"      # publisher side: SECRET, never shipped
DEFAULT_VERIFIER_DIR = "verifier"        # client side: the trust store
DEFAULT_LOG_FILE = "release_log.jsonl"

REGISTRY_FILENAME = "trusted_publishers.json"
MANIFEST_FILENAME = "manifest.json"
SIGNATURE_FILENAME = "signature.sig"
PAYLOAD_DIRNAME = "payload"

MIN_PASSPHRASE_LENGTH = 8   # group decision: weak passphrases are a listed threat
HASH_CHUNK_SIZE = 65536     # read files in 64 KiB chunks so large files are fine

EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_USAGE = 2              # argparse itself exits with 2 on bad arguments

# The eight verification reason codes named in the brief.
INVALID_MANIFEST = "INVALID_MANIFEST"
UNKNOWN_PUBLISHER = "UNKNOWN_PUBLISHER"
PUBLISHER_DISABLED = "PUBLISHER_DISABLED"
BAD_SIGNATURE = "BAD_SIGNATURE"
UNSAFE_PATH = "UNSAFE_PATH"
MISSING_FILE = "MISSING_FILE"
EXTRA_FILE = "EXTRA_FILE"
HASH_MISMATCH = "HASH_MISMATCH"

# Extra codes (documented in README; confirm with the lecturer).
REGISTRY_ERROR = "REGISTRY_ERROR"     # verify: registry missing/corrupt -> fail closed
BAD_PASSPHRASE = "BAD_PASSPHRASE"     # sign: wrong or empty passphrase
MISSING_KEY = "MISSING_KEY"           # sign: no private key for this publisher
INVALID_RELEASE = "INVALID_RELEASE"   # sign: no payload/, empty payload, unreadable file

# Publisher ids become part of file names, so keep them to a safe character set.
PUBLISHER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")

# One-line descriptions printed as each verify check passes (helps tracing).
CHECK_DESCRIPTIONS = {
    1: "manifest.json and signature.sig present, JSON valid, required fields present",
    2: "publisher is in the trusted registry and enabled",
    3: "signature is valid under the REGISTRY's public key",
    4: "no unsafe paths in the manifest; no symlinks/special files in payload/",
    5: "all listed files present, no extra files, every hash matches",
}


# =============================================================================
# ---- Shared helpers (hashing, payload scan, registry, JSON) ----
# =============================================================================

def sha256_file(path):
    """Return the SHA-256 hex digest of a file, reading it in chunks.

    The file is opened for reading bytes only - it is never executed or imported.
    sign and verify both call this function, so they always hash the same way.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_payload(payload_dir):
    """Walk payload/ without following links.

    Returns (files, unsafe):
      files  - set of regular-file paths relative to payload/, with forward slashes
      unsafe - sorted list of symlinks (to files or folders) and special files

    Symlink policy (group decision): a symlink could point OUTSIDE payload/, so
    sign refuses to sign a payload containing one, and verify rejects it with
    UNSAFE_PATH. Both commands use this one function so the policy is consistent.
    """
    payload_dir = Path(payload_dir)
    files = set()
    unsafe = []
    for root, dirnames, filenames in os.walk(payload_dir, followlinks=False):
        root_path = Path(root)
        for name in dirnames:
            folder = root_path / name
            if folder.is_symlink():  # os.walk lists it but will not descend into it
                unsafe.append(folder.relative_to(payload_dir).as_posix())
        for name in filenames:
            item = root_path / name
            relative = item.relative_to(payload_dir).as_posix()
            if item.is_symlink() or not item.is_file():
                unsafe.append(relative)
            else:
                files.add(relative)
    return files, sorted(unsafe)


def load_registry(registry_path):
    """Read the trusted-publisher registry fresh from disk (no caching).

    Raises OSError if the file cannot be read and ValueError if it is not a JSON
    list of objects. Callers decide what that means: setup refuses to touch it,
    verify fails closed.
    """
    data = json.loads(Path(registry_path).read_bytes())
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        raise ValueError("registry must be a JSON list of objects")
    return data


def publisher_id_arg(value):
    """argparse type: accept only safe publisher ids (they are used in file names)."""
    if not PUBLISHER_ID_PATTERN.match(value):
        raise argparse.ArgumentTypeError(
            "publisher id must be 1-64 characters: letters, digits, '_' or '-'"
        )
    return value


def private_key_path(keys_dir, publisher_id):
    """Where a publisher's encrypted private key lives (publisher side)."""
    return Path(keys_dir) / f"{publisher_id}_private.pem"


def public_key_relpath(publisher_id):
    """Registry path of a publisher's public key, relative to the verifier folder."""
    return f"keys/{publisher_id}_public.pem"


# =============================================================================
# ---- Part D: Log ----
# =============================================================================

def log_event(log_path, operation, release, publisher_id, result, reason):
    """Append one JSON line describing a sign or verify attempt.

    Exactly the six fields from the brief. Nothing secret is ever passed in, so
    nothing secret can be written. json.dumps escapes newlines, so each record
    stays on one line. A logging failure prints a warning but does not change
    the result of the command.
    """
    record = {
        "time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operation": operation,
        "release": release,
        "publisher_id": publisher_id,   # None (JSON null) if it could not be read
        "result": result,
        "reason": reason,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError as error:
        print(f"WARNING: could not write log file '{log_path}': {error}", file=sys.stderr)


# =============================================================================
# ---- Part A: Setup and keys ----
# =============================================================================

def write_new_file(path, data, mode):
    """Create a file that must not already exist and write bytes to it.

    O_EXCL makes the operating system refuse if the file appeared since we
    checked, so setup can never overwrite a key. 'mode' sets the permissions
    at creation time (0o600 = owner read/write only for the private key; on
    Windows only the read-only bit is honoured).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def prompt_new_passphrase():
    """Ask for a new passphrase twice at a hidden prompt.

    Returns the passphrase, or None (after printing why) if it is empty, too
    short, or the two entries differ. The passphrase is never echoed or stored.
    """
    first = getpass.getpass("New passphrase for the private key: ")
    if not first:
        print("SETUP REFUSED: the passphrase must not be empty.", file=sys.stderr)
        return None
    if len(first) < MIN_PASSPHRASE_LENGTH:
        print(f"SETUP REFUSED: the passphrase must be at least "
              f"{MIN_PASSPHRASE_LENGTH} characters.", file=sys.stderr)
        return None
    second = getpass.getpass("Repeat the passphrase: ")
    if first != second:
        print("SETUP REFUSED: the two passphrases do not match.", file=sys.stderr)
        return None
    return first


def cmd_setup(args):
    """Part A: create a key pair and register the publisher.

    Order matters: CHECK for existing keys/registration first, then ASK for the
    passphrase, then WRITE. A refusal therefore leaves every existing file
    byte-for-byte unchanged (T1).
    """
    publisher_id = args.publisher_id
    keys_dir = Path(args.keys_dir)
    verifier_dir = Path(args.verifier_dir)
    private_path = private_key_path(keys_dir, publisher_id)
    public_rel = public_key_relpath(publisher_id)
    public_path = verifier_dir / public_rel
    registry_path = verifier_dir / REGISTRY_FILENAME

    # The private key must never sit in the folder that models the client machine.
    if keys_dir.resolve() == verifier_dir.resolve() or \
            keys_dir.resolve().is_relative_to(verifier_dir.resolve()):
        print("SETUP REFUSED: the keys folder must not be inside the verifier folder.",
              file=sys.stderr)
        return EXIT_REJECTED

    # 1. CHECK - before asking for anything.
    for existing in (private_path, public_path):
        if existing.exists():
            print(f"SETUP REFUSED: '{existing}' already exists. Existing keys are "
                  f"never overwritten.", file=sys.stderr)
            return EXIT_REJECTED

    registry = []
    if registry_path.exists():
        try:
            registry = load_registry(registry_path)
        except (OSError, ValueError) as error:
            print(f"SETUP REFUSED: existing registry '{registry_path}' cannot be read "
                  f"({error}). It has not been changed.", file=sys.stderr)
            return EXIT_REJECTED
        if any(entry.get("publisher_id") == publisher_id for entry in registry):
            print(f"SETUP REFUSED: publisher '{publisher_id}' is already registered "
                  f"in '{registry_path}'.", file=sys.stderr)
            return EXIT_REJECTED

    # 2. ASK - hidden prompt, twice.
    passphrase = prompt_new_passphrase()
    if passphrase is None:
        return EXIT_REJECTED

    # 3. GENERATE - Ed25519 from the library; private key encrypted with the passphrase.
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 4. WRITE - private key (owner-only), public key, then the registry entry.
    keys_dir.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    write_new_file(private_path, private_pem, 0o600)
    write_new_file(public_path, public_pem, 0o644)
    registry.append({
        "publisher_id": publisher_id,
        "public_key_path": public_rel,
        "enabled": True,
    })
    registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

    print(f"SETUP COMPLETE for publisher '{publisher_id}'")
    print(f"  encrypted private key : {private_path}   (SECRET - never share or commit)")
    print(f"  public key            : {public_path}")
    print(f"  registry entry added  : {registry_path}  (enabled: true)")
    return EXIT_OK


# =============================================================================
# ---- Part B: Sign a release ----
# =============================================================================

def load_private_key(key_path, passphrase):
    """Decrypt and load the Ed25519 private key, or return None if that fails.

    The library raises ValueError for a wrong passphrase (or corrupt file) and
    TypeError for an empty one, so both are caught here - no traceback (T9).
    """
    if not passphrase:
        return None
    try:
        key = serialization.load_pem_private_key(
            Path(key_path).read_bytes(), password=passphrase.encode("utf-8")
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if not isinstance(key, Ed25519PrivateKey):
        return None
    return key


def build_manifest_bytes(publisher_id, release_name, payload_dir, files):
    """Hash each payload file and serialise the manifest to bytes ONCE.

    These exact bytes are both signed and written to disk, so verification can
    check the signature over the raw file without ever re-serialising it.
    """
    entries = [
        {"path": relative, "sha256": sha256_file(Path(payload_dir) / relative)}
        for relative in sorted(files)
    ]
    manifest = {
        "publisher_id": publisher_id,
        "release_name": release_name,
        "files": entries,
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def cmd_sign(args):
    """Part B: write manifest.json and signature.sig for a release folder.

    The passphrase is asked for and the key unlocked BEFORE anything is written,
    so a wrong or empty passphrase changes nothing on disk (T9).
    """
    publisher_id = args.publisher_id
    release_dir = Path(args.release)
    release_label = str(args.release)
    payload_dir = release_dir / PAYLOAD_DIRNAME
    key_path = private_key_path(args.keys_dir, publisher_id)

    def fail(reason, message):
        """Print a clear error, log the failed attempt, return the exit code."""
        print(f"SIGN FAILED - {reason}: {message}", file=sys.stderr)
        log_event(args.log, "sign", release_label, publisher_id, "FAILED", reason)
        return EXIT_REJECTED

    # 1. Validate the inputs.
    if not payload_dir.is_dir() or payload_dir.is_symlink():
        return fail(INVALID_RELEASE, f"'{payload_dir}' is not a folder.")
    if not key_path.is_file():
        return fail(MISSING_KEY, f"no private key at '{key_path}'. Run setup first.")
    files, unsafe = scan_payload(payload_dir)
    if unsafe:
        return fail(UNSAFE_PATH, "payload contains symlinks or special files "
                                 f"(not allowed): {', '.join(unsafe)}")
    if not files:
        return fail(INVALID_RELEASE, f"'{payload_dir}' contains no files to sign.")

    # 2. Unlock the key before writing anything.
    passphrase = getpass.getpass(f"Passphrase for the '{publisher_id}' private key: ")
    private_key = load_private_key(key_path, passphrase)
    if private_key is None:
        return fail(BAD_PASSPHRASE, "the private key could not be unlocked "
                                    "(wrong or empty passphrase). Nothing was written.")

    # 3-4. Hash every file and build the manifest bytes once.
    release_name = args.release_name or release_dir.resolve().name
    try:
        manifest_bytes = build_manifest_bytes(publisher_id, release_name, payload_dir, files)
    except OSError as error:
        return fail(INVALID_RELEASE, f"could not read a payload file: {error}")

    # 5. Sign those exact bytes and write the same bytes to disk.
    signature = private_key.sign(manifest_bytes)
    (release_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)
    (release_dir / SIGNATURE_FILENAME).write_bytes(signature)

    # 6. Log and report.
    log_event(args.log, "sign", release_label, publisher_id, "SIGNED", "OK")
    print(f"SIGNED '{release_label}' as publisher '{publisher_id}'")
    print(f"  files hashed : {len(files)}")
    print(f"  manifest     : {release_dir / MANIFEST_FILENAME}")
    print(f"  signature    : {release_dir / SIGNATURE_FILENAME} ({len(signature)} bytes)")
    return EXIT_OK


# =============================================================================
# ---- Part C: Verify a release (five checks) ----
# =============================================================================
#
# Each check is one function that takes a shared 'ctx' dictionary and returns
# either None (passed) or a (reason_code, detail) tuple (rejected). cmd_verify
# runs them in order and stops at the first rejection, so the flowchart in the
# report maps one-to-one onto this code. finish_verify is the ONLY place that
# prints the result, writes the log line and picks the exit code.

def manifest_shape_problem(manifest):
    """Return a description of what is wrong with the manifest structure, or None."""
    if not isinstance(manifest, dict):
        return "manifest must be a JSON object"
    for field in ("publisher_id", "release_name", "files"):
        if field not in manifest:
            return f"required field '{field}' is missing"
    if not isinstance(manifest["publisher_id"], str) or not manifest["publisher_id"]:
        return "'publisher_id' must be a non-empty string"
    if not isinstance(manifest["release_name"], str):
        return "'release_name' must be a string"
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        return "'files' must be a non-empty list"
    seen = set()
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            return f"files[{index}] must be an object"
        path = entry.get("path")
        digest = entry.get("sha256")
        if not isinstance(path, str) or not path:
            return f"files[{index}].path must be a non-empty string"
        if not isinstance(digest, str) or not SHA256_HEX_PATTERN.match(digest):
            return f"files[{index}].sha256 must be 64 lowercase hex characters"
        if path in seen:
            return f"duplicate path '{path}' in files"
        seen.add(path)
    return None


def check_1_manifest(ctx):
    """Check 1: manifest.json and signature.sig exist, JSON is valid, fields present.

    Keeps the RAW manifest bytes in ctx - check 3 verifies the signature over
    exactly those bytes.
    """
    release_dir = ctx["release_dir"]
    manifest_path = release_dir / MANIFEST_FILENAME
    signature_path = release_dir / SIGNATURE_FILENAME
    if not manifest_path.is_file():
        return INVALID_MANIFEST, f"'{manifest_path}' is missing"
    if not signature_path.is_file():
        return INVALID_MANIFEST, f"'{signature_path}' is missing"
    try:
        manifest_bytes = manifest_path.read_bytes()
        signature = signature_path.read_bytes()
    except OSError as error:
        return INVALID_MANIFEST, f"could not read release files: {error}"
    try:
        manifest = json.loads(manifest_bytes)  # ValueError covers bad JSON and bad encoding
    except ValueError as error:
        return INVALID_MANIFEST, f"manifest.json is not valid JSON: {error}"
    problem = manifest_shape_problem(manifest)
    if problem:
        return INVALID_MANIFEST, problem
    ctx["manifest_bytes"] = manifest_bytes
    ctx["signature"] = signature
    ctx["manifest"] = manifest
    # Read before authentication - unavoidable, it tells us WHICH registry key to
    # use. That is safe only because check 3 uses the registry's key, never one
    # from the release.
    ctx["publisher_id"] = manifest["publisher_id"]
    return None


def check_2_publisher(ctx):
    """Check 2: the publisher is in the client's registry and enabled.

    The registry is re-read on every run (T8). If it cannot be read the tool
    fails CLOSED - it never accepts without a working trust store.
    """
    registry_path = ctx["verifier_dir"] / REGISTRY_FILENAME
    try:
        registry = load_registry(registry_path)
    except (OSError, ValueError) as error:
        return REGISTRY_ERROR, f"trusted registry '{registry_path}' unusable ({error}); failing closed"
    publisher_id = ctx["publisher_id"]
    matches = [entry for entry in registry if entry.get("publisher_id") == publisher_id]
    if not matches:
        return UNKNOWN_PUBLISHER, f"publisher '{publisher_id}' is not in the trusted registry"
    if len(matches) > 1:
        return REGISTRY_ERROR, f"publisher '{publisher_id}' appears more than once in the registry"
    entry = matches[0]
    # 'is True', not truthiness: the string "false" would otherwise count as enabled.
    if entry.get("enabled") is not True:
        return PUBLISHER_DISABLED, (f"publisher '{publisher_id}' is in the registry but "
                                    f"enabled = {json.dumps(entry.get('enabled'))}")
    ctx["registry_entry"] = entry
    return None


def check_3_signature(ctx):
    """Check 3: the signature over the raw manifest bytes is valid under the
    public key named in the REGISTRY (never a key shipped with the release)."""
    key_rel = ctx["registry_entry"].get("public_key_path")
    if not isinstance(key_rel, str) or not key_rel:
        return BAD_SIGNATURE, "registry entry has no usable public_key_path"
    key_path = ctx["verifier_dir"] / key_rel   # relative to the verifier folder
    try:
        public_key = serialization.load_pem_public_key(key_path.read_bytes())
    except (OSError, ValueError, UnsupportedAlgorithm) as error:
        return BAD_SIGNATURE, f"trusted public key '{key_path}' could not be loaded ({error})"
    if not isinstance(public_key, Ed25519PublicKey):
        return BAD_SIGNATURE, f"trusted public key '{key_path}' is not an Ed25519 key"
    try:
        public_key.verify(ctx["signature"], ctx["manifest_bytes"])
    except InvalidSignature:
        return BAD_SIGNATURE, ("signature.sig does not match the bytes of manifest.json "
                               f"under the registered key of '{ctx['publisher_id']}'")
    return None


def unsafe_path_reason(path, payload_root):
    """Return why a manifest path is unsafe, or None if it is safe.

    The brief's rule is literal: reject any path that contains '..' or starts
    with '/'. That deliberately also rejects names like 'notes..txt' (we prefer
    a false alarm to a missed traversal). Backslashes and Windows drive letters
    are rejected too, and as defence in depth the resolved path must stay inside
    payload/.
    """
    if ".." in path:
        return "contains '..'"
    if path.startswith("/"):
        return "starts with '/'"
    if "\\" in path:
        return "contains a backslash"
    if WINDOWS_DRIVE_PATTERN.match(path):
        return "starts with a drive letter"
    try:
        if not (payload_root / path).resolve().is_relative_to(payload_root):
            return "resolves outside payload/"
    except (OSError, RuntimeError, ValueError):
        return "cannot be resolved safely"
    return None


def check_4_paths(ctx):
    """Check 4: no manifest path can escape payload/, and payload/ holds no
    symlinks or special files. Every path is checked BEFORE any payload file
    is opened. (The scan lists directory entries only; no file is read.)"""
    payload_dir = ctx["release_dir"] / PAYLOAD_DIRNAME
    if payload_dir.is_symlink():
        return UNSAFE_PATH, "payload/ itself is a symlink"
    payload_root = payload_dir.resolve()
    for entry in ctx["manifest"]["files"]:
        reason = unsafe_path_reason(entry["path"], payload_root)
        if reason:
            return UNSAFE_PATH, f"manifest path '{entry['path']}' {reason}"
    present, unsafe = scan_payload(payload_dir)
    if unsafe:
        return UNSAFE_PATH, f"payload contains symlinks or special files: {', '.join(unsafe)}"
    ctx["present_files"] = present
    return None


def check_5_payload(ctx):
    """Check 5: the real payload matches the signed manifest.

    Priority when several things are wrong: MISSING_FILE, then EXTRA_FILE,
    then HASH_MISMATCH. Missing files are never hashed.
    """
    payload_dir = ctx["release_dir"] / PAYLOAD_DIRNAME
    listed = {entry["path"]: entry["sha256"] for entry in ctx["manifest"]["files"]}
    present = ctx["present_files"]

    missing = sorted(set(listed) - present)
    if missing:
        return MISSING_FILE, f"listed in manifest but not in payload/: {', '.join(missing)}"
    extra = sorted(present - set(listed))
    if extra:
        return EXTRA_FILE, f"in payload/ but not listed in manifest: {', '.join(extra)}"

    mismatched = []
    for path in sorted(listed):
        try:
            actual = sha256_file(payload_dir / path)
        except OSError:
            mismatched.append(f"{path} (unreadable)")
            continue
        if not hmac.compare_digest(actual, listed[path]):
            mismatched.append(path)
    if mismatched:
        return HASH_MISMATCH, f"contents differ from the signed manifest: {', '.join(mismatched)}"
    return None


VERIFY_CHECKS = [
    (1, check_1_manifest),
    (2, check_2_publisher),
    (3, check_3_signature),
    (4, check_4_paths),
    (5, check_5_payload),
]


def finish_verify(args, ctx, check_number, rejection):
    """The single exit point of verify: print, log and return the exit code.

    Because screen output and the log line come from the same place, they can
    never disagree. ACCEPTED is printed here and nowhere else.
    """
    release_label = str(args.release)
    publisher_id = ctx.get("publisher_id")
    if rejection is None:
        print(f"ACCEPTED: '{release_label}' from publisher '{publisher_id}' passed all five checks.")
        log_event(args.log, "verify", release_label, publisher_id, "ACCEPTED", "OK")
        return EXIT_OK
    reason, detail = rejection
    print(f"REJECTED - {reason} (check {check_number}): {detail}")
    log_event(args.log, "verify", release_label, publisher_id, "REJECTED", reason)
    return EXIT_REJECTED


def cmd_verify(args):
    """Part C: run the five checks in order; stop at the first failure."""
    ctx = {
        "release_dir": Path(args.release),
        "verifier_dir": Path(args.verifier_dir),
        "publisher_id": None,
    }
    print(f"Verifying '{args.release}' against registry "
          f"'{Path(args.verifier_dir) / REGISTRY_FILENAME}'")
    for number, check in VERIFY_CHECKS:
        rejection = check(ctx)
        if rejection is not None:
            return finish_verify(args, ctx, number, rejection)
        print(f"  check {number} passed: {CHECK_DESCRIPTIONS[number]}")
    return finish_verify(args, ctx, None, None)


# =============================================================================
# ---- Command-line interface ----
# =============================================================================

def build_parser():
    """argparse with three sub-commands. Location flags let tests (T7, T10) use
    scratch key/registry folders without touching the real ones."""
    parser = argparse.ArgumentParser(
        prog="release_guard.py",
        description="Sign software releases and verify them against a trusted-publisher registry.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="{setup,sign,verify}")

    setup = sub.add_parser("setup", help="create a publisher key pair and register it (run once)")
    setup.add_argument("--publisher-id", required=True, type=publisher_id_arg,
                       help="publisher id, e.g. harbourview")
    setup.add_argument("--keys-dir", default=DEFAULT_KEYS_DIR,
                       help=f"publisher-side folder for the encrypted private key (default: {DEFAULT_KEYS_DIR})")
    setup.add_argument("--verifier-dir", default=DEFAULT_VERIFIER_DIR,
                       help=f"client-side folder for the registry and public keys (default: {DEFAULT_VERIFIER_DIR})")
    setup.set_defaults(func=cmd_setup)

    sign = sub.add_parser("sign", help="hash payload/, write manifest.json and signature.sig")
    sign.add_argument("--publisher-id", required=True, type=publisher_id_arg,
                      help="publisher whose private key signs the release")
    sign.add_argument("--release", required=True,
                      help="release folder that contains payload/, e.g. release_A")
    sign.add_argument("--release-name", default=None,
                      help="human-readable release name (default: the release folder name)")
    sign.add_argument("--keys-dir", default=DEFAULT_KEYS_DIR,
                      help=f"folder holding the encrypted private key (default: {DEFAULT_KEYS_DIR})")
    sign.add_argument("--log", default=DEFAULT_LOG_FILE,
                      help=f"log file to append to (default: {DEFAULT_LOG_FILE})")
    sign.set_defaults(func=cmd_sign)

    verify = sub.add_parser("verify", help="run the five checks on a release folder")
    verify.add_argument("--release", required=True,
                        help="release folder to verify, e.g. release_A")
    verify.add_argument("--verifier-dir", default=DEFAULT_VERIFIER_DIR,
                        help=f"client-side folder holding {REGISTRY_FILENAME} (default: {DEFAULT_VERIFIER_DIR})")
    verify.add_argument("--log", default=DEFAULT_LOG_FILE,
                        help=f"log file to append to (default: {DEFAULT_LOG_FILE})")
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv=None):
    """Parse arguments and run the chosen command; return the exit code."""
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. Nothing further was written.", file=sys.stderr)
        return EXIT_REJECTED


if __name__ == "__main__":
    sys.exit(main())
