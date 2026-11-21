#!/usr/bin/env python3
"""
TEST-ONLY HELPER for T10b (validly signed path traversal). Not part of the tool.

Why it exists: if you hand-edit manifest.json to add "../outside.txt", check 3
(BAD_SIGNATURE) fires before check 4 can ever look at the path. To prove that
check 4 works on its own, the hostile manifest must carry a VALID signature -
i.e. a careless or compromised trusted publisher signed it. This script signs
a manifest file you wrote by hand, using the same library calls as
release_guard.py sign (it reuses release_guard.load_private_key).

Usage (from the project root, on a SCRATCH copy only):
    python3 tests/t10_sign_custom_manifest.py \
        --publisher-id harbourview \
        --release scratch/release_T10b \
        --manifest-in scratch/T10b_manifest.json

The manifest bytes are copied exactly (no re-serialising), then signed.
The passphrase is asked for with getpass, like the real tool.
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import release_guard as rg  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="TEST ONLY: sign a hand-written manifest.")
    parser.add_argument("--publisher-id", required=True, type=rg.publisher_id_arg)
    parser.add_argument("--release", required=True, help="scratch release folder")
    parser.add_argument("--manifest-in", required=True, help="hand-written manifest JSON file")
    parser.add_argument("--keys-dir", default=rg.DEFAULT_KEYS_DIR)
    args = parser.parse_args()

    if Path(args.release).resolve().name == "release_A":
        print("Refusing: never modify the clean release_A. Use a scratch copy.", file=sys.stderr)
        return 1
    manifest_bytes = Path(args.manifest_in).read_bytes()
    passphrase = getpass.getpass(f"Passphrase for the '{args.publisher_id}' private key: ")
    key = rg.load_private_key(rg.private_key_path(args.keys_dir, args.publisher_id), passphrase)
    if key is None:
        print("Could not unlock the private key (wrong or empty passphrase).", file=sys.stderr)
        return 1
    release = Path(args.release)
    (release / rg.MANIFEST_FILENAME).write_bytes(manifest_bytes)
    (release / rg.SIGNATURE_FILENAME).write_bytes(key.sign(manifest_bytes))
    print(f"TEST-ONLY: signed hand-written manifest into '{release}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
