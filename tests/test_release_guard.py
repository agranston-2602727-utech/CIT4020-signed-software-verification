"""
Automated regression tests for release_guard.py (standard library unittest only).

Run from the project root:
    python3 -m unittest discover -s tests -v

What these tests ARE: a fast check that the code still behaves as T1-T10 expect,
for use during development and after every bug fix.

What they are NOT: the formal T1-T10 evidence. The brief requires the security
tester (M3) to run T1-T10 by hand on the frozen code, with labelled screenshots
(see docs/TESTING_GUIDE.md). Never paste these results into the report as if
they were the manual run.

Every test works in its own temporary folder; the real publisher_keys/,
verifier/, release_A/ and release_log.jsonl are never touched. getpass is
replaced by a stub that returns a throwaway test passphrase, so no human
needs to type.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import release_guard as rg  # noqa: E402

TEST_PASSPHRASE = "unit-test-only-passphrase"   # throwaway, test fixtures only
SAMPLE_PAYLOAD = PROJECT_ROOT / "release_A" / "payload"


class ReleaseGuardTestCase(unittest.TestCase):
    """Shared fixture: a temp workspace with keys, verifier and a signed release_A."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rg_test_"))
        self.keys = self.tmp / "publisher_keys"
        self.verifier = self.tmp / "verifier"
        self.log = self.tmp / "release_log.jsonl"
        self.release_a = self.tmp / "release_A"
        shutil.copytree(SAMPLE_PAYLOAD, self.release_a / "payload")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers -----------------------------------------------------------

    def run_cli(self, argv, passphrases=()):
        """Run release_guard.main(argv) with scripted getpass answers.

        Returns (exit_code, stdout_text, stderr_text).
        """
        answers = iter(passphrases)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("getpass.getpass", side_effect=lambda prompt="": next(answers)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = rg.main([str(a) for a in argv])
            except SystemExit as exit_error:      # argparse usage errors
                code = exit_error.code
        return code, out.getvalue(), err.getvalue()

    def setup_publisher(self, publisher_id="harbourview", keys=None, verifier=None):
        code, out, err = self.run_cli(
            ["setup", "--publisher-id", publisher_id,
             "--keys-dir", keys or self.keys, "--verifier-dir", verifier or self.verifier],
            passphrases=[TEST_PASSPHRASE, TEST_PASSPHRASE])
        self.assertEqual(code, 0, out + err)

    def sign(self, release, publisher_id="harbourview", keys=None, passphrase=TEST_PASSPHRASE):
        return self.run_cli(
            ["sign", "--publisher-id", publisher_id, "--release", release,
             "--keys-dir", keys or self.keys, "--log", self.log],
            passphrases=[passphrase])

    def verify(self, release, verifier=None):
        return self.run_cli(
            ["verify", "--release", release,
             "--verifier-dir", verifier or self.verifier, "--log", self.log])

    def signed_copy(self, name):
        """Fresh copy of the signed release_A (the cp -a workflow from the guide)."""
        target = self.tmp / name
        shutil.copytree(self.release_a, target)
        return target

    def ready(self):
        """setup + sign release_A, the starting point for T3-T10."""
        self.setup_publisher()
        code, out, err = self.sign(self.release_a)
        self.assertEqual(code, 0, out + err)

    def sign_custom_manifest(self, release, manifest_bytes, keys=None, publisher_id="harbourview"):
        """Test-only helper (T10b): sign arbitrary manifest bytes with the same
        library calls as cmd_sign, so check 3 passes and check 4 can be reached."""
        key = rg.load_private_key(rg.private_key_path(keys or self.keys, publisher_id),
                                  TEST_PASSPHRASE)
        (release / rg.MANIFEST_FILENAME).write_bytes(manifest_bytes)
        (release / rg.SIGNATURE_FILENAME).write_bytes(key.sign(manifest_bytes))

    def log_records(self):
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def assertRejected(self, result, reason):
        code, out, _ = result
        self.assertEqual(code, 1, out)
        self.assertIn(f"REJECTED - {reason}", out)
        self.assertNotIn("ACCEPTED", out)


class T1Setup(ReleaseGuardTestCase):

    def test_setup_creates_encrypted_key_public_key_and_registry(self):
        self.setup_publisher()
        private = self.keys / "harbourview_private.pem"
        first_line = private.read_text().splitlines()[0]
        self.assertEqual(first_line, "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        self.assertTrue((self.verifier / "keys" / "harbourview_public.pem").is_file())
        registry = json.loads((self.verifier / "trusted_publishers.json").read_text())
        self.assertEqual(registry, [{"publisher_id": "harbourview",
                                     "public_key_path": "keys/harbourview_public.pem",
                                     "enabled": True}])
        self.assertNotIn(TEST_PASSPHRASE.encode(), private.read_bytes())

    def test_second_setup_refuses_and_leaves_files_byte_identical(self):
        self.setup_publisher()
        private = self.keys / "harbourview_private.pem"
        before = hashlib.sha256(private.read_bytes()).hexdigest()
        # No passphrase answers supplied: refusal must happen BEFORE the prompt.
        code, out, err = self.run_cli(["setup", "--publisher-id", "harbourview",
                                       "--keys-dir", self.keys, "--verifier-dir", self.verifier])
        self.assertEqual(code, 1)
        self.assertIn("SETUP REFUSED", err)
        self.assertEqual(before, hashlib.sha256(private.read_bytes()).hexdigest())

    def test_setup_rejects_empty_short_and_mismatched_passphrases(self):
        args = ["setup", "--publisher-id", "harbourview",
                "--keys-dir", self.keys, "--verifier-dir", self.verifier]
        for answers in ([""], ["short"], [TEST_PASSPHRASE, TEST_PASSPHRASE + "x"]):
            code, _, err = self.run_cli(args, passphrases=answers)
            self.assertEqual(code, 1)
            self.assertIn("SETUP REFUSED", err)
        self.assertFalse((self.keys / "harbourview_private.pem").exists())

    def test_second_publisher_is_added_not_replacing_registry(self):
        self.setup_publisher("harbourview")
        self.setup_publisher("second_pub")
        registry = json.loads((self.verifier / "trusted_publishers.json").read_text())
        self.assertEqual([e["publisher_id"] for e in registry], ["harbourview", "second_pub"])

    def test_keys_dir_inside_verifier_is_refused(self):
        code, _, err = self.run_cli(["setup", "--publisher-id", "harbourview",
                                     "--keys-dir", self.verifier / "keys",
                                     "--verifier-dir", self.verifier])
        self.assertEqual(code, 1)
        self.assertIn("must not be inside the verifier", err)


class T2CleanRelease(ReleaseGuardTestCase):

    def test_sign_then_verify_is_accepted_and_logged(self):
        self.ready()
        manifest = json.loads((self.release_a / "manifest.json").read_bytes())
        self.assertEqual(manifest["publisher_id"], "harbourview")
        self.assertEqual(manifest["release_name"], "release_A")
        expected = {p: hashlib.sha256((SAMPLE_PAYLOAD / p).read_bytes()).hexdigest()
                    for p in ("app.py", "config/settings.ini", "release_notes.txt")}
        self.assertEqual({e["path"]: e["sha256"] for e in manifest["files"]}, expected)
        self.assertEqual(len((self.release_a / "signature.sig").read_bytes()), 64)

        code, out, _ = self.verify(self.release_a)
        self.assertEqual(code, 0)
        self.assertIn("ACCEPTED", out)

        records = self.log_records()
        self.assertEqual([(r["operation"], r["result"]) for r in records],
                         [("sign", "SIGNED"), ("verify", "ACCEPTED")])
        for record in records:
            self.assertEqual(set(record), {"time_utc", "operation", "release",
                                           "publisher_id", "result", "reason"})
        self.assertNotIn(TEST_PASSPHRASE, self.log.read_text())
        self.assertNotIn("PRIVATE KEY", self.log.read_text())


class T3toT6Tampering(ReleaseGuardTestCase):

    def setUp(self):
        super().setUp()
        self.ready()

    def test_T3_modified_payload_file_is_hash_mismatch(self):
        copy = self.signed_copy("release_T3")
        with open(copy / "payload" / "app.py", "ab") as handle:
            handle.write(b"#")
        result = self.verify(copy)
        self.assertRejected(result, "HASH_MISMATCH")
        self.assertIn("app.py", result[1])
        self.assertIn("check 3 passed", result[1])   # signature itself was still fine

    def test_T4a_deleted_file_is_missing_file(self):
        copy = self.signed_copy("release_T4a")
        (copy / "payload" / "config" / "settings.ini").unlink()
        result = self.verify(copy)
        self.assertRejected(result, "MISSING_FILE")
        self.assertIn("config/settings.ini", result[1])

    def test_T4b_new_file_in_subfolder_is_extra_file(self):
        copy = self.signed_copy("release_T4b")
        (copy / "payload" / "config" / "backdoor.ini").write_text("x")
        result = self.verify(copy)
        self.assertRejected(result, "EXTRA_FILE")
        self.assertIn("config/backdoor.ini", result[1])

    def test_missing_beats_extra_beats_hash(self):
        copy = self.signed_copy("release_multi")
        (copy / "payload" / "release_notes.txt").unlink()
        (copy / "payload" / "new.txt").write_text("x")
        with open(copy / "payload" / "app.py", "ab") as handle:
            handle.write(b"#")
        self.assertRejected(self.verify(copy), "MISSING_FILE")

    def test_T5_edited_release_name_is_bad_signature(self):
        copy = self.signed_copy("release_T5")
        manifest = copy / "manifest.json"
        manifest.write_bytes(manifest.read_bytes().replace(b'"release_A"', b'"release_B"'))
        self.assertRejected(self.verify(copy), "BAD_SIGNATURE")

    def test_T6_one_flipped_signature_byte_is_bad_signature(self):
        copy = self.signed_copy("release_T6")
        signature = bytearray((copy / "signature.sig").read_bytes())
        signature[10] ^= 0xFF
        (copy / "signature.sig").write_bytes(bytes(signature))
        self.assertRejected(self.verify(copy), "BAD_SIGNATURE")

    def test_truncated_and_empty_signature_are_bad_signature(self):
        for name, data in (("release_trunc", None), ("release_empty", b"")):
            copy = self.signed_copy(name)
            sig = copy / "signature.sig"
            sig.write_bytes(sig.read_bytes()[:32] if data is None else data)
            self.assertRejected(self.verify(copy), "BAD_SIGNATURE")


class T7T8Publishers(ReleaseGuardTestCase):

    def setUp(self):
        super().setUp()
        self.ready()

    def test_T7_unknown_publisher_and_real_registry_untouched(self):
        registry_file = self.verifier / "trusted_publishers.json"
        before = registry_file.read_bytes()
        other_keys = self.tmp / "scratch" / "other_keys"
        other_verifier = self.tmp / "scratch" / "other_verifier"
        self.setup_publisher("other_pub", keys=other_keys, verifier=other_verifier)
        copy = self.signed_copy("release_T7")
        code, out, err = self.sign(copy, publisher_id="other_pub", keys=other_keys)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.verify(copy, verifier=other_verifier)[0], 0)  # its own registry accepts
        self.assertRejected(self.verify(copy), "UNKNOWN_PUBLISHER")
        self.assertEqual(before, registry_file.read_bytes())

    def test_T8_disabled_then_reenabled(self):
        registry_file = self.verifier / "trusted_publishers.json"
        original = registry_file.read_text()
        registry_file.write_text(original.replace('"enabled": true', '"enabled": false'))
        self.assertRejected(self.verify(self.release_a), "PUBLISHER_DISABLED")
        registry_file.write_text(original)
        code, out, _ = self.verify(self.release_a)
        self.assertEqual(code, 0)
        self.assertIn("ACCEPTED", out)

    def test_string_false_is_not_treated_as_enabled(self):
        registry_file = self.verifier / "trusted_publishers.json"
        registry_file.write_text(registry_file.read_text().replace('true', '"true"'))
        self.assertRejected(self.verify(self.release_a), "PUBLISHER_DISABLED")

    def test_missing_or_corrupt_registry_fails_closed(self):
        registry_file = self.verifier / "trusted_publishers.json"
        registry_file.write_text("{not json")
        self.assertRejected(self.verify(self.release_a), "REGISTRY_ERROR")
        registry_file.unlink()
        self.assertRejected(self.verify(self.release_a), "REGISTRY_ERROR")

    def test_missing_public_key_file_is_bad_signature_not_traceback(self):
        (self.verifier / "keys" / "harbourview_public.pem").unlink()
        self.assertRejected(self.verify(self.release_a), "BAD_SIGNATURE")


class T9Passphrase(ReleaseGuardTestCase):

    def setUp(self):
        super().setUp()
        self.setup_publisher()

    def test_wrong_and_empty_passphrase_write_nothing_on_fresh_release(self):
        for passphrase in ("definitely-wrong", ""):
            code, _, err = self.sign(self.release_a, passphrase=passphrase)
            self.assertEqual(code, 1)
            self.assertIn("BAD_PASSPHRASE", err)
            self.assertNotIn("Traceback", err)
            self.assertFalse((self.release_a / "manifest.json").exists())
            self.assertFalse((self.release_a / "signature.sig").exists())
        reasons = [(r["result"], r["reason"]) for r in self.log_records()]
        self.assertEqual(reasons, [("FAILED", "BAD_PASSPHRASE")] * 2)
        self.assertNotIn("definitely-wrong", self.log.read_text())

    def test_wrong_passphrase_leaves_existing_signed_files_unchanged(self):
        self.assertEqual(self.sign(self.release_a)[0], 0)
        before = {n: (self.release_a / n).read_bytes() for n in ("manifest.json", "signature.sig")}
        self.assertEqual(self.sign(self.release_a, passphrase="definitely-wrong")[0], 1)
        after = {n: (self.release_a / n).read_bytes() for n in ("manifest.json", "signature.sig")}
        self.assertEqual(before, after)

    def test_sign_without_key_or_payload_fails_cleanly(self):
        code, _, err = self.sign(self.release_a, publisher_id="nobody")
        self.assertEqual(code, 1)
        self.assertIn("MISSING_KEY", err)
        code, _, err = self.sign(self.tmp / "no_such_release")
        self.assertEqual(code, 1)
        self.assertIn("INVALID_RELEASE", err)


class T10Custom(ReleaseGuardTestCase):

    def setUp(self):
        super().setUp()
        self.ready()

    def test_T10a_attacker_key_claiming_approved_id_is_bad_signature(self):
        attacker_keys = self.tmp / "scratch" / "attacker_keys"
        attacker_verifier = self.tmp / "scratch" / "attacker_verifier"
        # Attacker creates their OWN key under the approved id, in their own folders.
        self.setup_publisher("harbourview", keys=attacker_keys, verifier=attacker_verifier)
        copy = self.signed_copy("release_T10a")
        with open(copy / "payload" / "app.py", "ab") as handle:
            handle.write(b"\n# malicious change\n")
        self.assertEqual(self.sign(copy, keys=attacker_keys)[0], 0)
        self.assertRejected(self.verify(copy), "BAD_SIGNATURE")

    def test_T10b_validly_signed_traversal_path_is_unsafe_path(self):
        copy = self.signed_copy("release_T10b")
        manifest = json.loads((copy / "manifest.json").read_bytes())
        manifest["files"].append({"path": "../outside.txt", "sha256": "0" * 64})
        self.sign_custom_manifest(copy, (json.dumps(manifest, indent=2) + "\n").encode())
        result = self.verify(copy)
        self.assertRejected(result, "UNSAFE_PATH")
        self.assertIn("check 3 passed", result[1])

    def test_absolute_and_backslash_paths_are_unsafe(self):
        for bad in ("/etc/passwd", "config\\settings.ini", "C:/Windows/win.ini"):
            copy = self.signed_copy("release_path_" + str(abs(hash(bad))))
            manifest = json.loads((copy / "manifest.json").read_bytes())
            manifest["files"][0]["path"] = bad
            self.sign_custom_manifest(copy, json.dumps(manifest).encode())
            self.assertRejected(self.verify(copy), "UNSAFE_PATH")

    def test_T10c_malformed_inputs_are_invalid_manifest(self):
        cases = {
            "bad_json": lambda r: (r / "manifest.json").write_text("{oops"),
            "empty": lambda r: (r / "manifest.json").write_bytes(b""),
            "not_utf8": lambda r: (r / "manifest.json").write_bytes(b"\xff\xfe\x00{"),
            "a_list": lambda r: (r / "manifest.json").write_text("[]"),
            "no_sig": lambda r: (r / "signature.sig").unlink(),
            "no_manifest": lambda r: (r / "manifest.json").unlink(),
        }
        for name, damage in cases.items():
            copy = self.signed_copy("release_T10c_" + name)
            damage(copy)
            result = self.verify(copy)
            self.assertRejected(result, "INVALID_MANIFEST")
            self.assertNotIn("Traceback", result[1] + result[2])
        self.assertIsNone(self.log_records()[-1]["publisher_id"])

    def test_duplicate_path_is_invalid_manifest(self):
        copy = self.signed_copy("release_dup")
        manifest = json.loads((copy / "manifest.json").read_bytes())
        manifest["files"].append(dict(manifest["files"][0]))
        self.sign_custom_manifest(copy, json.dumps(manifest).encode())
        self.assertRejected(self.verify(copy), "INVALID_MANIFEST")

    def test_T10d_swapped_registry_key_is_accepted_residual_risk(self):
        """Documents the 'tampered registry' residual risk: if an attacker can
        replace the public key in the client's registry, all five checks pass."""
        attacker_keys = self.tmp / "scratch" / "attacker_keys"
        attacker_verifier = self.tmp / "scratch" / "attacker_verifier"
        self.setup_publisher("harbourview", keys=attacker_keys, verifier=attacker_verifier)
        shutil.copy(attacker_verifier / "keys" / "harbourview_public.pem",
                    self.verifier / "keys" / "harbourview_public.pem")
        copy = self.signed_copy("release_T10d")
        self.assertEqual(self.sign(copy, keys=attacker_keys)[0], 0)
        self.assertEqual(self.verify(copy)[0], 0)

    def test_empty_payload_cannot_be_signed(self):
        empty = self.tmp / "release_empty"
        (empty / "payload").mkdir(parents=True)
        code, _, err = self.sign(empty)
        self.assertEqual(code, 1)
        self.assertIn("INVALID_RELEASE", err)

    def test_symlink_policy(self):
        copy = self.signed_copy("release_symlink")
        link = copy / "payload" / "link.txt"
        try:
            os.symlink(self.tmp / "release_A" / "payload" / "app.py", link)
        except (OSError, NotImplementedError):
            self.skipTest("this OS/user cannot create symlinks (normal on Windows without "
                          "Developer Mode); run on the Linux golden VM")
        self.assertRejected(self.verify(copy), "UNSAFE_PATH")
        code, _, err = self.sign(copy)
        self.assertEqual(code, 1)
        self.assertIn("UNSAFE_PATH", err)


class CommandLine(ReleaseGuardTestCase):

    def test_usage_errors_exit_2(self):
        self.assertEqual(self.run_cli([])[0], 2)
        self.assertEqual(self.run_cli(["verify"])[0], 2)
        self.assertEqual(self.run_cli(["setup", "--publisher-id", "../evil"])[0], 2)


if __name__ == "__main__":
    unittest.main()
