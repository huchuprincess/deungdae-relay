from contextlib import redirect_stdout
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from relay.model import blank, dumps, parse_stamp, update
from relay.run import fixture_fetch
from relay.safety import RelayError
from relay.site import build
from relay.storage import (CACHE_CONTROL, R2, main, publish_r2, seed, signing_headers)

ROOT = Path(__file__).resolve().parents[1]
NOW = parse_stamp("2000-01-02T03:10:00Z")
GOOD = update(None, "live", NOW, fixture_fetch(ROOT / "fixtures"))
ETAG = '"' + 'a' * 32 + '"'


class StorageTests(unittest.TestCase):
    def r2(self, transport):
        return R2("0" * 32, "synthetic-bucket", "synthetic-access", "synthetic-secret", transport)

    def test_missing_account_is_not_guessed(self):
        with self.assertRaises(RelayError):
            R2("", "", "", "")

    def test_signer_matches_fixed_independent_review_vector(self):
        # Fixed vector is independently checked against botocore during review.
        headers = signing_headers("GET", "example.invalid", "/sample/v1/latest.json", b"",
                                  "synthetic-access", "synthetic-secret", NOW)
        self.assertIn("/20000102/auto/s3/aws4_request", headers["authorization"])
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date", headers["authorization"])
        self.assertEqual(headers["x-amz-content-sha256"], hashlib.sha256(b"").hexdigest())
        self.assertTrue(headers["authorization"].endswith("Signature=" + "0fc3296430f2962c1b8f66829b578da2770145c1a6f504bbe476d7712cac0065"))

    def test_conditional_put_signature_matches_official_sdk_vector(self):
        headers = signing_headers("PUT", "example.invalid", "/sample/v1/latest.json", b"{}",
                                  "synthetic-access", "synthetic-secret", NOW,
                                  {"content-type": "application/json; charset=utf-8", "cache-control": CACHE_CONTROL,
                                   "if-match": ETAG})
        self.assertTrue(headers["authorization"].endswith("Signature=" + "982efc71b3a597de5bc918d49f6c110a9b98c954f0e05ef62ca1ce24de45c17c"))

    def test_successful_seed_saves_valid_snapshot_and_etag(self):
        with tempfile.TemporaryDirectory() as directory:
            path, receipt = Path(directory) / "previous.json", Path(directory) / "receipt.json"
            seed("r2", path, receipt, r2=self.r2(lambda _: (200, {"etag": ETAG}, dumps(GOOD).encode())))
            self.assertEqual(json.loads(path.read_text()), GOOD)
            self.assertEqual(json.loads(receipt.read_text())["etag"], ETAG)

    def test_first_404_requires_explicit_bootstrap_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            path, receipt = Path(directory) / "previous.json", Path(directory) / "receipt.json"
            r2 = self.r2(lambda _: (404, {}, b""))
            with self.assertRaises(RelayError):
                seed("r2", path, receipt, r2=r2)
            self.assertFalse(path.exists())
            seed("r2", path, receipt, allow_empty=True, r2=r2)
            self.assertIsNone(json.loads(receipt.read_text())["etag"])

    def test_unavailable_or_corrupt_baseline_cannot_turn_into_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path, receipt = Path(directory) / "previous.json", Path(directory) / "receipt.json"
            for status, raw in ((503, b""), (200, b"corrupt")):
                with self.assertRaises(RelayError):
                    seed("r2", path, receipt, allow_empty=True, r2=self.r2(lambda _: (status, {}, raw)))
            self.assertFalse(path.exists())

    def test_example_cannot_become_live_baseline(self):
        example = update(None, "example", NOW, fixture_fetch(ROOT / "fixtures"))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RelayError):
            seed("pages", Path(directory) / "p.json", Path(directory) / "r.json", True,
                 transport=lambda _: (200, {}, dumps(example).encode()))

    def test_existing_r2_object_without_etag_stops(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RelayError):
            seed("r2", Path(directory) / "p.json", Path(directory) / "r.json",
                 r2=self.r2(lambda _: (200, {}, dumps(GOOD).encode())))

    def test_conditional_atomic_write_includes_json_cache_policy(self):
        calls = []
        r2 = self.r2(lambda request: (calls.append(request) or (200, {}, b"")))
        r2.put(dumps(GOOD).encode(), ETAG)
        headers = {k.lower(): v for k, v in calls[0].header_items()}
        self.assertEqual(headers["if-match"], ETAG)
        self.assertEqual(headers["cache-control"], CACHE_CONTROL)
        self.assertIn("if-match", headers["authorization"])
        self.assertEqual(calls[0].get_method(), "PUT")

    def test_initial_write_uses_if_none_match(self):
        calls = []
        self.r2(lambda request: (calls.append(request) or (200, {}, b""))).put(dumps(GOOD).encode(), None)
        self.assertEqual(calls[0].get_header("If-none-match"), "*")

    def test_concurrent_write_conflict_is_not_retried_as_unconditional_put(self):
        calls = []
        with self.assertRaisesRegex(RelayError, "conflict"):
            self.r2(lambda request: (calls.append(request) or (412, {}, b""))).put(dumps(GOOD).encode(), ETAG)
        self.assertEqual(len(calls), 1)

    def test_r2_never_publishes_example(self):
        example = update(None, "example", NOW, fixture_fetch(ROOT / "fixtures"))
        with self.assertRaises(RelayError):
            self.r2(lambda _: self.fail("network called")).put(dumps(example).encode(), None)

    def test_modified_baseline_receipt_blocks_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            previous, receipt, new = (Path(directory) / name for name in ("p.json", "r.json", "n.json"))
            previous.write_text(dumps(GOOD)); new.write_text(dumps(GOOD))
            receipt.write_text(json.dumps({"delivery": "r2", "etag": ETAG, "baselineSha256": "wrong"}))
            with self.assertRaisesRegex(RelayError, "conflict"):
                publish_r2(new, previous, receipt, self.r2(lambda _: self.fail("network called")))

    def test_publication_cli_stops_without_approval_variable(self):
        with patch.dict("os.environ", {}, clear=True), patch("relay.storage.R2.from_env", side_effect=AssertionError("credentials read")), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["seed", "--delivery", "r2", "--previous", "unused", "--receipt", "unused"]), 2)

    def test_failed_transport_logs_do_not_echo_credential_headers(self):
        secret = "synthetic-private-" + "value"
        stream = io.StringIO()
        with patch.dict("os.environ", {"RELAY_PUBLICATION_APPROVED": "true"}, clear=True), patch("relay.storage.seed", side_effect=RuntimeError(secret)), redirect_stdout(stream):
            self.assertEqual(main(["seed", "--delivery", "r2", "--previous", "unused", "--receipt", "unused"]), 2)
        self.assertNotIn(secret, stream.getvalue())
        self.assertNotIn("Traceback", stream.getvalue())


class SiteTests(unittest.TestCase):
    def test_pages_artifact_contains_only_allowed_static_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "snapshot.json"; source.write_text(dumps(blank()))
            output = Path(directory) / "site"
            build(ROOT / "public", source, output)
            self.assertEqual(sorted(p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()),
                             [".nojekyll", "examples/v1/latest.json", "index.html", "v1/latest.json"])

    def test_live_site_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "snapshot.json"; source.write_text(dumps(GOOD))
            with self.assertRaises(RelayError):
                build(ROOT / "public", source, Path(directory) / "site")

    def test_existing_site_folder_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "site"; output.mkdir(); (output / "keep").write_text("keep")
            source = Path(directory) / "snapshot.json"; source.write_text(dumps(blank()))
            with self.assertRaises(RelayError):
                build(ROOT / "public", source, output)
            self.assertEqual((output / "keep").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
