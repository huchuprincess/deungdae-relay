from contextlib import redirect_stdout
from copy import deepcopy
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from relay.model import (blank, dumps, load, parse_stamp, presentation,
                         identifier, stamp, update, validate)
from relay.provider import NoRedirect, PublicAPI, normalize, parse_page, response_time
from relay.run import atomic_write, fixture_fetch, main
from relay.safety import RelayError

ROOT = Path(__file__).resolve().parents[1]
NOW = parse_stamp("2000-01-02T03:10:00Z")
HTTP_DATE = "Sun, 02 Jan 2000 03:10:00 GMT"
FETCH = fixture_fetch(ROOT / "fixtures")


def good(mode="live", now=NOW):
    return update(None, mode, now, FETCH)


def page(rows, total=None, page_no=1, code="00"):
    return json.dumps({"response": {"header": {"resultCode": code, "resultMsg": "fixture"},
                                   "body": {"totalCount": len(rows) if total is None else total,
                                            "pageNo": page_no, "numOfRows": 100,
                                            "dataType": "JSON", "items": {"item": rows}}}}).encode()


def history_with_older_record(name):
    previous = good()
    data = previous["feeds"][name]["data"]
    latest = deepcopy(max(data["records"], key=lambda record: record["publishedAt"]))
    older = dict(latest, id=identifier((name, "synthetic-older-record")),
                 publishedAt=stamp(parse_stamp(latest["publishedAt"]) - timedelta(minutes=5)))
    data["records"] = [latest, older]
    return validate(previous), latest, older


class StateTests(unittest.TestCase):
    def test_bootstrap_has_no_success_or_safety_claim(self):
        result = validate(blank())
        self.assertEqual(result["mode"], "unconfigured")
        for feed in result["feeds"].values():
            self.assertIsNone(feed["lastSuccessAt"])
            self.assertIsNone(feed["data"])
            self.assertFalse(presentation(feed, NOW)["noWarningsConfirmed"])

    def test_partial_failure_preserves_exact_last_valid_data_and_time(self):
        previous = good()
        def fetch(name):
            if name == "weather":
                raise RelayError("transport")
            return FETCH(name)
        result = update(previous, "live", NOW + timedelta(minutes=10), fetch)
        before, after = previous["feeds"]["weather"], result["feeds"]["weather"]
        self.assertEqual(after["data"], before["data"])
        self.assertEqual(after["lastSuccessAt"], before["lastSuccessAt"])
        self.assertEqual(after["lastAttemptStatus"], "failure")
        self.assertEqual(result["feeds"]["earthquake"]["lastAttemptStatus"], "success")
        self.assertEqual(previous, good())

    def test_success_time_is_validation_completion_not_job_start(self):
        times = iter((NOW + timedelta(seconds=20), NOW + timedelta(seconds=40)))
        result = update(None, "live", NOW, FETCH, clock=lambda: next(times))
        self.assertEqual(result["feeds"]["weather"]["lastSuccessAt"], stamp(NOW + timedelta(seconds=20)))
        self.assertEqual(result["feeds"]["earthquake"]["lastSuccessAt"], stamp(NOW + timedelta(seconds=40)))
        self.assertEqual(result["generatedAt"], stamp(NOW + timedelta(seconds=40)))

    def test_empty_string_timestamp_or_success_without_time_is_invalid(self):
        for field in ("generatedAt", "lastSuccessAt"):
            value = blank()
            if field == "generatedAt":
                value[field] = ""
            else:
                value["feeds"]["weather"][field] = ""
            with self.assertRaises(RelayError):
                validate(value)
        value = blank(); value["feeds"]["weather"]["lastAttemptStatus"] = "success"
        with self.assertRaises(RelayError):
            validate(value)

    def test_http_success_with_old_source_time_does_not_advance_success(self):
        old = good()
        def fetch(name):
            data = FETCH(name)
            data["sourceResponseAt"] = "2000-01-02T02:00:00Z"
            return data
        result = update(old, "live", NOW + timedelta(minutes=10), fetch)
        for name in old["feeds"]:
            self.assertEqual(result["feeds"][name]["data"], old["feeds"][name]["data"])
            self.assertEqual(result["feeds"][name]["lastSuccessAt"], old["feeds"][name]["lastSuccessAt"])
            self.assertEqual(result["feeds"][name]["lastAttemptStatus"], "failure")

    def test_successful_but_regressing_recent_snapshot_is_rejected(self):
        old = good()
        def fetch(name):
            data = FETCH(name)
            data["sourceResponseAt"] = "2000-01-02T03:09:00Z"
            return data
        result = update(old, "live", NOW + timedelta(minutes=1), fetch)
        self.assertEqual(result["feeds"]["weather"]["failureCode"], "stale-upstream")

    def test_false_empty_success_cannot_erase_recent_history(self):
        old = good()
        def fetch(name):
            data = FETCH(name)
            data["sourceResponseAt"] = "2000-01-02T03:20:00Z"
            data["records"] = []
            return data
        result = update(old, "live", NOW + timedelta(minutes=10), fetch)
        self.assertEqual(result["feeds"]["weather"]["failureCode"], "stale-upstream")
        self.assertEqual(result["feeds"]["earthquake"]["data"], old["feeds"]["earthquake"]["data"])

    def test_older_record_omission_with_latest_time_kept_replaces_history(self):
        for name in ("weather", "earthquake"):
            with self.subTest(feed=name):
                previous, latest, older = history_with_older_record(name)
                incoming = deepcopy(previous["feeds"][name]["data"])
                incoming["sourceResponseAt"] = stamp(NOW + timedelta(minutes=10))
                incoming["records"] = [latest]
                def fetch(feed_name):
                    return incoming if feed_name == name else FETCH(feed_name)
                result = update(previous, "live", NOW + timedelta(minutes=10), fetch)
                feed = result["feeds"][name]
                self.assertEqual(incoming["queryFrom"], previous["feeds"][name]["data"]["queryFrom"])
                self.assertEqual(incoming["queryTo"], previous["feeds"][name]["data"]["queryTo"])
                self.assertEqual(feed["lastAttemptStatus"], "success")
                self.assertEqual(feed["lastSuccessAt"], stamp(NOW + timedelta(minutes=10)))
                self.assertEqual(feed["data"], incoming)
                self.assertNotIn(older["id"], {r["id"] for r in feed["data"]["records"]})
                self.assertEqual(previous["feeds"][name]["data"]["records"], [latest, older])

    def test_latest_record_omission_with_only_older_time_keeps_previous(self):
        for name in ("weather", "earthquake"):
            with self.subTest(feed=name):
                previous, latest, older = history_with_older_record(name)
                incoming = deepcopy(previous["feeds"][name]["data"])
                incoming["sourceResponseAt"] = stamp(NOW + timedelta(minutes=10))
                incoming["records"] = [older]
                def fetch(feed_name):
                    return incoming if feed_name == name else FETCH(feed_name)
                result = update(previous, "live", NOW + timedelta(minutes=10), fetch)
                feed = result["feeds"][name]
                self.assertEqual(feed["lastAttemptStatus"], "failure")
                self.assertEqual(feed["failureCode"], "stale-upstream")
                self.assertEqual(feed["lastSuccessAt"], previous["feeds"][name]["lastSuccessAt"])
                self.assertEqual(feed["data"], previous["feeds"][name]["data"])

    def test_valid_initial_empty_history_still_cannot_confirm_no_warning(self):
        def fetch(name):
            data = FETCH(name)
            data["records"] = []
            return data
        result = update(None, "live", NOW, fetch)
        feed = result["feeds"]["weather"]
        self.assertEqual(feed["lastAttemptStatus"], "success")
        self.assertFalse(presentation(feed, NOW)["noWarningsConfirmed"])

    def test_missing_key_is_not_an_empty_success(self):
        provider = PublicAPI("", NOW, True, transport=lambda _: self.fail("network called"))
        result = update(good(), "live", NOW + timedelta(minutes=10), provider.fetch)
        self.assertEqual(result["feeds"]["weather"]["lastAttemptStatus"], "unconfigured")
        self.assertEqual(result["feeds"]["weather"]["lastSuccessAt"], stamp(NOW))

    def test_delay_boundary_and_client_transport_failure_are_separate(self):
        feed = good()["feeds"]["weather"]
        self.assertFalse(presentation(feed, NOW + timedelta(minutes=30))["delayed"])
        delayed = presentation(feed, NOW + timedelta(minutes=30, seconds=1))
        self.assertEqual(delayed["label"], "갱신 지연")
        failed = presentation(feed, NOW + timedelta(minutes=31), transport_failed=True)
        self.assertEqual(failed["label"], "조회 실패")
        self.assertTrue(failed["delayed"])
        self.assertTrue(failed["referenceOnly"])

    def test_generated_time_does_not_refresh_failed_feed(self):
        def fetch(_):
            raise RelayError("transport")
        result = update(good(), "live", NOW + timedelta(hours=2), fetch)
        state = presentation(result["feeds"]["weather"], NOW + timedelta(hours=2))
        self.assertTrue(state["delayed"])
        self.assertEqual(state["lastSuccessAt"], stamp(NOW))

    def test_earthquake_is_always_a_dated_report(self):
        feed = good()["feeds"]["earthquake"]
        self.assertLess(feed["data"]["records"][0]["occurredAt"], feed["lastSuccessAt"])
        self.assertFalse(presentation(feed, NOW)["earthquakeIsCurrent"])

    def test_release_title_is_not_inferred_as_an_active_warning(self):
        records = good()["feeds"]["weather"]["data"]["records"]
        self.assertTrue(any("해제" in r["title"] for r in records))
        self.assertTrue(all(r["state"] == "unconfirmed" for r in records))
        self.assertTrue(all(r["effectiveAt"] is None and r["releasedAt"] is None for r in records))

    def test_forged_lifecycle_or_expiry_cannot_be_published_as_active(self):
        old = good()
        for field, value in (("state", "active"), ("releasedAt", stamp(NOW)),
                             ("expiresAt", "2000-01-01T00:00:00Z")):
            with self.subTest(field=field):
                def fetch(name):
                    data = FETCH(name)
                    if name == "weather":
                        data["records"][0][field] = value
                    return data
                result = update(old, "live", NOW, fetch)
                self.assertEqual(result["feeds"]["weather"]["data"], old["feeds"]["weather"]["data"])
                self.assertEqual(result["feeds"]["weather"]["lastAttemptStatus"], "failure")

    def test_example_cannot_seed_live(self):
        with self.assertRaises(RelayError):
            update(good("example"), "live", NOW, FETCH)

    def test_future_baseline_stops_before_fetch(self):
        with self.assertRaises(RelayError):
            update(good(), "live", NOW - timedelta(seconds=1), lambda _: self.fail("fetched"))

    def test_future_upstream_does_not_refresh(self):
        def fetch(name):
            data = FETCH(name)
            data["sourceResponseAt"] = stamp(NOW + timedelta(hours=1))
            return data
        result = update(good(), "live", NOW, fetch)
        self.assertEqual(result["feeds"]["weather"]["lastAttemptStatus"], "failure")

    def test_unknown_fields_duplicate_json_nan_and_bad_time_rejected(self):
        cases = []
        value = good(); value["profile"] = {"location": "synthetic"}; cases.append(dumps(value).encode())
        cases.append(b'{"schemaVersion":1,"schemaVersion":1}')
        value = good(); value["feeds"]["earthquake"]["data"]["records"][0]["latitude"] = float("nan")
        cases.append(json.dumps(value).encode())
        value = good(); value["feeds"]["weather"]["lastSuccessAt"] = "2000-01-02T12:10:00+09:00"; cases.append(dumps(value).encode())
        for raw in cases:
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(RelayError):
                    load(raw)

    def test_known_secret_echo_is_rejected_without_redaction(self):
        secret = "synthetic-check-" + "value"
        def fetch(name):
            data = FETCH(name)
            if name == "weather":
                data["records"][0]["title"] = secret
            return data
        result = update(good(), "live", NOW, fetch, (secret,))
        self.assertEqual(result["feeds"]["weather"]["failureCode"], "sensitive-output")
        self.assertNotIn(secret, dumps(result))

    def test_oversized_normalized_feed_keeps_last_valid_snapshot(self):
        old = good()
        def fetch(name):
            data = FETCH(name)
            if name == "earthquake":
                row = data["records"][0]
                data["records"] = [dict(row, id=identifier(("synthetic-large", i)),
                                        intensity="예" * 1000, correction="예" * 1000) for i in range(1000)]
            return data
        result = update(old, "live", NOW + timedelta(minutes=10), fetch)
        self.assertEqual(result["feeds"]["earthquake"]["lastAttemptStatus"], "failure")
        self.assertEqual(result["feeds"]["earthquake"]["data"], old["feeds"]["earthquake"]["data"])


class ProviderTests(unittest.TestCase):
    def row(self, name="weather"):
        return json.loads((ROOT / "fixtures" / (name + ".json")).read_text())["records"][0]

    def test_verified_operations_and_single_key_encoding(self):
        paths = {"weather": "/1360000/WthrWrnInfoService/getWthrWrnList",
                 "earthquake": "/1360000/EqkInfoService/getEqkMsg"}
        for name, expected_path in paths.items():
            for key in ("synthetic%2Bkey%2Fvalue%3D", "synthetic+key/value="):
                with self.subTest(feed=name, encoded="%" in key):
                    calls = []
                    def transport(url):
                        calls.append(url)
                        return page([self.row(name)]), {"Date": HTTP_DATE}
                    result = PublicAPI(key, NOW, True, transport).fetch(name)
                    target = urlsplit(calls[0])
                    query = parse_qs(target.query)
                    self.assertEqual(target.scheme, "https")
                    self.assertEqual(target.hostname, "apis.data.go.kr")
                    self.assertEqual(target.path, expected_path)
                    self.assertEqual(query["ServiceKey"], ["synthetic+key/value="])
                    self.assertNotIn("serviceKey", query)
                    self.assertEqual(query["fromTmFc"], ["19991226"])
                    self.assertEqual(query["toTmFc"], ["20000102"])
                    self.assertEqual(result["records"][0]["publishedAt"], "2000-01-02T03:00:00Z")

    def test_local_midnight_uses_korean_calendar_range(self):
        now = parse_stamp("2000-01-01T15:00:00Z")
        calls = []
        def transport(url):
            calls.append(parse_qs(urlsplit(url).query))
            return page([]), {"Date": "Sat, 01 Jan 2000 15:00:00 GMT"}
        result = PublicAPI("synthetic", now, True, transport).fetch("weather")
        self.assertEqual(result["queryTo"], "2000-01-02")
        self.assertEqual(calls[0]["fromTmFc"], ["19991226"])

    def test_both_empty_representations_require_explicit_complete_success(self):
        for container in ("", None, {}, {"item": []}):
            raw = json.loads(page([])); raw["response"]["body"]["items"] = container
            self.assertEqual(parse_page(json.dumps(raw), 1), ([], 0))

    def test_api_error_even_with_http_200_is_failure(self):
        provider = PublicAPI("synthetic", NOW, True, lambda _: (page([], code="20"), {"Date": HTTP_DATE}))
        with self.assertRaisesRegex(RelayError, "upstream-error"):
            provider.fetch("weather")

    def test_xml_error_or_invalid_json_is_not_success(self):
        for raw in (b"<error>synthetic</error>", b"not json"):
            with self.assertRaises(RelayError):
                parse_page(raw, 1)

    def test_incomplete_page_is_failure(self):
        with self.assertRaisesRegex(RelayError, "pagination"):
            parse_page(page([self.row()], total=2), 1)

    def test_all_pages_collected_before_success(self):
        rows = [dict(self.row(), tmSeq=i) for i in range(101)]
        calls = []
        def transport(url):
            n = int(parse_qs(urlsplit(url).query)["pageNo"][0]); calls.append(n)
            return page(rows[(n-1)*100:n*100], total=101, page_no=n), {"Date": HTTP_DATE}
        result = PublicAPI("synthetic", NOW, True, transport).fetch("weather")
        self.assertEqual(calls, [1, 2])
        self.assertEqual(len(result["records"]), 101)

    def test_total_count_change_or_duplicate_page_is_failure(self):
        rows = [dict(self.row(), tmSeq=i) for i in range(100)]
        for total in (101, 102):
            def transport(url):
                n = int(parse_qs(urlsplit(url).query)["pageNo"][0])
                return page(rows if n == 1 else [rows[0]], total=101 if n == 1 else total, page_no=n), {"Date": HTTP_DATE}
            with self.assertRaises(RelayError):
                PublicAPI("synthetic", NOW, True, transport).fetch("weather")

    def test_unknown_raw_fields_are_dropped(self):
        row = dict(self.row(), internal="discard", serviceKey="synthetic-echo")
        result = normalize("weather", row)
        self.assertNotIn("internal", result)
        self.assertNotIn("synthetic-echo", json.dumps(result))

    def test_old_http_date_age_missing_date_and_future_date_are_failures(self):
        for headers in ({"Date": "Sun, 02 Jan 2000 01:00:00 GMT"},
                        {"Date": HTTP_DATE, "Age": "1801"}, {},
                        {"Date": "Sun, 02 Jan 2000 04:00:00 GMT"}):
            with self.subTest(headers=headers), self.assertRaises(RelayError):
                response_time(headers, NOW)

    def test_redirect_is_blocked_before_forwarding_credentials(self):
        with self.assertRaises(RelayError):
            NoRedirect().redirect_request(None, None, 302, "fixture", {}, "https://example.invalid/")

    def test_unverified_live_is_blocked_before_network(self):
        with self.assertRaisesRegex(RelayError, "not-verified"):
            PublicAPI("synthetic", NOW, False, lambda _: self.fail("network called")).fetch("weather")


class CommandTests(unittest.TestCase):
    def test_default_and_example_do_not_read_credentials_or_use_network(self):
        with tempfile.TemporaryDirectory() as directory, patch("relay.run.os.environ", {}) as env, patch("socket.create_connection", side_effect=AssertionError("network")), redirect_stdout(io.StringIO()):
            output = Path(directory) / "snapshot.json"
            self.assertEqual(main(["--output", str(output)]), 0)
            self.assertEqual(load(output.read_bytes())["mode"], "unconfigured")
            self.assertEqual(main(["--mode", "example", "--fixtures", str(ROOT / "fixtures"), "--output", str(output)]), 0)
            self.assertEqual(load(output.read_bytes())["mode"], "example")
            self.assertEqual(env, {})

    def test_live_without_key_has_no_fake_success(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {}, clear=True), patch("socket.create_connection", side_effect=AssertionError("network")), redirect_stdout(io.StringIO()):
            output = Path(directory) / "snapshot.json"
            self.assertEqual(main(["--mode", "live", "--output", str(output)]), 0)
            result = load(output.read_bytes())
            self.assertEqual(result["mode"], "unconfigured")
            self.assertTrue(all(f["lastSuccessAt"] is None for f in result["feeds"].values()))

    def test_missing_or_corrupt_previous_does_not_replace_output(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            output = Path(directory) / "snapshot.json"; output.write_text("keep")
            missing = Path(directory) / "missing.json"
            self.assertEqual(main(["--mode", "live", "--previous", str(missing), "--output", str(output)]), 2)
            missing.write_text("corrupt")
            self.assertEqual(main(["--mode", "live", "--previous", str(missing), "--output", str(output)]), 2)
            self.assertEqual(output.read_text(), "keep")

    def test_cli_failure_logs_do_not_echo_exception_or_path(self):
        secret = "synthetic-test-" + "private-value"
        stream = io.StringIO()
        with patch("relay.run.atomic_write", side_effect=OSError(secret)), redirect_stdout(stream):
            self.assertEqual(main(["--output", "unused.json"]), 2)
        self.assertNotIn(secret, stream.getvalue())
        self.assertNotIn("Traceback", stream.getvalue())

    def test_local_atomic_write_failure_keeps_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "latest.json"; output.write_text("keep")
            with patch.object(Path, "replace", side_effect=OSError("fixture")), self.assertRaises(OSError):
                atomic_write(output, "new")
            self.assertEqual(output.read_text(), "keep")
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_file_link_is_rejected_but_trusted_parent_link_is_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual"; actual.mkdir()
            output = actual / "snapshot.json"; output.write_text("keep")
            file_link = root / "file-link.json"; file_link.symlink_to(output)
            with self.assertRaisesRegex(RelayError, "io"):
                atomic_write(file_link, "rejected")
            self.assertEqual(output.read_text(), "keep")
            parent_link = root / "parent-link"; parent_link.symlink_to(actual, target_is_directory=True)
            atomic_write(parent_link / "snapshot.json", "accepted in a trusted directory")
            self.assertTrue(parent_link.is_symlink())
            self.assertEqual(output.read_text(), "accepted in a trusted directory")

    def test_live_cannot_use_fabricated_clock(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--mode", "live", "--now", stamp(NOW), "--output", "unused.json"]), 2)


if __name__ == "__main__":
    unittest.main()
