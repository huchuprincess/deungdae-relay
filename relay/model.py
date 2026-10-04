"""Public contract and time rules. A successful HTTP response is not an alert."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re
from zoneinfo import ZoneInfo

from .safety import RelayError, require_public

UTC = timezone.utc
KST = ZoneInfo("Asia/Seoul")
POLL_SECONDS = 600
STALE_SECONDS = 1800
MAX_BYTES = 4 * 1024 * 1024
FEEDS = ("weather", "earthquake")
NOTICES = {
    "unconfigured": "실제 조회 전입니다. 최신 재난 자료가 아닙니다.",
    "example": "직접 만든 예제입니다. 실제 재난 자료가 아닙니다.",
    "live": "정부 공개 자료의 조회용 중계입니다. 공식 경보 수신 서비스가 아닙니다.",
}
SOURCES = {
    "weather": {
        "provider": "기상청", "dataset": "기상청_기상특보 조회서비스",
        "url": "https://www.data.go.kr/data/15000415/openapi.do",
        "license": "공공누리 제1유형, 출처표시",
        "licenseUrl": "https://www.kogl.or.kr/info/licenseType1.do",
        "termsCheckedOn": "2026-10-04",
    },
    "earthquake": {
        "provider": "기상청", "dataset": "기상청_지진정보 조회서비스",
        "url": "https://www.data.go.kr/data/15000420/openapi.do",
        "license": "이용허락범위 제한 없음",
        "licenseUrl": "https://www.data.go.kr/data/15000420/openapi.do",
        "termsCheckedOn": "2026-10-04",
    },
}


def stamp(value):
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_stamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise RelayError("invalid-snapshot")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RelayError("invalid-snapshot") from None


def nullable_stamp(value):
    return None if value is None else parse_stamp(value)


def api_time(value):
    text = str(value)
    if not re.fullmatch(r"\d{12}(?:\d{2})?", text):
        raise RelayError("invalid-response")
    try:
        return stamp(datetime.strptime(text, "%Y%m%d%H%M" if len(text) == 12 else "%Y%m%d%H%M%S").replace(tzinfo=KST))
    except ValueError:
        raise RelayError("invalid-response") from None


def text_field(value, limit=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RelayError("invalid-response")
    if any(ord(ch) < 32 and ch not in "\n\t\r" for ch in value):
        raise RelayError("invalid-response")
    require_public(value)
    return value


def number_field(value, lower, upper):
    if isinstance(value, bool):
        raise RelayError("invalid-response")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise RelayError("invalid-response") from None
    if not math.isfinite(number) or not lower <= number <= upper:
        raise RelayError("invalid-response")
    return number


def identifier(parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()[:24]


def blank(mode="unconfigured"):
    return {
        "schemaVersion": 1, "mode": mode, "notice": NOTICES[mode],
        "generatedAt": None, "pollAfterSeconds": POLL_SECONDS,
        "staleAfterSeconds": STALE_SECONDS,
        "feeds": {name: {
            "source": deepcopy(SOURCES[name]), "lastAttemptAt": None,
            "lastAttemptStatus": "not-requested", "failureCode": None,
            "lastSuccessAt": None, "data": None,
        } for name in FEEDS},
    }


def _keys(obj, expected):
    if not isinstance(obj, dict) or set(obj) != set(expected):
        raise RelayError("invalid-snapshot")


def validate(snapshot, secrets=()):
    """Exact allowlists also apply to old snapshots read from public hosting."""
    _keys(snapshot, ("schemaVersion", "mode", "notice", "generatedAt", "pollAfterSeconds", "staleAfterSeconds", "feeds"))
    mode = snapshot["mode"]
    if type(snapshot["schemaVersion"]) is not int or snapshot["schemaVersion"] != 1 or mode not in NOTICES or snapshot["notice"] != NOTICES[mode]:
        raise RelayError("invalid-snapshot")
    if snapshot["pollAfterSeconds"] != POLL_SECONDS or snapshot["staleAfterSeconds"] != STALE_SECONDS:
        raise RelayError("invalid-snapshot")
    generated = nullable_stamp(snapshot["generatedAt"])
    _keys(snapshot["feeds"], FEEDS)
    for name, feed in snapshot["feeds"].items():
        _keys(feed, ("source", "lastAttemptAt", "lastAttemptStatus", "failureCode", "lastSuccessAt", "data"))
        if feed["source"] != SOURCES[name]:
            raise RelayError("invalid-snapshot")
        status = feed["lastAttemptStatus"]
        if status not in ("not-requested", "success", "failure", "unconfigured"):
            raise RelayError("invalid-snapshot")
        if status in ("failure", "unconfigured"):
            if feed["failureCode"] not in RelayError.CODES:
                raise RelayError("invalid-snapshot")
        elif feed["failureCode"] is not None:
            raise RelayError("invalid-snapshot")
        attempted = nullable_stamp(feed["lastAttemptAt"])
        success = nullable_stamp(feed["lastSuccessAt"])
        if (status == "not-requested") != (attempted is None):
            raise RelayError("invalid-snapshot")
        if attempted and (not generated or attempted > generated):
            raise RelayError("invalid-snapshot")
        if success and (not attempted or success > attempted):
            raise RelayError("invalid-snapshot")
        if status == "success" and (success is None or success != attempted):
            raise RelayError("invalid-snapshot")
        data = feed["data"]
        if (data is None) != (success is None) or (mode == "unconfigured" and data is not None):
            raise RelayError("invalid-snapshot")
        if data is None:
            continue
        _keys(data, ("sourceResponseAt", "queryFrom", "queryTo", "coverage", "regionStateVerified", "records"))
        response_time = parse_stamp(data["sourceResponseAt"])
        if response_time > success + timedelta(minutes=5) or success - response_time > timedelta(seconds=STALE_SECONDS):
            raise RelayError("invalid-snapshot")
        for field in ("queryFrom", "queryTo"):
            if not isinstance(data[field], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", data[field]):
                raise RelayError("invalid-snapshot")
            try:
                datetime.strptime(data[field], "%Y-%m-%d")
            except ValueError:
                raise RelayError("invalid-snapshot") from None
        if data["queryFrom"] > data["queryTo"] or data["regionStateVerified"] is not False:
            raise RelayError("invalid-snapshot")
        if data["coverage"] != ("bulletin-history" if name == "weather" else "event-history"):
            raise RelayError("invalid-snapshot")
        records = data["records"]
        if not isinstance(records, list) or len(records) > 1000:
            raise RelayError("invalid-snapshot")
        ids = set()
        for record in records:
            common = ("id", "publishedAt", "effectiveAt", "releasedAt", "expiresAt", "state")
            specific = ("title", "stationCode") if name == "weather" else ("occurredAt", "latitude", "longitude", "magnitude", "location", "intensity", "correction")
            _keys(record, common + specific)
            if not isinstance(record["id"], str) or not re.fullmatch(r"[a-f0-9]{24}", record["id"]) or record["id"] in ids:
                raise RelayError("invalid-snapshot")
            ids.add(record["id"])
            published = parse_stamp(record["publishedAt"])
            if published > success + timedelta(minutes=5):
                raise RelayError("invalid-snapshot")
            if not data["queryFrom"] <= published.astimezone(KST).date().isoformat() <= data["queryTo"]:
                raise RelayError("invalid-snapshot")
            # Neither verified operation supplies a structured warning lifecycle.
            # Do not infer activation or cancellation from bulletin titles.
            if any(record[f] is not None for f in ("effectiveAt", "releasedAt", "expiresAt")):
                raise RelayError("invalid-snapshot")
            if record["state"] != ("unconfirmed" if name == "weather" else "reported"):
                raise RelayError("invalid-snapshot")
            if name == "weather":
                text_field(record["title"], 1000)
                if record["stationCode"] is not None and not re.fullmatch(r"\d{1,5}", record["stationCode"]):
                    raise RelayError("invalid-snapshot")
            else:
                if parse_stamp(record["occurredAt"]) > published:
                    raise RelayError("invalid-snapshot")
                number_field(record["latitude"], -90, 90)
                number_field(record["longitude"], -180, 180)
                if record["magnitude"] is not None:
                    number_field(record["magnitude"], 0, 10)
                text_field(record["location"], 300)
                for field in ("intensity", "correction"):
                    if record[field] is not None:
                        text_field(record[field], 1000)
    serialized = dumps(snapshot)
    if len(serialized.encode("utf-8")) > MAX_BYTES:
        raise RelayError("invalid-snapshot")
    require_public(serialized, secrets)
    return snapshot


def dumps(snapshot):
    return json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def load(raw):
    if len(raw) > MAX_BYTES:
        raise RelayError("invalid-snapshot")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RelayError("invalid-snapshot")
            result[key] = value
        return result
    try:
        return validate(json.loads(raw, object_pairs_hook=unique))
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError):
        raise RelayError("invalid-snapshot") from None


def update(previous, mode, now, fetch, secrets=(), clock=None):
    if previous is not None:
        validate(previous, secrets)
        if previous["mode"] != mode:
            raise RelayError("invalid-snapshot")
        if previous["generatedAt"] and parse_stamp(previous["generatedAt"]) > now:
            raise RelayError("future-time")
    result = deepcopy(previous) if previous is not None else blank(mode)
    result["generatedAt"] = stamp(now)
    for name in FEEDS:
        feed = result["feeds"][name]
        completed = now
        try:
            data = fetch(name)
            completed = clock() if clock else now
            feed["lastAttemptAt"] = stamp(completed)
            result["generatedAt"] = stamp(completed)
            response_time = parse_stamp(data["sourceResponseAt"])
            if completed - response_time > timedelta(seconds=STALE_SECONDS):
                raise RelayError("stale-upstream")
            if response_time > completed + timedelta(minutes=5):
                raise RelayError("future-time")
            candidate = deepcopy(result)
            candidate["feeds"][name].update(lastAttemptStatus="success", failureCode=None,
                                           lastSuccessAt=stamp(completed), data=data)
            validate(candidate, secrets)
            if feed["data"] is not None:
                # A successful but older response cannot roll the feed backwards.
                if response_time < parse_stamp(feed["data"]["sourceResponseAt"]):
                    raise RelayError("stale-upstream")
                old_times = [r["publishedAt"] for r in feed["data"]["records"]]
                new_times = [r["publishedAt"] for r in data["records"]]
                if old_times and any(data["queryFrom"] <= parse_stamp(t).astimezone(KST).date().isoformat() <= data["queryTo"] for t in old_times):
                    if not new_times or max(new_times) < max(old_times):
                        raise RelayError("stale-upstream")
            feed.update(lastAttemptStatus="success", failureCode=None,
                        lastSuccessAt=stamp(completed), data=data)
        except RelayError as exc:
            completed = clock() if clock else now
            feed["lastAttemptAt"] = stamp(completed)
            result["generatedAt"] = stamp(completed)
            feed["lastAttemptStatus"] = "unconfigured" if exc.code == "missing-key" else "failure"
            feed["failureCode"] = exc.code
        except Exception:
            completed = clock() if clock else now
            feed["lastAttemptAt"] = stamp(completed)
            result["generatedAt"] = stamp(completed)
            feed["lastAttemptStatus"] = "failure"
            feed["failureCode"] = "unexpected"
    return validate(result, secrets)


def presentation(feed, now, mode="live", transport_failed=False):
    """Reference display rules; consumers recompute them on every reading."""
    success = parse_stamp(feed["lastSuccessAt"]) if feed["lastSuccessAt"] else None
    stale = bool(success and (now - success).total_seconds() > STALE_SECONDS)
    future = bool(success and success > now + timedelta(minutes=5))
    failed = transport_failed or feed["lastAttemptStatus"] in ("failure", "unconfigured")
    label = "조회 전"
    if mode == "example":
        label = "예제 자료"
    elif failed:
        label = "조회 실패" if feed["lastAttemptStatus"] != "unconfigured" else "조회 전"
    elif stale or future:
        label = "갱신 지연"
    elif success:
        label = "조회 성공"
    else:
        label = "조회 전"
    return {
        "label": label, "delayed": stale or future,
        "referenceOnly": failed or stale or future or mode != "live",
        "lastSuccessAt": feed["lastSuccessAt"],
        # A complete bulletin history is not a current regional warning snapshot.
        "noWarningsConfirmed": False,
        "earthquakeIsCurrent": False,
    }
