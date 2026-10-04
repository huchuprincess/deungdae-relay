"""Only documented data.go.kr operations. No scraping, redirects or raw dumps."""

from datetime import timedelta
from email.utils import parsedate_to_datetime
import json
from urllib.parse import urlencode, unquote
from urllib.request import Request, HTTPRedirectHandler, build_opener

from .model import (KST, MAX_BYTES, STALE_SECONDS, api_time, identifier,
                    number_field, parse_stamp, stamp, text_field)
from .safety import RelayError

ENDPOINTS = {
    "weather": "https://apis.data.go.kr/1360000/WthrWrnInfoService/getWthrWrnList",
    "earthquake": "https://apis.data.go.kr/1360000/EqkInfoService/getEqkMsg",
}
ROWS = 100
MAX_PAGES = 10


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RelayError("transport")


def http_get(url):
    try:
        request = Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"})
        with build_opener(NoRedirect).open(request, timeout=15) as response:
            if response.status != 200 or "json" not in response.headers.get("Content-Type", "").lower():
                raise RelayError("invalid-response")
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise RelayError("invalid-response")
            return raw, dict(response.headers)
    except RelayError:
        raise
    except Exception:
        # urllib errors can contain the complete authenticated URL.
        raise RelayError("transport") from None


def response_time(headers, now):
    h = {k.lower(): v for k, v in headers.items()}
    try:
        value = parsedate_to_datetime(h["date"])
        age = int(h.get("age", "0"))
        if value.tzinfo is None or age < 0:
            raise ValueError
    except (ValueError, KeyError, TypeError, OverflowError):
        raise RelayError("invalid-response") from None
    # HTTP Date is a transport timestamp, not a claim about source observation time.
    if age > STALE_SECONDS or now - value > timedelta(seconds=STALE_SECONDS):
        raise RelayError("stale-upstream")
    if value > now + timedelta(minutes=5):
        raise RelayError("future-time")
    return stamp(value)


def parse_page(raw, page_no):
    try:
        def unique(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError
                obj[key] = value
            return obj
        document = json.loads(raw, object_pairs_hook=unique)
        response = document["response"]
        if response["header"]["resultCode"] != "00":
            raise RelayError("upstream-error")
        body = response["body"]
        def integer(value):
            if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
                raise RelayError("pagination")
            return int(value)
        total = integer(body["totalCount"])
        if total > ROWS * MAX_PAGES or integer(body["pageNo"]) != page_no or integer(body["numOfRows"]) != ROWS:
            raise RelayError("pagination")
        if body["dataType"] != "JSON":
            raise RelayError("invalid-response")
        container = body["items"]
        if total == 0 and container in ("", None, {}):
            records = []
        else:
            records = container["item"]
            if isinstance(records, dict):
                records = [records]
        if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
            raise RelayError("invalid-response")
        expected = min(ROWS, max(0, total - (page_no - 1) * ROWS))
        if len(records) != expected:
            raise RelayError("pagination")
        return records, total
    except RelayError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        raise RelayError("invalid-response") from None


def normalize(name, row):
    try:
        published = api_time(row["tmFc"])
        station = str(row["stnId"]) if row.get("stnId") is not None else None
        result = {
            "id": identifier((name, published, station, row.get("tmSeq"), row.get("cnt"))),
            "publishedAt": published, "effectiveAt": None,
            "releasedAt": None, "expiresAt": None,
            "state": "unconfirmed" if name == "weather" else "reported",
        }
        if name == "weather":
            result.update(title=text_field(row["title"]), stationCode=station)
        else:
            result.update(
                occurredAt=api_time(row["tmEqk"]),
                latitude=number_field(row["lat"], -90, 90),
                longitude=number_field(row["lon"], -180, 180),
                magnitude=None if row.get("mt") in (None, "") else number_field(row["mt"], 0, 10),
                location=text_field(row["loc"], 300),
                intensity=None if row.get("inT") in (None, "") else text_field(row["inT"]),
                correction=None if row.get("cor") in (None, "") else text_field(row["cor"]),
            )
        return result
    except KeyError:
        raise RelayError("invalid-response") from None


class PublicAPI:
    def __init__(self, key, now, verified=False, transport=http_get):
        self.key = key
        self.now = now
        self.verified = verified
        self.transport = transport

    def fetch(self, name):
        if not self.key:
            raise RelayError("missing-key")
        if not self.verified:
            raise RelayError("not-verified")
        # Date range is Korean calendar time, including the current day.
        end = self.now.astimezone(KST).date()
        start = end - timedelta(days=7)
        records, total, as_of = [], None, []
        for page in range(1, MAX_PAGES + 1):
            params = {
                "ServiceKey": unquote(self.key), "pageNo": page,
                "numOfRows": ROWS, "dataType": "JSON",
                "fromTmFc": start.strftime("%Y%m%d"),
                "toTmFc": end.strftime("%Y%m%d"),
            }
            raw, headers = self.transport(ENDPOINTS[name] + "?" + urlencode(params))
            as_of.append(response_time(headers, self.now))
            rows, page_total = parse_page(raw, page)
            if total is not None and total != page_total:
                raise RelayError("pagination")
            total = page_total
            records.extend(normalize(name, row) for row in rows)
            if len(records) == total:
                break
        if len(records) != total or len({r["id"] for r in records}) != len(records):
            raise RelayError("pagination")
        records.sort(key=lambda r: (r["publishedAt"], r["id"]), reverse=True)
        return {
            "sourceResponseAt": min(as_of), "queryFrom": start.isoformat(),
            "queryTo": end.isoformat(),
            "coverage": "bulletin-history" if name == "weather" else "event-history",
            "regionStateVerified": False, "records": records,
        }
