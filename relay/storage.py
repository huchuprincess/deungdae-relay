"""R2 atomic snapshot and Pages baseline. No object listing or deletion."""

import argparse
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, build_opener

from .model import MAX_BYTES, UTC, blank, dumps, load, parse_stamp, validate
from .provider import NoRedirect
from .run import atomic_write
from .safety import RelayError

PAGES_URL = "https://huchuprincess.github.io/deungdae-relay/v1/latest.json"
CACHE_CONTROL = "public, max-age=0, s-maxage=300, must-revalidate"


def request_bytes(request):
    try:
        with build_opener(NoRedirect).open(request, timeout=20) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise RelayError("storage")
            return response.status, {k.lower(): v for k, v in response.headers.items()}, raw
    except HTTPError as exc:
        # Error bodies, authenticated URLs and headers never leave this function.
        if exc.code in (404, 409, 412):
            return exc.code, {}, b""
        raise RelayError("storage") from None
    except RelayError:
        raise
    except Exception:
        raise RelayError("storage") from None


def signing_headers(method, host, path, payload, access, secret, now, extra=None, region="auto"):
    """AWS Signature V4 for the fixed R2 object; headers included in the signature."""
    date = now.strftime("%Y%m%d")
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(payload).hexdigest()
    headers = {"host": host, "x-amz-date": timestamp, "x-amz-content-sha256": digest}
    headers.update(extra or {})
    headers = {k.lower(): " ".join(v.split()) for k, v in headers.items()}
    signed = ";".join(sorted(headers))
    canonical_headers = "".join(k + ":" + headers[k] + "\n" for k in sorted(headers))
    canonical = method + "\n" + path + "\n\n" + canonical_headers + "\n" + signed + "\n" + digest
    scope = date + "/" + region + "/s3/aws4_request"
    string_to_sign = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
    def mac(key, message):
        return hmac.new(key, message.encode(), hashlib.sha256).digest()
    key = mac(("AWS4" + secret).encode(), date)
    for component in (region, "s3", "aws4_request"):
        key = mac(key, component)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = "AWS4-HMAC-SHA256 Credential=" + access + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + signature
    return headers


class R2:
    def __init__(self, account, bucket, access, secret, transport=request_bytes):
        if not re.fullmatch(r"[a-f0-9]{32}", account) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket):
            raise RelayError("invalid-config")
        if not access or not secret or any(ch.isspace() for ch in access + secret):
            raise RelayError("invalid-config")
        self.host = account + ".r2.cloudflarestorage.com"
        self.path = "/" + bucket + "/v1/latest.json"
        self.access, self.secret, self.transport = access, secret, transport

    @classmethod
    def from_env(cls):
        return cls(*(os.environ.get(name, "") for name in (
            "R2_ACCOUNT_ID", "R2_BUCKET", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY")))

    def request(self, method, payload=b"", extra=None):
        headers = signing_headers(method, self.host, self.path, payload,
                                  self.access, self.secret, datetime.now(UTC), extra)
        request = Request("https://" + self.host + self.path,
                          data=payload if method == "PUT" else None,
                          headers=headers, method=method)
        return self.transport(request)

    def get(self):
        return self.request("GET", extra={"cache-control": "no-cache"})

    def put(self, raw, etag):
        snapshot = load(raw)
        validate(snapshot, (self.access, self.secret))
        if snapshot["mode"] != "live":
            raise RelayError("invalid-snapshot")
        condition = {"if-match": etag} if etag is not None else {"if-none-match": "*"}
        status, _, _ = self.request("PUT", raw, {
            "content-type": "application/json; charset=utf-8",
            "cache-control": CACHE_CONTROL, **condition,
        })
        if status in (409, 412):
            raise RelayError("conflict")
        if status != 200:
            raise RelayError("storage")


def seed(delivery, path, receipt_path, allow_empty=False, r2=None, transport=request_bytes):
    if delivery == "r2":
        status, headers, raw = (r2 or R2.from_env()).get()
    elif delivery == "pages":
        status, headers, raw = transport(Request(PAGES_URL, headers={"Accept": "application/json", "Cache-Control": "no-cache"}))
    else:
        raise RelayError("invalid-config")
    etag = None
    if status == 404 and allow_empty:
        snapshot = blank("live")
    elif status == 200:
        snapshot = load(raw)
        if snapshot["mode"] != "live":
            if not (allow_empty and snapshot["mode"] == "unconfigured" and all(f["data"] is None for f in snapshot["feeds"].values())):
                raise RelayError("baseline-unavailable")
            snapshot = blank("live")
        if delivery == "r2":
            etag = headers.get("etag")
            if not isinstance(etag, str) or not re.fullmatch(r'"[a-fA-F0-9]{32}(?:-\d+)?"', etag):
                raise RelayError("baseline-unavailable")
    else:
        raise RelayError("baseline-unavailable")
    atomic_write(path, dumps(snapshot))
    atomic_write(receipt_path, json.dumps({"delivery": delivery, "etag": etag,
                                        "baselineSha256": hashlib.sha256(dumps(snapshot).encode()).hexdigest()}))


def publish_r2(path, baseline, receipt_path, r2=None):
    raw = Path(path).read_bytes()
    new = load(raw)
    old_raw = Path(baseline).read_bytes()
    old = load(old_raw)
    receipt = json.loads(Path(receipt_path).read_text())
    if set(receipt) != {"delivery", "etag", "baselineSha256"} or receipt["delivery"] != "r2":
        raise RelayError("invalid-config")
    if receipt["baselineSha256"] != hashlib.sha256(old_raw).hexdigest():
        raise RelayError("conflict")
    etag = receipt["etag"]
    if etag is not None and (not isinstance(etag, str) or not re.fullmatch(r'"[a-fA-F0-9]{32}(?:-\d+)?"', etag)):
        raise RelayError("invalid-config")
    if old["generatedAt"] and (not new["generatedAt"] or parse_stamp(new["generatedAt"]) < parse_stamp(old["generatedAt"])):
        raise RelayError("conflict")
    for name, before in old["feeds"].items():
        after = new["feeds"][name]
        if before["lastSuccessAt"]:
            if not after["lastSuccessAt"] or parse_stamp(after["lastSuccessAt"]) < parse_stamp(before["lastSuccessAt"]):
                raise RelayError("conflict")
            if after["lastSuccessAt"] == before["lastSuccessAt"] and after["data"] != before["data"]:
                raise RelayError("conflict")
    (r2 or R2.from_env()).put(raw, etag)


def main(argv=None):
    parser = argparse.ArgumentParser(description="승인 후 배포용 저장소 입출력")
    parser.add_argument("operation", choices=("seed", "publish"))
    parser.add_argument("--delivery", choices=("r2", "pages"), required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.environ.get("RELAY_PUBLICATION_APPROVED") != "true":
            raise RelayError("invalid-config")
        if args.operation == "seed":
            seed(args.delivery, args.previous, args.receipt,
                 os.environ.get("ALLOW_EMPTY_BASELINE") == "true")
        elif args.delivery == "r2" and args.snapshot:
            publish_r2(args.snapshot, args.previous, args.receipt)
        else:
            raise RelayError("invalid-config")
        print("storage: " + args.operation + " complete")
        return 0
    except RelayError as exc:
        print("storage: " + exc.code)
    except OSError:
        print("storage: io")
    except Exception:
        print("storage: unexpected")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
