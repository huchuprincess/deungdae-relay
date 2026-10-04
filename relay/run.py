"""python3 -m relay.run. No credentials are read in default/example modes."""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import tempfile

from .model import UTC, blank, dumps, load, parse_stamp, update, validate
from .provider import PublicAPI, normalize
from .safety import RelayError


def atomic_write(path, content):
    """Replace a file atomically within a trusted output directory.

    The final file's symlink is rejected. Parent symlinks and concurrent path
    changes are not prevented; the caller must control the entire output path.
    """
    path = Path(path)
    if path.is_symlink():
        raise RelayError("io")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def fixture_fetch(directory):
    directory = Path(directory)
    def fetch(name):
        document = json.loads((directory / (name + ".json")).read_text())
        if document.get("synthetic") is not True:
            raise RelayError("invalid-response")
        return {
            "sourceResponseAt": document["sourceResponseAt"],
            "queryFrom": document["queryFrom"], "queryTo": document["queryTo"],
            "coverage": "bulletin-history" if name == "weather" else "event-history",
            "regionStateVerified": False,
            "records": [normalize(name, row) for row in document["records"]],
        }
    return fetch


def main(argv=None):
    parser = argparse.ArgumentParser(description="조회용 공개 데이터 중계, 기본은 실제 조회 전 상태")
    parser.add_argument("--mode", choices=("unconfigured", "example", "live"), default="unconfigured")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures"))
    parser.add_argument("--now", help="예제 재현용 UTC 시각, live 모드에서는 사용 불가")
    args = parser.parse_args(argv)
    try:
        if args.mode == "live" and args.now:
            raise RelayError("invalid-config")
        now = parse_stamp(args.now) if args.now else datetime.now(UTC)
        previous = None
        if args.previous:
            # A missing or damaged explicitly requested baseline stops the run.
            # It must never be silently replaced by an empty success.
            previous = load(args.previous.read_bytes())
        if args.mode == "unconfigured":
            if previous is not None:
                raise RelayError("invalid-config")
            result = validate(blank())
        elif args.mode == "example":
            if not args.now:
                now = parse_stamp("2000-01-02T03:10:00Z")
            result = update(previous, "example", now, fixture_fetch(args.fixtures))
        else:
            # Only explicit, approved live execution reads these named variables.
            key = os.environ.get("DATA_GO_KR_SERVICE_KEY", "")
            provider = PublicAPI(key, now, os.environ.get("LIVE_API_VERIFIED") == "true")
            result = update(previous, "live", now, provider.fetch, (key,), clock=lambda: datetime.now(UTC))
            if not key and all(f["data"] is None for f in result["feeds"].values()):
                result["mode"] = "unconfigured"
                from .model import NOTICES
                result["notice"] = NOTICES["unconfigured"]
                validate(result)
        atomic_write(args.output, dumps(result))
        for name, feed in result["feeds"].items():
            print(name + ": " + feed["lastAttemptStatus"])
        return 0
    except RelayError as exc:
        print("relay: " + exc.code)
    except OSError:
        print("relay: io")
    except Exception:
        print("relay: unexpected")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
