"""Build a Pages artifact from a strict static allowlist and a validated snapshot."""

import argparse
from pathlib import Path

from .model import dumps, load
from .run import atomic_write
from .safety import RelayError

STATIC = ("index.html", ".nojekyll", "examples/v1/latest.json")


def build(source, snapshot, output, allow_live=False):
    source, output = Path(source), Path(output)
    if output.exists() and any(output.iterdir()):
        raise RelayError("invalid-config")
    result = load(Path(snapshot).read_bytes())
    if result["mode"] == "live" and not allow_live:
        raise RelayError("invalid-config")
    for name in STATIC:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise RelayError("io")
        raw = path.read_text(encoding="utf-8")
        if name.endswith(".json"):
            example = load(raw.encode())
            if example["mode"] != "example":
                raise RelayError("invalid-snapshot")
        atomic_write(output / name, raw)
    atomic_write(output / "v1/latest.json", dumps(result))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path("public"))
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-live", action="store_true")
    args = parser.parse_args(argv)
    try:
        build(args.source, args.snapshot, args.output, args.allow_live)
        print("site: build complete")
        return 0
    except RelayError as exc:
        print("site: " + exc.code)
    except Exception:
        print("site: io")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
