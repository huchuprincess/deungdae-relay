"""Copy the audited allowlist into a new folder, with no Git metadata."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_candidate import check, manifest


def export(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    if output.is_relative_to(root) or root.is_relative_to(output) or output.exists():
        raise ValueError("invalid-output")
    if not check(root)["ok"]:
        raise ValueError("audit-failed")
    output.mkdir(parents=True)
    for name in manifest(root):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((root / name).read_bytes())
        path.chmod(0o644)
    if not check(output)["ok"]:
        raise ValueError("export-audit-failed")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        export(args.root, args.output)
        print("export: complete, no git metadata")
        return 0
    except Exception:
        print("export: failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
