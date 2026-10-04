"""Audit only this independent candidate; findings never echo matching content."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from relay.model import load
from relay.safety import sensitive_findings

PUBLIC_REMOTE = "https://github.com/huchuprincess/deungdae-relay"
PINNED_ACTIONS = {
    "actions/upload-pages-artifact": "fc324d3547104276b827a68afc52ff2a11cc49c9",
    "actions/deploy-pages": "368f82528645a54fb793d4d04e342629a3f51346",
}


def manifest(root):
    names = (root / "PUBLIC_FILES.txt").read_text().splitlines()
    if not names or len(names) != len(set(names)):
        raise ValueError("manifest")
    for name in names:
        p = Path(name)
        if p.is_absolute() or ".." in p.parts or name != p.as_posix() or name.startswith(".git/"):
            raise ValueError("manifest")
    return sorted(names)


def scan_text(text, forbidden=()):
    result = sensitive_findings(text)
    if any(needle and needle.casefold() in text.casefold() for needle in forbidden):
        result.append("forbidden-content")
    # Look for long token-like values outside reviewed SHA pins and hashes.
    public_links = [m.span() for m in re.finditer(r"https://(?:www\.data\.go\.kr|www\.kogl\.or\.kr|docs\.github\.com|developers\.cloudflare\.com|github\.com)/[A-Za-z0-9_./#-]+", text)]
    for match in re.finditer(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{48,256}(?![A-Za-z0-9])", text):
        value = match.group()
        if re.search(r"(?:def|class)\s+$", text[max(0, match.start()-12):match.start()]):
            continue
        if any(start <= match.start() and match.end() <= end for start, end in public_links):
            continue
        if not re.fullmatch(r"[a-f0-9]{64}", value) and len(set(value)) > 20:
            result.append("token-like-value")
            break
    return sorted(set(result))


def git(root, args, binary=False):
    # Do not invoke credential helpers, hooks, external diffs, or global config.
    import os
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=True)
    return result.stdout if binary else result.stdout.decode("utf-8")


def history(root, forbidden):
    findings, counts = [], {"present": False, "objects": 0, "commits": 0}
    metadata = root / ".git"
    if not metadata.exists():
        return findings, counts
    counts["present"] = True
    if metadata.is_symlink() or not metadata.is_dir():
        return [{"file": "git-metadata", "check": "external-history"}], counts
    if (metadata / "objects/info/alternates").exists() or (metadata / "commondir").exists() or (metadata / "shallow").exists():
        return [{"file": "git-metadata", "check": "incomplete-or-shared-history"}], counts
    if any(p.is_symlink() for p in metadata.rglob("*")):
        return [{"file": "git-metadata", "check": "symlink"}], counts
    for p in (metadata / "hooks").glob("*"):
        if not p.name.endswith(".sample"):
            findings.append({"file": "git-hooks", "check": "unexpected-hook"})
    config = git(root, ["config", "--no-includes", "--local", "--list"])
    allowed_keys = {"core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
                    "init.defaultbranch", "remote.origin.url", "remote.origin.fetch", "branch.main.remote",
                    "branch.main.merge", "user.name", "user.email", "core.hookspath"}
    for line in config.splitlines():
        key, _, value = line.partition("=")
        if key not in allowed_keys or (key == "remote.origin.url" and value not in (PUBLIC_REMOTE, PUBLIC_REMOTE + ".git")):
            findings.append({"file": "git-config", "check": "unexpected-config"})
        if key == "core.hookspath" and value != "/dev/null":
            findings.append({"file": "git-config", "check": "unexpected-hook"})
        if key == "user.email" and not value.endswith("@users.noreply.github.com"):
            findings.append({"file": "git-config", "check": "author-privacy"})
        if key != "user.email":
            findings.extend({"file": "git-config", "check": f} for f in scan_text(line, forbidden))
    objects = git(root, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)"])
    for line in objects.splitlines():
        oid, kind, size = line.split()
        counts["objects"] += 1
        label = "git-" + kind + ":" + oid[:12]
        if int(size) > 4 * 1024 * 1024:
            findings.append({"file": label, "check": "oversized-object"})
            continue
        if kind == "tree":
            for entry in git(root, ["ls-tree", "-z", oid], binary=True).split(b"\0"):
                if not entry:
                    continue
                metadata_part, name = entry.split(b"\t", 1)
                if metadata_part.split()[0] not in (b"100644", b"040000"):
                    findings.append({"file": label, "check": "executable-link-or-submodule"})
                findings.extend({"file": label, "check": f} for f in scan_text(name.decode("utf-8", errors="replace"), forbidden))
            continue
        raw = git(root, ["cat-file", kind, oid], binary=True)
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            findings.append({"file": label, "check": "binary-object"})
            continue
        if kind in ("commit", "tag"):
            counts["commits"] += int(kind == "commit")
            safe_lines = []
            for header in text.splitlines():
                if header.startswith(("author ", "committer ", "tagger ")):
                    identity = re.fullmatch(r"(?:author|committer|tagger) ([A-Za-z0-9_-]+(?:\[bot\])?) <([^<>]+@users\.noreply\.github\.com|noreply@github\.com)> \d+ [+-]\d{4}", header)
                    if identity and identity.group(2).endswith("@github.com") and identity.group(1) != "GitHub":
                        identity = None
                    if not identity:
                        findings.append({"file": label, "check": "author-privacy"})
                    if any(needle and needle.casefold() in header.casefold() for needle in forbidden):
                        findings.append({"file": label, "check": "forbidden-content"})
                else:
                    safe_lines.append(header)
            text = "\n".join(safe_lines)
        findings.extend({"file": label, "check": f} for f in scan_text(text, forbidden))
    for p in (metadata / "logs").rglob("*"):
        if p.is_file():
            text = p.read_text()
            text = re.sub(r" <(?:[^<>]+@users\.noreply\.github\.com|noreply@github\.com)>", " <public-noreply>", text)
            findings.extend({"file": "git-reflog", "check": f} for f in scan_text(text, forbidden))
    return findings, counts


def check(root, forbidden=()):
    root = Path(root).resolve()
    findings, files = [], []
    names = manifest(root)
    actual = []
    for p in root.rglob("*"):
        name = p.relative_to(root).as_posix()
        if name == ".git" or name.startswith(".git/"):
            continue
        if p.is_symlink():
            findings.append({"file": name if name in names else "unlisted-file", "check": "symlink"})
        elif p.is_file():
            actual.append(name)
    if set(actual) != set(names):
        findings.append({"file": "manifest", "check": "unlisted-or-missing-files"})
    for name in names:
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        mode = path.stat().st_mode
        if mode & (0o111 | stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH):
            findings.append({"file": name, "check": "unsafe-file-permission"})
        raw = path.read_bytes()
        files.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            findings.append({"file": name, "check": "binary-file"})
            continue
        findings.extend({"file": name, "check": f} for f in scan_text(text, forbidden))
        if name.startswith("public/") and name.endswith(".json"):
            try:
                snapshot = load(raw)
                expected = "example" if "/examples/" in name else "unconfigured"
                if snapshot["mode"] != expected:
                    findings.append({"file": name, "check": "live-data-in-candidate"})
            except Exception:
                findings.append({"file": name, "check": "invalid-public-json"})
        if name.startswith("fixtures/") and name.endswith(".json"):
            try:
                if json.loads(text).get("synthetic") is not True:
                    findings.append({"file": name, "check": "unmarked-fixture"})
            except ValueError:
                findings.append({"file": name, "check": "invalid-fixture"})
        if name.startswith(".github/workflows/"):
            if name.endswith("/pages.yml") and ("false && github.ref" not in text or "if: ${{ false }}" not in text):
                findings.append({"file": name, "check": "pages-dependency-lock-missing"})
            if any(term in text for term in ("pull_request_target:", "workflow_run:", "write-all", "contents: write", "set -x")):
                findings.append({"file": name, "check": "unsafe-workflow"})
            for action, pin in re.findall(r"uses:\s*([\w/-]+)@([^\s#]+)", text):
                if PINNED_ACTIONS.get(action) != pin:
                    findings.append({"file": name, "check": "unreviewed-action"})
    git_findings, counts = history(root, forbidden)
    findings.extend(git_findings)
    blockers = ["pages-dependency-review"] if ".github/workflows/pages.yml" in names else []
    return {"ok": not findings, "fileCount": len(files), "files": files,
            "history": counts, "findings": findings, "deploymentBlockers": blockers}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path)
    parser.add_argument("--forbid-text", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        report = check(args.root, args.forbid_text)
        if args.report:
            target = args.report.resolve()
            if target.is_relative_to(args.root.resolve()):
                raise ValueError("report-inside-candidate")
            target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print("candidate: " + ("pass" if report["ok"] else "fail") + ", files=" + str(report["fileCount"]) + ", git objects=" + str(report["history"]["objects"]))
        for finding in report["findings"]:
            print(finding["file"] + ": " + finding["check"])
        return 0 if report["ok"] else 2
    except Exception:
        print("candidate: audit-incomplete")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
