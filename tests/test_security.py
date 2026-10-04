from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from relay.safety import RelayError, require_public, sensitive_findings
from scripts.check_candidate import PUBLIC_REMOTE, check, history, scan_text
from scripts.export_candidate import export


class SecurityTests(unittest.TestCase):
    def candidate(self, directory):
        root = Path(directory) / "candidate"; root.mkdir()
        (root / "PUBLIC_FILES.txt").write_text("PUBLIC_FILES.txt\nREADME.md\n")
        (root / "README.md").write_text("Synthetic candidate for a local test.\n")
        return root

    def init_git(self, root):
        import os
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                   GIT_AUTHOR_NAME="RelayReview", GIT_COMMITTER_NAME="RelayReview",
                   GIT_AUTHOR_EMAIL="noreply" + "@" + "users.noreply.github.com",
                   GIT_COMMITTER_EMAIL="noreply" + "@" + "users.noreply.github.com")
        template = root.parent / "empty-template"; template.mkdir()
        subprocess.run(["git", "init", "--template=" + str(template), "--initial-branch=main", str(root)], env=env,
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Keep synthetic fixtures minimal on macOS too; retain the audit allowlist.
        for key in ("core.ignorecase", "core.precomposeunicode"):
            result = subprocess.run(["git", "-C", str(root), "config", "--local", "--unset-all", key],
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode not in (0, 5):
                result.check_returncode()
        return env

    def command(self, root, env, *args):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args], env=env,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def test_key_encodings_are_rejected_rather_than_masked(self):
        secret = "synthetic+value/" + "="
        for text in (secret, "synthetic%2Bvalue%2F%3D", "c3ludGhldGljK3ZhbHVlLz0="):
            with self.assertRaises(RelayError):
                require_public(text, (secret,))

    def test_credentials_and_personal_information_patterns(self):
        texts = ["ghp_" + "Ab1" * 13,
                 "-----BEGIN " + "PRIVATE KEY-----",
                 "sample" + "@" + "example.invalid",
                 "010" + "-1234-5678", "991231" + "-1234567",
                 "https://example.invalid/?serviceKey=" + "synthetic"]
        self.assertTrue(all(sensitive_findings(text) for text in texts))

    def test_unlisted_files_logs_symlinks_and_execution_permissions_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.candidate(directory)
            self.assertTrue(check(root)["ok"])
            log = root / "unexpected.log"; log.write_text("fixture")
            self.assertFalse(check(root)["ok"]); log.unlink()
            readme = root / "README.md"; readme.chmod(0o755)
            self.assertFalse(check(root)["ok"]); readme.chmod(0o644)
            linked = root / "unexpected-link"; linked.symlink_to(readme)
            self.assertFalse(check(root)["ok"])

    def test_failures_report_rule_not_matching_secret(self):
        secret = "ghp_" + "Ab1" * 13
        with tempfile.TemporaryDirectory() as directory:
            root = self.candidate(directory); (root / "README.md").write_text(secret)
            report = check(root)
            self.assertFalse(report["ok"])
            self.assertNotIn(secret, json.dumps(report))

    def test_removed_secret_in_unreachable_git_objects_is_found(self):
        secret = "ghp_" + "Ab1" * 13
        with tempfile.TemporaryDirectory() as directory:
            root = self.candidate(directory); env = self.init_git(root)
            self.command(root, env, "add", "PUBLIC_FILES.txt", "README.md")
            self.command(root, env, "commit", "-m", "Synthetic baseline. Refs #1")
            base = self.command(root, env, "rev-parse", "HEAD").decode().strip()
            (root / "README.md").write_text(secret)
            self.command(root, env, "add", "README.md")
            self.command(root, env, "commit", "-m", "Synthetic fixture. Refs #1")
            self.command(root, env, "reset", "--hard", base)
            findings, counts = history(root, ())
            self.assertEqual(counts["commits"], 2)
            self.assertTrue(any(f["check"] == "provider-token" for f in findings))
            self.assertNotIn(secret, json.dumps(findings))

    def test_unexpected_remote_and_git_hook_are_found(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.candidate(directory); env = self.init_git(root)
            self.command(root, env, "remote", "add", "origin", "https://example.invalid/synthetic-private")
            hooks = root / ".git/hooks"; hooks.mkdir(exist_ok=True)
            (hooks / "pre-push").write_text("synthetic")
            findings, _ = history(root, ())
            rules = {f["check"] for f in findings}
            self.assertIn("unexpected-config", rules)
            self.assertIn("unexpected-hook", rules)

    def test_author_email_privacy_is_checked_in_commit_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.candidate(directory); env = self.init_git(root)
            env["GIT_AUTHOR_EMAIL"] = "synthetic" + "@" + "example.invalid"
            self.command(root, env, "add", "PUBLIC_FILES.txt", "README.md")
            self.command(root, env, "commit", "-m", "Synthetic commit. Refs #1")
            findings, _ = history(root, ())
            self.assertTrue(any(f["check"] == "author-privacy" for f in findings))

    def test_ci_checkout_has_public_reflogs_and_still_rejects_sensitive_history(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        read_step = workflow.split("      - name: Read public source with native Git\n", 1)[1]
        read_step = read_step.split("      - name:", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            source_parent = Path(directory) / "source"; source_parent.mkdir()
            source = self.candidate(source_parent); source_env = self.init_git(source)
            self.command(source, source_env, "add", "PUBLIC_FILES.txt", "README.md")
            self.command(source, source_env, "commit", "-m", "Synthetic source. Refs #1")
            sha = self.command(source, source_env, "rev-parse", "HEAD").decode().strip()
            self.command(source, source_env, "bundle", "create", str(Path(directory) / "input.bundle"), "main")

            checkout = Path(directory) / "checkout"; checkout.mkdir()
            checkout_env = self.init_git(checkout)
            checkout_env.update(GIT_COMMITTER_NAME="SyntheticRunner",
                                GIT_COMMITTER_EMAIL="synthetic-runner" + "@" + "actions.example.invalid")
            for key, value in re.findall(r"(?m)^          (GIT_COMMITTER_(?:NAME|EMAIL)):\s*(.+)$", read_step):
                checkout_env[key] = value.replace("${{ github.actor }}", "RelayReview")
            self.command(checkout, checkout_env, "remote", "add", "origin", PUBLIC_REMOTE + ".git")
            self.command(checkout, checkout_env, "fetch", "--no-tags", "../input.bundle", "main:refs/remotes/origin/main")
            self.command(checkout, checkout_env, "checkout", "--detach", sha)
            report = check(checkout)
            self.assertTrue(report["ok"], report["findings"])
            self.assertEqual(report["history"]["commits"], 1)

            private_email = "synthetic" + "@" + "example.invalid"
            private_env = dict(checkout_env, GIT_COMMITTER_EMAIL=private_email)
            self.command(checkout, private_env, "update-ref", "--create-reflog", "refs/heads/email-fixture", sha)
            findings, _ = history(checkout, ())
            self.assertTrue(any(f["check"] == "personal-email" for f in findings))
            self.assertNotIn(private_email, json.dumps(findings))

            token = "ghp_" + "Ab1" * 13
            self.command(checkout, checkout_env, "update-ref", "--create-reflog", "-m", token,
                         "refs/heads/token-fixture", sha)
            findings, _ = history(checkout, ())
            self.assertTrue(any(f["check"] == "provider-token" for f in findings))
            self.assertNotIn(token, json.dumps(findings))

    def test_export_excludes_all_git_history_and_normalizes_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.candidate(directory); env = self.init_git(root)
            self.command(root, env, "add", "PUBLIC_FILES.txt", "README.md")
            self.command(root, env, "commit", "-m", "Synthetic candidate. Refs #1")
            output = Path(directory) / "export"
            export(root, output)
            self.assertFalse((output / ".git").exists())
            self.assertEqual((output / "README.md").stat().st_mode & 0o777, 0o644)

    def test_explicit_forbidden_private_reference_is_found(self):
        text = "private-" + "repository-marker"
        self.assertIn("forbidden-content", scan_text(text, (text,)))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.relay = (root / ".github/workflows/relay.yml").read_text()
        self.ci = (root / ".github/workflows/ci.yml").read_text()
        self.pages = (root / ".github/workflows/pages.yml").read_text()

    def test_publication_requires_main_and_two_explicit_flags(self):
        for text in ("github.ref == 'refs/heads/main'", "vars.RELAY_PUBLICATION_APPROVED == 'true'", "vars.LIVE_API_VERIFIED == 'true'"):
            self.assertIn(text, self.relay)
        self.assertIn("vars.PAGES_PUBLICATION_APPROVED == 'true'", self.pages)

    def test_ci_has_no_secret_access_or_write_permission(self):
        self.assertNotIn("secrets.", self.ci)
        self.assertNotIn(": write", self.ci)
        self.assertNotIn("pull_request_target", self.ci)
        self.assertNotIn("workflow_run", self.ci)

    def test_serial_publication_and_no_credential_persistence(self):
        self.assertIn("cancel-in-progress: false", self.relay)
        self.assertIn("credential.helper=", self.relay)
        self.assertIn('test "$(git rev-parse FETCH_HEAD)" = "$RELAY_SHA"', self.relay)
        self.assertNotIn("uses:", self.relay)
        self.assertNotIn("uses:", self.ci)
        self.assertNotIn("contents: write", self.relay)
        self.assertNotIn("git push", self.relay)

    def test_pages_upload_uses_only_the_built_site(self):
        self.assertIn("path: dist", self.pages)
        self.assertIn("retention-days: 1", self.pages)
        self.assertNotIn("path: .runtime", self.pages)

    def test_dependency_blocked_pages_cannot_be_unlocked_with_variables(self):
        self.assertIn("false && github.ref", self.pages)
        self.assertIn("if: ${{ false }}", self.pages)
        self.assertNotIn("RELAY_DELIVERY == 'pages'", self.relay)


if __name__ == "__main__":
    unittest.main()
