"""Reject sensitive output; never redact it into an apparently safe artifact."""

import base64
import re
from urllib.parse import quote, quote_plus, unquote


class RelayError(Exception):
    """Only a fixed error code may leave the process."""

    CODES = frozenset({
        "missing-key", "not-verified", "transport", "upstream-error",
        "invalid-response", "stale-upstream", "future-time", "pagination",
        "invalid-snapshot", "sensitive-output", "invalid-config", "storage",
        "baseline-unavailable", "conflict", "io", "unexpected",
    })

    def __init__(self, code):
        self.code = code if code in self.CODES else "unexpected"
        super().__init__(self.code)


# Pattern checks supplement exact secret checks and manual review.
# They are deliberately not described as a proof that a file is safe.
PATTERNS = {
    "private-key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "provider-token": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16})\b",
    "credential-url": r"https?://[^\s/]+:[^\s/]+@",
    "credential-query": r"(?i)[?&](?:servicekey|authkey|api[_-]?key|access_token|token)=[^\s&#\"']+",
    "personal-email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "resident-id": r"\b\d{6}-[1-8]\d{6}\b",
    "personal-phone": r"\b01[016789][ -]?\d{3,4}[ -]?\d{4}\b",
    "machine-path": r"/(?:Users|home)/[^\s/]+/",
}


def secret_variants(values):
    variants = set()
    for value in values:
        if not value:
            continue
        for v in (value, unquote(value)):
            variants.update((v, quote(v, safe=""), quote_plus(v),
                             base64.b64encode(v.encode()).decode()))
    return variants


def sensitive_findings(text, secrets=()):
    findings = {name for name, pattern in PATTERNS.items() if re.search(pattern, text)}
    if any(v in text for v in secret_variants(secrets)):
        findings.add("configured-secret")
    return sorted(findings)


def require_public(text, secrets=()):
    if sensitive_findings(text, secrets):
        raise RelayError("sensitive-output")
