#!/usr/bin/env python3
"""CI guard: verify every runbook link in Prometheus alert rules exists.

Checks `annotations.runbook`, `annotations.runbook_url`, and any `docs/*.md`
links embedded in `annotations.description` across Prometheus alert rule files
so on-call engineers are never paged with a dead runbook link.

Usage:
    scripts/check_alert_runbooks.py [alert-rules-file ...]

With no arguments, checks `monitoring/alert_rules.yml`.
Exits 1 when any referenced local runbook file does not exist or when a
`runbook` / `runbook_url` annotation is empty.
"""

from __future__ import annotations

import os
import re
import sys

import yaml

DEFAULT_FILES = ("monitoring/alert_rules.yml",)
DOC_REF_RE = re.compile(r"\bdocs/[A-Za-z0-9_./-]+\.md(?:#[A-Za-z0-9_.-]+)?")


def _strip_fragment(ref: str) -> str:
    return ref.split("#", 1)[0].strip()


def _is_external_url(ref: str) -> bool:
    return ref.startswith(("http://", "https://"))


def find_broken_runbooks(rules_doc: dict, repo_root: str) -> list[str]:
    """Return a description of every broken runbook reference in a parsed rules file."""
    violations: list[str] = []
    groups = rules_doc.get("groups") or []
    for group in groups:
        for rule in (group or {}).get("rules") or []:
            alert = (rule or {}).get("alert", "<unnamed>")
            annotations = (rule or {}).get("annotations") or {}

            for key in ("runbook", "runbook_url"):
                if key not in annotations:
                    continue
                raw = annotations[key]
                if not isinstance(raw, str) or not raw.strip():
                    violations.append(f"alert '{alert}': empty annotations.{key}")
                    continue
                ref = raw.strip()
                if _is_external_url(ref):
                    continue
                rel_path = _strip_fragment(ref)
                full_path = os.path.join(repo_root, rel_path)
                if not os.path.isfile(full_path):
                    violations.append(
                        f"alert '{alert}': annotations.{key} points to missing file '{rel_path}'"
                    )

            description = annotations.get("description")
            if isinstance(description, str):
                for match in DOC_REF_RE.findall(description):
                    rel_path = _strip_fragment(match)
                    full_path = os.path.join(repo_root, rel_path)
                    if not os.path.isfile(full_path):
                        violations.append(
                            f"alert '{alert}': annotations.description references missing file '{rel_path}'"
                        )

    return violations


def check_files(paths: list[str], repo_root: str | None = None) -> int:
    root = repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    failures = 0
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            rules_doc = yaml.safe_load(fh) or {}
        for violation in find_broken_runbooks(rules_doc, root):
            print(f"FAIL: {path}: {violation}")
            failures += 1
    if failures:
        print(
            "\nEvery alert runbook link must point to an existing file in the repository.",
            file=sys.stderr,
        )
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    paths = argv if argv else list(DEFAULT_FILES)
    return check_files(paths)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
