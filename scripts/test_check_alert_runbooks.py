#!/usr/bin/env python3
"""Tests for scripts/check_alert_runbooks.py."""

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_alert_runbooks as check  # noqa: E402

SCRIPT = os.path.join(HERE, "check_alert_runbooks.py")
REPO_ROOT = os.path.dirname(HERE)


def _alert(annotations):
    return {"groups": [{"name": "test", "rules": [{"alert": "TestAlert", "annotations": annotations}]}]}


class FindBrokenRunbooksTests(unittest.TestCase):
    def test_valid_runbook_and_description_pass(self):
        doc = _alert(
            {
                "runbook": "docs/runbook-alerts.md#ethoscanaryrollback",
                "runbook_url": "docs/canary-deployments.md",
                "description": "See docs/canary-deployments.md and docs/runbook-alerts.md#ethoscanaryrollback",
            }
        )
        self.assertEqual(check.find_broken_runbooks(doc, REPO_ROOT), [])

    def test_missing_runbook_file_is_rejected(self):
        doc = _alert({"runbook": "docs/does-not-exist.md#section"})
        found = check.find_broken_runbooks(doc, REPO_ROOT)
        self.assertEqual(len(found), 1)
        self.assertIn("docs/does-not-exist.md", found[0])

    def test_missing_runbook_url_file_is_rejected(self):
        doc = _alert({"runbook_url": "docs/runary-deployments.md"})
        found = check.find_broken_runbooks(doc, REPO_ROOT)
        self.assertEqual(len(found), 1)
        self.assertIn("docs/runary-deployments.md", found[0])

    def test_missing_doc_in_description_is_rejected(self):
        doc = _alert(
            {
                "runbook": "docs/runbook-alerts.md#ethoscanaryrollback",
                "description": "See docs/runary-deployments.md for details",
            }
        )
        found = check.find_broken_runbooks(doc, REPO_ROOT)
        self.assertEqual(len(found), 1)
        self.assertIn("docs/runary-deployments.md", found[0])

    def test_empty_runbook_url_is_rejected(self):
        doc = _alert({"runbook_url": "   "})
        found = check.find_broken_runbooks(doc, REPO_ROOT)
        self.assertEqual(len(found), 1)

    def test_external_http_runbook_url_is_allowed(self):
        doc = _alert({"runbook_url": "https://example.com/runbook"})
        self.assertEqual(check.find_broken_runbooks(doc, REPO_ROOT), [])


class RepositoryAlertRulesTests(unittest.TestCase):
    def test_repository_alert_rules_have_valid_runbooks(self):
        status = subprocess.run(
            [sys.executable, SCRIPT, os.path.join(REPO_ROOT, "monitoring", "alert_rules.yml")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)

    def test_script_fails_on_broken_runbook_link(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(
                "groups:\n"
                "  - name: g\n"
                "    rules:\n"
                "      - alert: BrokenAlert\n"
                "        annotations:\n"
                "          runbook_url: docs/runary-deployments.md\n"
            )
            path = fh.name
        try:
            status = subprocess.run(
                [sys.executable, SCRIPT, path], capture_output=True, text=True
            )
            self.assertEqual(status.returncode, 1)
            self.assertIn("docs/runary-deployments.md", status.stdout)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
