# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
import unittest

from surface.apk import AppSurface, Component
from surface import risk


class RiskTest(unittest.TestCase):
    def test_debuggable_is_high(self):
        s = AppSurface(package="x", debuggable=True)
        findings = risk.analyze(s)
        self.assertIn("high", [f["severity"] for f in findings])

    def test_open_provider_is_high(self):
        s = AppSurface(package="x", components=[
            Component("provider", ".P", True, None, [])
        ])
        findings = risk.analyze(s)
        self.assertEqual(findings[0]["severity"], "high")

    def test_guarded_provider_is_low(self):
        s = AppSurface(package="x", components=[
            Component("provider", ".P", True, "android.permission.X", [])
        ])
        findings = risk.analyze(s)
        self.assertEqual(findings[0]["severity"], "low")

    def test_browsable_deep_link(self):
        s = AppSurface(package="x", components=[
            Component("activity", ".A", True, None, ["https://example.com"])
        ])
        findings = risk.analyze(s)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("deep link", findings[0]["title"])

    def test_exported_receiver_without_permission(self):
        s = AppSurface(package="x", components=[
            Component("receiver", ".R", True, None, [])
        ])
        findings = risk.analyze(s)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_not_exported_is_ignored(self):
        s = AppSurface(package="x", components=[
            Component("service", ".S", False, None, [])
        ])
        self.assertEqual(risk.analyze(s), [])

    def test_score_weights(self):
        s = AppSurface(package="x", debuggable=True, components=[
            Component("provider", ".P", True, None, [])
        ])
        self.assertEqual(risk.score(risk.analyze(s)), 20)


if __name__ == "__main__":
    unittest.main()
