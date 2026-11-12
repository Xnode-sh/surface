# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""Risk rules: turn a declared surface into ranked findings."""

from .apk import DANGEROUS_PERMISSIONS

SEVERITY_WEIGHT = {"high": 10, "medium": 4, "low": 1, "info": 0}


def _finding(severity, kind, title, detail, component=None):
    return {
        "severity": severity,
        "kind": kind,
        "title": title,
        "detail": detail,
        "component": component,
    }


def _is_browsable(component):
    return bool(component.deep_links)


def analyze(surface):
    findings = []

    if surface.debuggable:
        findings.append(_finding("high", "app", "debuggable=true",
                                 "Приложение отлаживаемое: к процессу можно подключить отладчик."))
    if surface.allow_backup:
        findings.append(_finding("medium", "app", "allowBackup=true",
                                 "Данные приложения попадают в резервные копии (adb backup/облако)."))
    if surface.target_sdk and surface.target_sdk < 30:
        findings.append(_finding("low", "app", "old targetSdk",
                                 f"targetSdk {surface.target_sdk} < 30: меньше современных ограничений платформы."))

    for perm in surface.permissions:
        if perm in DANGEROUS_PERMISSIONS:
            findings.append(_finding("info", "permission", "dangerous permission", perm))

    for c in surface.components:
        exported = c.exported
        if exported is None:
            exported = c.kind == "provider" and (surface.target_sdk or 0) < 17
        if not exported:
            continue

        if c.kind == "provider":
            if not c.permission:
                findings.append(_finding(
                    "high", "component",
                    "exported provider without permission",
                    f"{c.name}: content provider доступен другим приложениям без permission.",
                    c.name))
            else:
                findings.append(_finding(
                    "low", "component",
                    "exported provider (guarded)",
                    f"{c.name}: доступ ограничен permission {c.permission}.", c.name))
        elif c.kind in ("activity", "activity-alias"):
            if _is_browsable(c):
                findings.append(_finding(
                    "medium", "component",
                    "browsable deep link",
                    f"{c.name}: {', '.join(c.deep_links)}", c.name))
            elif not c.permission:
                findings.append(_finding(
                    "low", "component",
                    "exported activity without permission",
                    f"{c.name}: может быть запущена извне.", c.name))
        else:  # service / receiver
            if not c.permission:
                findings.append(_finding(
                    "medium", "component",
                    f"exported {c.kind} without permission",
                    f"{c.name}: доступен другим приложениям без permission.", c.name))

    return findings


def score(findings):
    return sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
