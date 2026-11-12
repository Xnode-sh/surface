# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""Read installed APKs and extract their declared attack surface."""

import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import axml

ANDROID_NS = "http://schemas.android.com/apk/res/android"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.QUERY_ALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.POST_NOTIFICATIONS",
}


@dataclass
class Component:
    kind: str
    name: str
    exported: bool | None
    permission: str | None
    deep_links: list = field(default_factory=list)


@dataclass
class AppSurface:
    package: str
    label: str | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    debuggable: bool = False
    allow_backup: bool = False
    permissions: list = field(default_factory=list)
    components: list = field(default_factory=list)
    apk_path: str | None = None
    error: str | None = None


def _bool(value, default=False):
    if value is None:
        return default
    return str(value).lower() == "true"


def _android_attr(node, *names):
    for n in names:
        if n in node.attrs:
            return node.attrs[n]
    return None


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _deep_links(intent_filter):
    links = []
    for data in intent_filter.find_all("data"):
        scheme = _android_attr(data, "scheme") or ""
        host = _android_attr(data, "host") or ""
        path = _android_attr(data, "path") or _android_attr(data, "pathPrefix") or ""
        if scheme:
            links.append(f"{scheme}://{host}{path}".rstrip(":"))
    return links


def _components(app_node):
    found = []
    for tag in COMPONENT_TAGS:
        for node in app_node.find_all(tag):
            name = _android_attr(node, "name") or "?"
            exported_raw = _android_attr(node, "exported")
            exported = None if exported_raw is None else _bool(exported_raw)
            permission = _android_attr(node, "permission")
            links = []
            for f in node.find_all("intent-filter"):
                links.extend(_deep_links(f))
            found.append(Component(tag, name, exported, permission, links))
    return found


def parse_manifest(data, package_hint=None):
    root = axml.parse(data)
    app = root.find("application")
    surface = AppSurface(package=root.attrs.get("package") or package_hint or "?")

    sdk = root.find("uses-sdk")
    if sdk is not None:
        surface.min_sdk = _int_or_none(_android_attr(sdk, "minSdkVersion"))
        surface.target_sdk = _int_or_none(_android_attr(sdk, "targetSdkVersion"))

    surface.permissions = [
        _android_attr(p, "name") for p in root.find_all("uses-permission") if _android_attr(p, "name")
    ]

    if app is not None:
        surface.label = _android_attr(app, "label")
        surface.debuggable = _bool(_android_attr(app, "debuggable"))
        surface.allow_backup = _bool(_android_attr(app, "allowBackup"))
        surface.components = _components(app)
    return surface


def apk_paths(package):
    try:
        out = subprocess.run(["pm", "path", package], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.split("package:", 1)[1].strip() for line in out.stdout.splitlines() if line.startswith("package:")]


def installed_packages():
    try:
        out = subprocess.run(["pm", "list", "packages"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return sorted(line.split(":", 1)[1].strip() for line in out.stdout.splitlines() if line.startswith("package:"))


def read_manifest(apk):
    with zipfile.ZipFile(apk) as z:
        return z.read("AndroidManifest.xml")


def inspect(package):
    paths = apk_paths(package)
    if not paths:
        return AppSurface(package=package, error="apk not found")
    surface = AppSurface(package=package, apk_path=paths[0])
    try:
        surface = parse_manifest(read_manifest(paths[0]), package)
        surface.apk_path = paths[0]
    except Exception as exc:  # noqa: BLE001 - report parse problems per app
        surface.error = f"{type(exc).__name__}: {exc}"
    return surface
