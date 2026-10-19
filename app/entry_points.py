"""Entry points that are exported *by design*, and deep links that are not verified.

Every app has an exported launcher activity, and car apps must export a `CarAppService` or a
`MediaBrowserService` so the host can bind to them. Reporting those as "exported without permission" is noise
that makes teams switch a scanner off. Instead they are recognized by role: the launcher is simply an entry
point, and the car and media services get a precise review point (validate who is calling).

Shared by the source and APK manifest inspectors, which parse XML differently, through `FilterInfo`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LAUNCHER_CATEGORIES = {
    "android.intent.category.LAUNCHER",
    "android.intent.category.LEANBACK_LAUNCHER",
    "android.intent.category.CAR_LAUNCHER",
}
CAR_APP_ACTIONS = {"androidx.car.app.CarAppService"}
MEDIA_ACTIONS = {
    "android.media.browse.MediaBrowserService",
    "android.service.media.MediaBrowserService",
    "androidx.media3.session.MediaLibraryService",
    "androidx.media3.session.MediaSessionService",
}
WEB_SCHEMES = {"http", "https"}


@dataclass
class FilterInfo:
    """What the checks need to know about one <intent-filter>."""

    actions: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    schemes: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    auto_verify: bool = False


def component_role(filters: list[FilterInfo]) -> str | None:
    """Return "launcher", "car-app-service", "media-browser", or None for an ordinary component."""
    for info in filters:
        if "android.intent.action.MAIN" in info.actions and info.categories & LAUNCHER_CATEGORIES:
            return "launcher"
    for info in filters:
        if info.actions & CAR_APP_ACTIONS:
            return "car-app-service"
        if info.actions & MEDIA_ACTIONS:
            return "media-browser"
    return None


def role_finding(role: str, component_type: str, component_name: str) -> dict[str, str] | None:
    """A review point for roles that are exported on purpose but must still authenticate their caller."""
    if role == "car-app-service":
        return {
            "rule_id": "AAOS-CAR-APP-HOST-VALIDATION",
            "title": "Car App service exported: validate the host",
            "severity": "info",
            "summary": (
                f"{component_type} {component_name} is a CarAppService. It must be exported so the host can bind to it, "
                "which also means any app can try to bind. Access control is the HostValidator, not the manifest."
            ),
            "recommendation": "Return a HostValidator with an allow-list of trusted host signatures from createHostValidator; never ship ALLOW_ALL_HOSTS_VALIDATOR.",
        }
    if role == "media-browser":
        return {
            "rule_id": "AAOS-MEDIA-BROWSER-CALLER-VALIDATION",
            "title": "Media browser service exported: validate the caller",
            "severity": "info",
            "summary": (
                f"{component_type} {component_name} is a media browser/session service. It is exported by design so the car "
                "UI and assistants can connect, so the manifest cannot restrict callers."
            ),
            "recommendation": "In onGetRoot (or the session's connect callback) check the calling package and signature against an allow-list, and return limited content to unknown callers.",
        }
    return None


def unverified_web_link_hosts(filters: list[FilterInfo]) -> list[str]:
    """Hosts of browsable http(s) links declared without android:autoVerify="true"."""
    hosts: set[str] = set()
    for info in filters:
        browsable = "android.intent.action.VIEW" in info.actions and "android.intent.category.BROWSABLE" in info.categories
        if browsable and info.schemes & WEB_SCHEMES and not info.auto_verify:
            hosts.update(info.hosts or {"(any host)"})
    return sorted(hosts)


def unverified_link_finding(component_type: str, component_name: str, hosts: list[str]) -> dict[str, Any]:
    listed = ", ".join(hosts[:4]) + (f" (+{len(hosts) - 4})" if len(hosts) > 4 else "")
    return {
        "rule_id": "ANDROID-DEEPLINK-UNVERIFIED",
        "title": "Web deep link without App Links verification",
        "severity": "low",
        "summary": (
            f"{component_type} {component_name} handles browsable http(s) links for {listed} without android:autoVerify. "
            "Without a verified Digital Asset Link, another app can also claim these links and receive their data."
        ),
        "recommendation": "Set android:autoVerify=\"true\", publish /.well-known/assetlinks.json on every host, and keep tokens and sensitive data out of link parameters.",
    }
