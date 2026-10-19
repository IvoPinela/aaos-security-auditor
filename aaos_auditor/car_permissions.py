"""Protection levels of `android.car.permission.*`, taken from the AOSP Car service manifest.

Source: https://android.googlesource.com/platform/packages/services/Car/+/refs/heads/main/service/AndroidManifest.xml
Branch: main. Retrieved: 2026-10-18 (156 permissions).

Protection levels differ between Android releases and OEM builds, so treat this as a strong hint and
confirm against the AAOS release you target. The level decides what a request *means*:

* `normal` and `dangerous`: a third-party app can be granted the permission (dangerous ones after a
  runtime prompt), so a request is a real data-access capability.
* anything with `signature`: only platform-signed or privileged system apps are granted it. A normal
  third-party app that requests it is not granted it; the request matters when the app is, or will
  be shipped as, a system app.
"""

from __future__ import annotations

from typing import Any

PREFIX = "android.car.permission."
SOURCE_URL = "https://android.googlesource.com/platform/packages/services/Car/+/refs/heads/main/service/AndroidManifest.xml"
SOURCE_NOTE = "AOSP main branch, retrieved 2026-10-18; confirm for your target AAOS release"

_TABLE = """
READ_DRIVER_MONITORING_SETTINGS signature|privileged
CONTROL_DRIVER_MONITORING_SETTINGS signature|privileged
READ_DRIVER_MONITORING_STATES signature|privileged
CAR_ENERGY dangerous
CONTROL_CAR_ENERGY signature|privileged
BIND_OEM_CAR_SERVICE signature|privileged
ADJUST_RANGE_REMAINING signature|privileged
CAR_IDENTIFICATION signature|privileged
CONTROL_CAR_CLIMATE signature|privileged
CONTROL_CAR_DOORS signature|privileged
CONTROL_CAR_WINDOWS signature|privileged
CONTROL_GLOVE_BOX signature|privileged
CONTROL_CAR_MIRRORS signature|privileged
CONTROL_CAR_SEATS signature|privileged
READ_CAR_SEATS dangerous
READ_CAR_SEAT_BELTS signature|privileged
READ_IMPACT_SENSORS signature|privileged
READ_VALET_MODE signature|privileged
CONTROL_VALET_MODE signature|privileged
READ_HEAD_UP_DISPLAY_STATUS signature|privileged
CONTROL_HEAD_UP_DISPLAY signature|privileged
READ_CAR_AIRBAGS signature|privileged
CONTROL_CAR_AIRBAGS signature|privileged
CAR_MILEAGE signature|privileged
CAR_MILEAGE_3P dangerous
READ_CAR_HORN dangerous
CONTROL_CAR_HORN signature|privileged
READ_CAR_PEDALS dangerous
READ_BRAKE_INFO dangerous
CAR_TIRES signature|privileged
CAR_TIRES_3P dangerous
READ_CAR_STEERING signature|privileged
READ_CAR_STEERING_3P dangerous
READ_CAR_DISPLAY_UNITS normal
CONTROL_CAR_DISPLAY_UNITS normal
CAR_SPEED dangerous
CAR_ENERGY_PORTS normal
CONTROL_CAR_ENERGY_PORTS signature|privileged
CAR_ENGINE_DETAILED signature|privileged
CAR_ENGINE_DETAILED_3P dangerous
CAR_DYNAMICS_STATE signature|privileged
CONTROL_CAR_DYNAMICS_STATE signature|privileged
CAR_VENDOR_EXTENSION signature|privileged
CAR_PROJECTION signature|privileged
ACCESS_CAR_PROJECTION_STATUS signature|privileged
CAR_MOCK_VEHICLE_HAL signature|privileged
CAR_INFO normal
PRIVILEGED_CAR_INFO signature|privileged
READ_CAR_VENDOR_PERMISSION_INFO signature|privileged
CAR_EXTERIOR_ENVIRONMENT normal
CAR_EPOCH_TIME signature|privileged
CAR_EXTERIOR_LIGHTS signature|privileged
READ_CAR_EXTERIOR_LIGHTS dangerous
CONTROL_CAR_EXTERIOR_LIGHTS signature|privileged
READ_CAR_INTERIOR_LIGHTS signature|privileged
CONTROL_CAR_INTERIOR_LIGHTS signature|privileged
CAR_POWER signature|privileged|vendorPrivileged
CAR_POWERTRAIN normal
CONTROL_CAR_POWERTRAIN signature|privileged
CAR_NAVIGATION_MANAGER signature|privileged
CAR_DIAGNOSTICS signature|privileged
CLEAR_CAR_DIAGNOSTICS signature|privileged
VMS_PUBLISHER signature|privileged
VMS_SUBSCRIBER signature|privileged
READ_ULTRASONICS_SENSOR_DATA signature|privileged
CAR_DRIVING_STATE signature|privileged
CAR_DRIVING_STATE_3P dangerous
USE_CAR_TELEMETRY_SERVICE signature|privileged
REQUEST_CAR_EVS_ACTIVITY signature|privileged
CONTROL_CAR_EVS_ACTIVITY signature|privileged
USE_CAR_EVS_CAMERA signature|privileged
MONITOR_CAR_EVS_STATUS signature|privileged
CONTROL_APP_BLOCKING signature|privileged
CAR_CONTROL_AUDIO_VOLUME signature|privileged
CAR_CONTROL_AUDIO_SETTINGS signature|privileged
RECEIVE_CAR_AUDIO_DUCKING_EVENTS signature|privileged
CAR_DISPLAY_IN_CLUSTER signature|privileged
CAR_INSTRUMENT_CLUSTER_CONTROL signature|privileged
CAR_MONITOR_CLUSTER_NAVIGATION_STATE signature|privileged
CAR_HANDLE_USB_AOAP_DEVICE signature|privileged
CAR_UX_RESTRICTIONS_CONFIGURATION signature|privileged
READ_CAR_OCCUPANT_AWARENESS_STATE signature|privileged
ACCESS_PRIVATE_DISPLAY_ID signature|privileged
CONTROL_CAR_OCCUPANT_AWARENESS_SYSTEM signature|privileged
STORAGE_MONITORING signature|privileged
CAR_ENROLL_TRUST signature|privileged
CAR_TEST_SERVICE signature|privileged
CONTROL_CAR_FEATURES signature|privileged
USE_CAR_WATCHDOG signature|privileged
CONTROL_CAR_WATCHDOG_CONFIG signature|privileged
COLLECT_CAR_WATCHDOG_METRICS signature|privileged
CAR_MONITOR_INPUT signature|privileged
READ_CAR_POWER_POLICY normal
CONTROL_CAR_POWER_POLICY signature|privileged|vendorPrivileged
CONTROL_SHUTDOWN_PROCESS signature|privileged|vendorPrivileged
TEMPLATE_RENDERER signature|privileged
CONTROL_CAR_APP_LAUNCH signature|privileged
MANAGE_THREAD_PRIORITY signature|privileged
MANAGE_OCCUPANT_ZONE signature|privileged
USE_REMOTE_ACCESS normal
CONTROL_REMOTE_ACCESS signature|privileged
CONTROL_STEERING_WHEEL signature|privileged
READ_ADAS_SETTINGS signature|privileged
CONTROL_ADAS_SETTINGS signature|privileged
READ_ADAS_STATES signature|privileged
CONTROL_ADAS_STATES signature|privileged
MANAGE_REMOTE_DEVICE signature|privileged
MANAGE_OCCUPANT_CONNECTION signature|privileged
ACCESS_MIRRORED_SURFACE signature|privileged
MIRROR_DISPLAY signature|privileged
REGISTER_CAR_SYSTEM_UI_PROXY signature|privileged
MANAGE_CAR_SYSTEM_UI signature|privileged
READ_WINDSHIELD_WIPERS signature|privileged
READ_WINDSHIELD_WIPERS_3P dangerous
CONTROL_WINDSHIELD_WIPERS signature|privileged
MANAGE_DISPLAY_COMPATIBILITY signature|privileged
READ_PERSIST_TETHERING_SETTINGS signature|privileged
BIND_APP_CARD_PROVIDER signature|privileged
RECORD_VEHICLE_PROPERTIES signature
INJECT_VEHICLE_PROPERTIES signature
"""

# The vendor-category permissions are generated, not listed one by one: GET_/SET_CAR_VENDOR_CATEGORY_<name>.
VENDOR_CATEGORY_PREFIXES = ("GET_CAR_VENDOR_CATEGORY_", "SET_CAR_VENDOR_CATEGORY_")
VENDOR_CATEGORY_LEVEL = "signature|privileged"

PROTECTION_LEVELS: dict[str, str] = {}
for _line in _TABLE.strip().splitlines():
    _name, _level = _line.split()
    PROTECTION_LEVELS[PREFIX + _name] = _level


def protection_level(permission: str) -> str | None:
    """Return the AOSP protection level of an android.car permission, or None when it is not in the table."""
    level = PROTECTION_LEVELS.get(permission)
    if level is not None:
        return level
    if permission.startswith(PREFIX) and permission[len(PREFIX):].startswith(VENDOR_CATEGORY_PREFIXES):
        return VENDOR_CATEGORY_LEVEL
    return None


def is_system_only(level: str | None) -> bool:
    """True when only platform-signed or privileged apps are granted the permission."""
    return level is not None and "signature" in level


def is_third_party_grantable(level: str | None) -> bool:
    """True when a normal third-party app can be granted the permission (dangerous ones after a prompt)."""
    return level is not None and not is_system_only(level)


def classify_car_permissions(permissions: list[str] | set[str]) -> list[dict[str, Any]]:
    """Describe every requested android.car permission with its protection level and what that implies."""
    result = []
    for permission in sorted(set(permissions)):
        if not permission.startswith(PREFIX):
            continue
        level = protection_level(permission)
        result.append({
            "permission": permission,
            "protection_level": level or "unknown",
            "system_only": is_system_only(level),
            "third_party_grantable": is_third_party_grantable(level),
            "known": level is not None,
        })
    return result
