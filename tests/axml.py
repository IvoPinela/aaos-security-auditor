"""Build a minimal binary Android manifest (AXML) and APK so the real Androguard parser can be tested.

Android compiles `AndroidManifest.xml` into a binary format. Without the Android SDK there is no `aapt`, so this
is a small encoder for exactly what a manifest needs: a string pool, namespaces, elements and typed attributes.
It lets tests run the *real* `analyze_apk` path instead of a fake.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO
from xml.etree import ElementTree

ANDROID_URI = "http://schemas.android.com/apk/res/android"
NO_ENTRY = 0xFFFFFFFF

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

# Resource ids of the android: attributes a manifest uses; aapt writes them in a resource map chunk.
RES_XML_RESOURCE_MAP = 0x0180
ATTR_RESOURCE_IDS = {
    "name": 0x01010003, "exported": 0x01010010, "permission": 0x01010006, "debuggable": 0x0101000F,
    "allowBackup": 0x01010280, "usesCleartextTraffic": 0x010104EC, "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270, "versionCode": 0x0101021B, "versionName": 0x0101021C, "scheme": 0x01010027,
    "host": 0x01010028, "pathPrefix": 0x0101002B, "autoVerify": 0x010104EE, "testOnly": 0x01010272,
    "grantUriPermissions": 0x0101001B, "authorities": 0x01010018, "sharedUserId": 0x0101000B, "required": 0x0101028E,
}


class _StringPool:
    def __init__(self) -> None:
        self.strings: list[str] = []

    def index(self, value: str) -> int:
        if value not in self.strings:
            self.strings.append(value)
        return self.strings.index(value)


def _chunk(chunk_type: int, header_extra: bytes, body: bytes) -> bytes:
    header_size = 8 + len(header_extra)
    return struct.pack("<HHI", chunk_type, header_size, header_size + len(body)) + header_extra + body


def _string_pool_chunk(strings: list[str]) -> bytes:
    data = bytearray()
    offsets = []
    for value in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(value)) + value.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + 4 * len(strings)
    header_extra = struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
    return _chunk(RES_STRING_POOL, header_extra, b"".join(struct.pack("<I", o) for o in offsets) + bytes(data))


def _attribute_value(pool: _StringPool, raw: str) -> tuple[int, int, int]:
    """Return (raw string index, data type, data) the way aapt encodes common manifest values."""
    if raw in ("true", "false"):
        return NO_ENTRY, TYPE_INT_BOOLEAN, NO_ENTRY if raw == "true" else 0
    if raw.lstrip("-").isdigit():
        return NO_ENTRY, TYPE_INT_DEC, int(raw) & 0xFFFFFFFF
    index = pool.index(raw)
    return index, TYPE_STRING, index


def build_axml(xml_text: str) -> bytes:
    """Compile manifest XML text (with the android: namespace) to Android binary XML."""
    ElementTree.register_namespace("android", ANDROID_URI)
    root = ElementTree.fromstring(xml_text)
    pool = _StringPool()
    attribute_names: list[str] = []

    # Pass 1: attribute names first, so that the resource map lines up with the start of the string pool.
    def collect(element: ElementTree.Element) -> None:
        for key in element.attrib:
            local = key.rsplit("}", 1)[-1]
            if key.startswith("{") and local in ATTR_RESOURCE_IDS and local not in attribute_names:
                attribute_names.append(local)
        for child in element:
            collect(child)

    collect(root)
    for name in attribute_names:
        pool.index(name)
    prefix_index, uri_index = pool.index("android"), pool.index(ANDROID_URI)

    body = bytearray()
    line = 1

    def namespace_chunk(chunk_type: int) -> bytes:
        return _chunk(chunk_type, struct.pack("<II", line, NO_ENTRY), struct.pack("<II", prefix_index, uri_index))

    body += namespace_chunk(RES_XML_START_NAMESPACE)

    def emit(element: ElementTree.Element) -> None:
        nonlocal line
        line += 1
        name_index = pool.index(element.tag)
        attrs = []
        for key, raw in element.attrib.items():
            if key.startswith("{"):
                namespace, local = key[1:].split("}", 1)
                namespace_index = pool.index(namespace)
            else:
                local, namespace_index = key, NO_ENTRY
            raw_index, data_type, data = _attribute_value(pool, raw)
            attrs.append(struct.pack("<IIIHBBI", namespace_index, pool.index(local), raw_index, 8, 0, data_type, data))
        element_body = struct.pack("<IIHHHHHH", NO_ENTRY, name_index, 20, 20, len(attrs), 0, 0, 0) + b"".join(attrs)
        body.extend(_chunk(RES_XML_START_ELEMENT, struct.pack("<II", line, NO_ENTRY), element_body))
        for child in element:
            emit(child)
        line += 1
        body.extend(_chunk(RES_XML_END_ELEMENT, struct.pack("<II", line, NO_ENTRY), struct.pack("<II", NO_ENTRY, name_index)))

    emit(root)
    body += namespace_chunk(RES_XML_END_NAMESPACE)

    resource_map = _chunk(RES_XML_RESOURCE_MAP, b"", b"".join(struct.pack("<I", ATTR_RESOURCE_IDS[n]) for n in attribute_names))
    pool_chunk = _string_pool_chunk(pool.strings)
    payload = pool_chunk + resource_map + bytes(body)
    return _chunk(RES_XML, b"", payload)


def build_apk(manifest_xml: str, extra_files: dict[str, bytes] | None = None) -> bytes:
    """A zip with a compiled manifest, enough for Androguard and for the upload limits of this tool."""
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_axml(manifest_xml))
        for name, content in (extra_files or {}).items():
            archive.writestr(name, content)
    return buffer.getvalue()
