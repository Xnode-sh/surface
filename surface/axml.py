# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""Minimal binary AndroidManifest.xml (AXML) reader.

Pure Python, no dependencies: parses the compiled XML chunk format that lives
inside every APK as AndroidManifest.xml.
"""

import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class XmlNode:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag):
        self.tag = tag
        self.attrs = {}
        self.children = []

    def find_all(self, tag):
        return [c for c in self.children if c.tag == tag]

    def find(self, tag):
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def __repr__(self):
        return f"<{self.tag} {self.attrs}>"


def _read_string_pool(buf, off):
    (chunk_type, header_size, chunk_size) = struct.unpack_from("<HHI", buf, off)
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from("<IIIII", buf, off + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{string_count}I", buf, off + header_size)
    data_base = off + strings_start
    out = []
    for rel in offsets:
        p = data_base + rel
        if p >= len(buf):
            out.append("")
            continue
        if utf8:
            n = buf[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | buf[p + 1]
                p += 2
            else:
                p += 1
            raw = buf[p:p + n]
            out.append(raw.decode("utf-8", errors="replace"))
        else:
            n = struct.unpack_from("<H", buf, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
                p += 2
            raw = buf[p:p + n * 2]
            out.append(raw.decode("utf-16-le", errors="replace"))
    return out


def _attr_value(buf, strings, raw_value, data_type, data):
    if raw_value != 0xFFFFFFFF and raw_value < len(strings):
        return strings[raw_value]
    if data_type == TYPE_STRING and data < len(strings):
        return strings[data]
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if data_type == TYPE_INT_DEC:
        return str(struct.unpack("<i", struct.pack("<I", data))[0])
    if data_type == TYPE_INT_HEX:
        return f"0x{data:x}"
    return None


def _name(strings, idx):
    if idx != 0xFFFFFFFF and idx < len(strings):
        return strings[idx]
    return None


def parse(buf):
    """Parse compiled AndroidManifest.xml bytes into a tree of XmlNode."""
    if len(buf) < 8:
        raise ValueError("manifest too short")
    chunk_type, header_size, total = struct.unpack_from("<HHI", buf, 0)
    if chunk_type != RES_XML_TYPE:
        raise ValueError("not a binary XML document")

    strings = []
    root = None
    stack = []
    off = header_size

    while off + 8 <= total:
        ctype, c_header, csize = struct.unpack_from("<HHI", buf, off)
        if csize < 8:
            break
        if ctype == RES_STRING_POOL_TYPE:
            strings = _read_string_pool(buf, off)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            ns_idx, name_idx = struct.unpack_from("<II", buf, off + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", buf, off + 24)
            node = XmlNode(_name(strings, name_idx))
            base = off + 16 + attr_start
            for i in range(attr_count):
                a = base + i * attr_size
                a_ns, a_name, a_raw = struct.unpack_from("<III", buf, a)
                v_size, _res0, v_type, v_data = struct.unpack_from("<HBBI", buf, a + 12)
                key = _name(strings, a_name)
                val = _attr_value(buf, strings, a_raw, v_type, v_data)
                if key is not None:
                    node.attrs[key] = val
            if stack:
                stack[-1].children.append(node)
            elif root is None:
                root = node
            stack.append(node)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        off += csize

    if root is None:
        raise ValueError("empty manifest")
    return root
