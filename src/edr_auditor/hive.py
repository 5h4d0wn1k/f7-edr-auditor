"""Minimal, read-only Windows registry hive (REGF v1.3 / v1.4) parser.

This is a deliberately small, dependency-free parser that understands just
enough of the on-disk hive format to walk keys, enumerate subkeys and read
value data (REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ / REG_DWORD / REG_BINARY).
It is used to audit persistence and services *passively*, straight from a
copy of an NTUSER.DAT / SOFTWARE / SYSTEM hive file, without any privileged
Windows API.

Also included: :class:`HiveBuilder`, a synthetic hive writer used by the
offline self-test and the unit tests so the parser is exercised on curated
fixtures without ever touching a real system.

Reference layout (verified against Project Zero "The Windows Registry
Adventure #5", dissect.regf and memf-windows source):

    _CM_KEY_NODE ("nk")              offset
      Signature 0x6B6E                0x00
      Flags (0x20 == KEY_COMP_NAME)   0x02
      LastWriteTime                   0x04
      AccessBits / Spare              0x0C
      Parent                          0x10
      SubKeyCounts[0] stable          0x14
      SubKeyCounts[1] volatile        0x18
      SubKeyLists[0] stable list cell 0x1C
      SubKeyLists[1] volatile list    0x20
      ValueList.Count                 0x24
      ValueList.List                  0x28
      Security                        0x2C
      Class                           0x30
      MaxNameLen                     0x34
      MaxClassLen                    0x38
      MaxValueNameLen                0x3C
      MaxValueDataLen                0x40
      WorkVar                        0x44
      NameLength                      0x48
      ClassLength                     0x4A
      Name (0x4C...)

    _CM_KEY_INDEX ("li"/"lf"/"lh"/"ri")
      Signature 0x02, Count 0x04, then entries:
        "li"/"ri": u32 cell indexes (4 bytes each)
        "lf"/"lh": (u32 cell, u32 name hint) -> 8 bytes each

    _CM_KEY_VALUE ("vk")
      Signature 0x6B56 @0x00, NameLength @0x02,
      DataLength @0x04, Data @0x08 (cell index or inline),
      Type @0x0C, Flags @0x10 (0x1 == KEY_VALUE_COMP_NAME),
      Name @0x14

Cell size headers are placed *before* cell data; a NEGATIVE size marks an
allocated cell (the magnitude includes the 4-byte header), a positive size
marks a free cell. All cell indexes are offsets relative to 0x1000, so an
absolute file offset is ``0x1000 + cell_index``.
"""

import struct

# Registry value types we decode.
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_MULTI_SZ = 7
REG_QWORD = 11

TYPE_NAMES = {
    REG_NONE: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_QWORD: "REG_QWORD",
}

HCELL_NIL = 0xFFFFFFFF
HIVE_BASE = 0x1000

# Flag bits.
KEY_COMP_NAME = 0x20  # compact 8-bit key names
VALUE_COMP_NAME = 0x1  # compact 8-bit value names


def _encode_name(name):
    """Encode a key/value name. Pure-ASCII/Latin-1 names use the compact
    8-bit form; anything else is written as UTF-16LE (non-compact)."""
    try:
        b = str(name).encode("latin-1")
    except UnicodeEncodeError:
        return str(name).encode("utf-16-le"), False
    if b.decode("latin-1") == str(name):
        return b, True
    return str(name).encode("utf-16-le"), False


class HiveError(Exception):
    """Raised for malformed or unsupported hive files."""


def decode_value_data(vtype, data):
    """Decode raw value data bytes according to the registry type."""
    if vtype in (REG_SZ, REG_EXPAND_SZ):
        if not data:
            return ""
        try:
            text = data.decode("utf-16-le")
        except UnicodeDecodeError:
            return "".join(chr(b) for b in data)  # keep it lossless
        return text.rstrip("\x00")
    if vtype == REG_MULTI_SZ:
        if not data:
            return []
        text = data.decode("utf-16-le", "replace")
        return [part for part in text.split("\x00") if part]
    if vtype in (REG_DWORD_BIG_ENDIAN,):
        return struct.unpack(">I", data[:4].ljust(4, b"\x00"))[0]
    if vtype in (REG_DWORD, REG_QWORD):
        width = 4 if vtype == REG_DWORD else 8
        return int.from_bytes(data[:width].ljust(width, b"\x00"), "little")
    if vtype == REG_NONE:
        return data.hex()
    return data.hex()


def encode_value_data(vtype, data):
    """Encode a Python value into raw hive value data (HiveBuilder helper)."""
    if vtype in (REG_SZ, REG_EXPAND_SZ):
        return str(data).encode("utf-16-le")
    if vtype == REG_MULTI_SZ:
        parts = list(data)
        return ("\x00".join(parts) + "\x00").encode("utf-16-le")
    if vtype == REG_DWORD:
        return struct.pack("<I", int(data))
    if vtype == REG_QWORD:
        return struct.pack("<Q", int(data))
    if vtype in (REG_BINARY, REG_NONE) and isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return str(data).encode("utf-8")


# ---------------------------------------------------------------------------
# Reading cells
# ---------------------------------------------------------------------------

class HiveRegistry:
    """Read-only view of a REGF hive file."""

    def __init__(self, path):
        with open(path, "rb") as fh:
            self._blob = fh.read()
        self.path = str(path)
        self._parse_header()
        self._root = None

    def _parse_header(self):
        blob = self._blob
        if len(blob) < HIVE_BASE:
            raise HiveError("file too small to be a registry hive")
        if blob[0:4] != b"regf":
            raise HiveError(f"not a REGF hive (signature {blob[0:4]!r})")
        self.major = struct.unpack_from("<I", blob, 0x14)[0]
        self.minor = struct.unpack_from("<I", blob, 0x18)[0]
        if self.major != 1:
            raise HiveError(f"unsupported hive format major {self.major}")
        self.root_cell = struct.unpack_from("<I", blob, 0x24)[0]

    def _cell_offset(self, cell_index):
        if cell_index == HCELL_NIL:
            return -1
        return HIVE_BASE + cell_index

    def read_cell(self, cell_index):
        """Return body bytes of an allocated cell, or None for free/absent."""
        off = self._cell_offset(cell_index)
        if off < HIVE_BASE or off + 4 > len(self._blob):
            return None
        raw = struct.unpack_from("<i", self._blob, off)[0]
        if raw > 0:  # free cell (positive size)
            return None
        size = -raw
        if size < 4 or off + size > len(self._blob):
            return None
        return self._blob[off + 4: off + size]

    # -- navigation ---------------------------------------------------------

    def root(self):
        if self._root is None:
            body = self.read_cell(self.root_cell)
            if body is None or body[0:2] != b"nk":
                raise HiveError("root key node not found")
            self._root = KeyNode(self, self.root_cell, body, "")
        return self._root

    def open_key(self, path):
        """Walk ``path`` (split on '\\\\' or '/') from the hive root."""
        if not path:
            return self.root()
        node = self.root()
        for part in path.replace("\\", "\0").replace("/", "\0").split("\0"):
            if not part:
                continue
            node = node.subkey(part)
            if node is None:
                return None
        return node


class Value:
    """A registry value: name, raw type + data, decoded data."""

    __slots__ = ("name", "type", "raw", "data", "data_length")

    def __init__(self, name, vtype, raw, data, data_length):
        self.name = name
        self.type = vtype
        self.raw = raw
        self.data = data
        self.data_length = data_length

    def __repr__(self):
        return f"<Value {self.name}={self.data!r}>"


class KeyNode:
    """A key node inside a hive."""

    __slots__ = ("hive", "cell_index", "body", "path", "name", "flags",
                 "stable_count", "stable_list", "volatile_list",
                 "value_count", "value_list")

    def __init__(self, hive, cell_index, body, path):
        self.hive = hive
        self.cell_index = cell_index
        self.body = body
        self.path = path
        self.flags = struct.unpack_from("<H", body, 0x02)[0]
        self.stable_count = struct.unpack_from("<I", body, 0x14)[0]
        self.stable_list = struct.unpack_from("<I", body, 0x1C)[0]
        self.volatile_list = struct.unpack_from("<I", body, 0x20)[0]
        self.value_count = struct.unpack_from("<I", body, 0x24)[0]
        self.value_list = struct.unpack_from("<I", body, 0x28)[0]
        name_len = struct.unpack_from("<H", body, 0x48)[0]
        name_blob = body[0x4C: 0x4C + name_len]
        if self.flags & KEY_COMP_NAME:
            self.name = name_blob.decode("latin-1", "replace")
        else:
            self.name = name_blob.decode("utf-16-le", "replace")
        if not self.name:
            self.name = path.rsplit("\\", 1)[-1] if path else ""

    def __repr__(self):
        return f"<KeyNode {self.path}>"

    # -- children -----------------------------------------------------------

    def _child_cells(self):
        if not self.stable_count or self.stable_list in (0, HCELL_NIL):
            return []
        body = self.hive.read_cell(self.stable_list)
        if body is None or len(body) < 4:
            return []
        sig = body[0:2]
        count = struct.unpack_from("<H", body, 0x02)[0]
        stride = 4 if sig == b"li" else 8  # "lf"/"lh"/"ri" use 8-byte entries
        cells = []
        for i in range(count):
            base = 4 + i * stride
            if base + 4 > len(body):
                break
            cells.append(struct.unpack_from("<I", body, base)[0])
        return cells

    def subkeys(self):
        out = []
        prefix = f"{self.path}\\" if self.path else ""
        for cell in self._child_cells():
            body = self.hive.read_cell(cell)
            if body is None or body[0:2] != b"nk":
                continue
            name_len = struct.unpack_from("<H", body, 0x48)[0]
            if struct.unpack_from("<H", body, 0x02)[0] & KEY_COMP_NAME:
                name = body[0x4C: 0x4C + name_len].decode("latin-1", "replace")
            else:
                name = body[0x4C: 0x4C + name_len].decode("utf-16-le", "replace")
            out.append(KeyNode(self.hive, cell, body, f"{prefix}{name}"))
        return out

    def subkey(self, name):
        for child in self.subkeys():
            if child.name == name:
                return child
        return None

    # -- values --------------------------------------------------------------

    def values(self):
        """Return the stable values of this key (decoded for known types)."""
        out = []
        if not self.value_count or self.value_list in (0, HCELL_NIL):
            return out
        body = self.hive.read_cell(self.value_list)
        if body is None:
            return out
        for i in range(self.value_count):
            base = i * 4
            if base + 4 > len(body):
                break
            vcell = struct.unpack_from("<I", body, base)[0]
            vbody = self.hive.read_cell(vcell)
            if vbody is None or vbody[0:2] != b"vk":
                continue
            name_len = struct.unpack_from("<H", vbody, 0x02)[0]
            data_len = struct.unpack_from("<I", vbody, 0x04)[0]
            data_field = struct.unpack_from("<I", vbody, 0x08)[0]
            vtype = struct.unpack_from("<I", vbody, 0x0C)[0]
            vflags = struct.unpack_from("<H", vbody, 0x10)[0]
            name_blob = vbody[0x14: 0x14 + name_len]
            if vflags & VALUE_COMP_NAME:
                vname = name_blob.decode("latin-1", "replace")
            else:
                vname = name_blob.decode("utf-16-le", "replace")
            if data_len <= 4:
                raw = struct.pack("<I", data_field)[:data_len]
            else:
                dbody = self.hive.read_cell(data_field)
                raw = (dbody or b"")[:data_len]
            out.append(Value(vname, vtype, raw, decode_value_data(vtype, raw), data_len))
        return out

    def get_value(self, name):
        for value in self.values():
            if value.name == name:
                return value
        return None


# ---------------------------------------------------------------------------
# Synthetic hive builder (for self-test / unit fixtures; never touches a host)
# ---------------------------------------------------------------------------

class _Assembler:
    """Lays cells out sequentially starting at cell index 0x20."""

    def __init__(self):
        self.buf = bytearray()
        self.next = 0x20

    def alloc(self, body):
        payload = len(body)
        size = 4 + payload
        size += (-size) % 8  # pad to 8 bytes
        index = self.next
        self.buf += struct.pack("<i", -size) + body + b"\x00" * (size - 4 - payload)
        self.next += size
        return index

    def alloc_nk(self, name, stable_count, stable_list, value_count=0,
                 value_list=None, comp=True):
        body = bytearray(0x4C) + name
        body[0:2] = b"nk"
        struct.pack_into("<H", body, 0x02, KEY_COMP_NAME if comp else 0)
        struct.pack_into("<I", body, 0x10, HCELL_NIL)
        struct.pack_into("<I", body, 0x14, stable_count)
        struct.pack_into("<I", body, 0x18, 0)
        struct.pack_into("<I", body, 0x1C, stable_list if stable_list else HCELL_NIL)
        struct.pack_into("<I", body, 0x20, HCELL_NIL)
        struct.pack_into("<I", body, 0x24, value_count)
        struct.pack_into("<I", body, 0x28, value_list if value_list else HCELL_NIL)
        struct.pack_into("<I", body, 0x2C, HCELL_NIL)
        struct.pack_into("<I", body, 0x30, HCELL_NIL)
        struct.pack_into("<H", body, 0x48, len(name))
        struct.pack_into("<H", body, 0x4A, 0)
        return self.alloc(bytes(body))

    def alloc_index(self, sig, cells):
        body = sig + struct.pack("<H", len(cells))
        body += b"".join(struct.pack("<I", c) for c in cells)
        return self.alloc(body)

    def alloc_value_list(self, vk_cells):
        return self.alloc(b"".join(struct.pack("<I", c) for c in vk_cells))

    def alloc_vk(self, name, vtype, data_len, data_index, comp=True):
        body = bytearray(0x14) + name
        body[0:2] = b"vk"
        struct.pack_into("<H", body, 0x02, len(name))
        struct.pack_into("<I", body, 0x04, data_len)
        struct.pack_into("<I", body, 0x08, data_index)
        struct.pack_into("<I", body, 0x0C, vtype & 0xFFFFFFFF)
        struct.pack_into("<H", body, 0x10, VALUE_COMP_NAME if comp else 0)
        struct.pack_into("<H", body, 0x12, 0)
        return self.alloc(bytes(body))

    def alloc_data(self, data):
        return self.alloc(bytes(data))


class HiveBuilder:
    """Build a minimal but structurally-valid REGF hive for fixtures."""

    def __init__(self):
        self._root = None  # dict node
        self._lineno = 0
        self._nodes = {}  # key path -> dict(name, children, values)

    def _node(self, path):
        parts = [p for p in path.replace("/", "\0").replace("\\", "\0").split("\0") if p]
        if not parts:
            return self._root
        if self._root is None:
            self._root = {"name": "ROOT", "children": [], "values": []}
        cur = self._root
        for part in parts:
            target = None
            for child in cur["children"]:
                if child["name"] == part:
                    target = child
                    break
            if target is None:
                target = {"name": part, "children": [], "values": []}
                cur["children"].append(target)
            cur = target
        return cur

    def add_key(self, path):
        return self._node(path)

    def add_value(self, path, name, vtype, data):
        node = self._node(path)
        node["values"].append((name, vtype, data))
        return node

    # -- finalization ---------------------------------------------------------

    def _finalize(self, node, assembler):
        child_cells = [self._finalize(c, assembler) for c in node["children"]]
        list_index = None
        if child_cells:
            if len(child_cells) == 1:
                list_index = assembler.alloc_index(b"li", child_cells)
            else:
                list_index = assembler.alloc_index(b"li", child_cells)

        vk_cells = []
        for (name, vtype, data) in node["values"]:
            raw = encode_value_data(vtype, data)
            if raw and len(raw) <= 4:
                # Values of 4 bytes or fewer live inline in the Data field
                # (matches Windows behaviour).
                data_index = int.from_bytes(raw, "little")
                data_len = len(raw)
            elif raw:
                data_index = assembler.alloc_data(raw)
                data_len = len(raw)
            else:
                data_index = HCELL_NIL
                data_len = 0
            name_bytes_comp = _encode_name(name)
            vk_cells.append(assembler.alloc_vk(name_bytes_comp[0], vtype, data_len,
                                               data_index, comp=name_bytes_comp[1]))

        value_list_index = None
        if vk_cells:
            value_list_index = assembler.alloc_value_list(vk_cells)

        node_name, comp = _encode_name(node["name"])
        idx = assembler.alloc_nk(
            node_name,
            len(child_cells),
            list_index,
            value_count=len(vk_cells),
            value_list=value_list_index,
            comp=comp,
        )
        return idx

    def write(self, path):
        bytes_ = self.to_bytes()
        import os
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(bytes_)

    def to_bytes(self):
        assembler = _Assembler()
        if self._root is None:
            self._root = {"name": "ROOT", "children": [], "values": []}
        root_index = self._finalize(self._root, assembler)

        cell_bytes = bytes(assembler.buf)
        bin_size = 0x20 + len(cell_bytes)
        aligned = ((bin_size + 0xFFF) // 0x1000) * 0x1000

        hbin = bytearray(aligned)
        hbin[0:4] = b"hbin"
        struct.pack_into("<I", hbin, 0x04, 0)  # offset relative to 0x1000
        struct.pack_into("<I", hbin, 0x08, aligned)
        hbin[0x20: 0x20 + len(cell_bytes)] = cell_bytes
        free_pos = 0x20 + len(cell_bytes)
        free_size = aligned - free_pos
        if free_size >= 8:
            struct.pack_into("<I", hbin, free_pos, free_size)

        regf = bytearray(HIVE_BASE)
        regf[0:4] = b"regf"
        struct.pack_into("<I", regf, 0x04, 1)
        struct.pack_into("<I", regf, 0x08, 1)
        struct.pack_into("<Q", regf, 0x0C, 0)
        struct.pack_into("<I", regf, 0x14, 1)  # major
        struct.pack_into("<I", regf, 0x18, 4)  # minor
        struct.pack_into("<I", regf, 0x1C, 0)
        struct.pack_into("<I", regf, 0x20, 1)  # format
        struct.pack_into("<I", regf, 0x24, root_index)
        struct.pack_into("<I", regf, 0x28, aligned)
        struct.pack_into("<I", regf, 0x2C, 1)
        name = b"f7-edr-fixture-hive\x00"
        regf[0x30: 0x30 + len(name)] = name
        # Simple checksum (sum of DWORDs in the header block).
        struct.pack_into("<I", regf, 0x70, 0)
        cksum = 0
        for i in range(0x04, 0x74, 4):
            cksum = (cksum + struct.unpack_from("<I", regf, i)[0]) & 0xFFFFFFFF
        struct.pack_into("<I", regf, 0x70, cksum)
        regf[0x74:] = b"\x00" * (HIVE_BASE - 0x74)

        return bytes(regf) + bytes(hbin)