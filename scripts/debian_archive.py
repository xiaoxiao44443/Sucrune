"""Read verified Debian packages and their ARM64 ELF metadata."""
import hashlib
import io
from pathlib import Path
import re
import struct
import tarfile
import tempfile
import urllib.request


def atomic_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
    temp = Path(temporary.name)
    try:
        with temporary:
            temporary.write(data)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def fetch(row, cache, offline):
    name = row["filename"]
    if not re.fullmatch(r"pool/main/[\w+.-]+/[\w+.-]+/[\w~+.-]+_(arm64|all)\.deb", name, re.ASCII):
        raise ValueError("Bad Debian pool path: " + name)
    path = cache / name.rsplit("/", 1)[1]
    size = int(row["size"])
    if not 0 < size <= 64 * 1024 * 1024:
        raise ValueError("Unexpected Debian package size")
    cached = path.exists()
    if cached:
        if path.stat().st_size != size:
            raise ValueError("Incorrect cached package size: " + path.name)
        data = path.read_bytes()
    elif offline:
        raise FileNotFoundError(path)
    else:
        with urllib.request.urlopen("https://deb.debian.org/debian/" + name, timeout=50) as response:
            data = response.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ValueError("Debian package checksum mismatch: " + str(path.name))
    if not cached:
        atomic_file(path, data)
    return path


def payload(path):
    deb = path.read_bytes()
    if deb[:8] != b"!<arch>\n":
        raise ValueError("Invalid Debian ar header")
    pos = 8
    while pos + 60 <= len(deb):
        header = deb[pos:pos + 60]
        size = int(header[48:58].strip())
        pos += 60
        if size < 0 or pos + size > len(deb) or header[58:] != b"`\n":
            raise ValueError("Invalid Debian ar member")
        if header[:16].rstrip(b" /") in (b"data.tar.xz", b"data.tar.gz"):
            return tarfile.open(fileobj=io.BytesIO(deb[pos:pos + size]), mode="r:*")
        pos += size + size % 2
    raise ValueError("Missing Debian data payload")


def elf_deps(data):
    """Read AArch64 ELF64 PT_DYNAMIC through the file's load segments."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected little-endian ARM64 ELF")
    header_offset = struct.unpack_from("<Q", data, 32)[0]
    header_size, count = struct.unpack_from("<HH", data, 54)
    segments = [struct.unpack_from("<IIQQQQQQ", data, header_offset + i * header_size)
                for i in range(count)]
    dynamic = next((segment for segment in segments if segment[0] == 2), None)
    if dynamic is None:
        return None, []
    tags = []
    for off in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<QQ", data, off)
        if not tag:
            break
        tags.append((tag, value))
    string_address = next(value for tag, value in tags if tag == 5)  # DT_STRTAB
    load = next(segment for segment in segments
                if segment[0] == 1 and segment[3] <= string_address < segment[3] + segment[5])
    string_offset = string_address - load[3] + load[2]
    soname, needed = None, []
    for tag, value in tags:
        if tag not in (1, 14):  # DT_NEEDED, DT_SONAME
            continue
        name_offset = string_offset + value
        name = data[name_offset:data.index(b"\0", name_offset)].decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise ValueError("Unexpected dynamic library name")
        if tag == 1:
            needed.append(name)
        else:
            soname = name
    return soname, needed
