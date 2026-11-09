"""Package prepared Linux overlays exclusively for Android instrumentation."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
LAYERS = ("linux-base-tools", "linux-git-curl", "linux-python")
COMPILERS = ("linux-go", "linux-go-stdlib", "linux-jdk", "linux-jdk-zero", "linux-android-build",
             "linux-native-activity", "linux-gradle", "linux-gradle-maven", "linux-gradle-sdk")


def guest_path(value):
    p = PurePosixPath(value)
    if (not value.startswith("/") or value.startswith("//") or value != p.as_posix()
            or ".." in p.parts or value == "/" or "\\" in value or "\0" in value):
        raise ValueError(f"Invalid guest path {value!r}")
    return value


def entry(name):
    info = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    return info


def package(inputs, output, layers=LAYERS):
    files, aliases = {}, {}
    for name in layers:
        folder = (inputs / name).resolve()
        layer = json.loads((folder / "manifest.json").read_bytes())
        for row in layer["files"]:
            path = guest_path(row["path"])
            src = (folder / row["asset"]).resolve()
            if not src.is_relative_to(folder) or not src.is_file():
                raise ValueError(f"Invalid source for {path}")
            data = src.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != row["sha256"].lower() or len(data) != row["bytes"]:
                raise ValueError(f"Integrity mismatch for {path}")
            spec = dict(path=path, sha256=digest, bytes=len(data), mode=row["mode"])
            if path in files and files[path][0] != spec:
                raise ValueError(f"Conflicting overlay file {path}")
            files[path] = (spec, src)
        for alias in layer.get("aliases", []):
            path, target = guest_path(alias["path"]), guest_path(alias["target"])
            if aliases.setdefault(path, target) != target:
                raise ValueError(f"Conflicting alias {path}")
    for path, target in aliases.items():
        if path in files or target not in files:
            raise ValueError(f"Invalid alias {path} -> {target}")
    paths = sorted(files)
    manifest = dict(schema_version=1, layers=layers, files=[files[p][0] for p in paths],
                    aliases=[dict(path=p, target=t) for p, t in sorted(aliases.items())])
    output.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=output.parent, delete=False) as temp:
        temporary = Path(temp.name)
    try:
        with ZipFile(temporary, "w") as archive:
            archive.writestr(entry("manifest.json"), json.dumps(manifest, separators=(",", ":")).encode())
            for path in paths:
                archive.writestr(entry("root" + path), files[path][1].read_bytes())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"{output.name}: {len(paths)} files, {len(aliases)} aliases, {output.stat().st_size} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=ROOT / ".build/toolbox-inputs")
    parser.add_argument("--compiler-layer", choices=COMPILERS, help="Package a separate optional compiler test fixture")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    group = args.compiler_layer or "linux-toolbox"
    output = args.output or ROOT / ".build/linux-test-assets" / group / "profile.bin"
    package(args.inputs, output, (group,) if args.compiler_layer else LAYERS)
