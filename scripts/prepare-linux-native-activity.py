"""Stage an ARM64 C compiler and the NDK API 29 link stub used by the NativeActivity probe."""
import argparse
import hashlib
import json
from pathlib import Path

from debian_archive import atomic_file, elf_deps, fetch, payload

ROOT = Path(__file__).resolve().parents[1]


def prepare(cache, sdk, output, offline):
    lock = json.loads(Path(__file__).with_name("linux-native-activity-packages.json").read_text())
    package = lock["package"]
    files = []

    def emit(path, data, source, mode=0o644):
        digest = hashlib.sha256(data).hexdigest()
        asset = "files/" + digest + ".bin"
        atomic_file(output / asset, data)
        files.append(dict(path="/opt/android-native/" + path, asset=asset, bytes=len(data),
                          sha256=digest, mode=mode, package=source))

    with payload(fetch(package, cache, offline)) as tar:
        compiler = tar.extractfile("./usr/bin/tcc").read()
        _, deps = elf_deps(compiler)
        if set(deps) - {"libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "ld-linux-aarch64.so.1"}:
            raise ValueError("Unexpected TinyCC dependency: " + str(deps))
        emit("bin/tcc", compiler, package["package"], 0o755)
        emit("licenses/tcc-copyright", tar.extractfile("./usr/share/doc/tcc/copyright").read(), package["package"])
    ndk = sdk / "ndk" / lock["ndk_revision"]
    stub_path = next(path / lock["stub"] for path in (ndk / "toolchains/llvm/prebuilt").iterdir()
                     if (path / lock["stub"]).is_file())
    stub = stub_path.read_bytes()
    if len(stub) != lock["stub_bytes"] or hashlib.sha256(stub).hexdigest() != lock["stub_sha256"]:
        raise ValueError("Android NDK stub checksum mismatch")
    source = "Android NDK " + lock["ndk_revision"]
    emit("lib/libandroid.so", stub, source)
    emit("licenses/NDK-NOTICE", (ndk / "NOTICE").read_bytes(), source)
    manifest = dict(schema_version=1, name="linux-arm64-native-activity-compiler",
                    packages=[package], ndk=lock["ndk_revision"], files=files)
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(files)} native build inputs, {sum(f['bytes'] for f in files)} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-native-activity")
    parser.add_argument("--offline", action="store_true")
    options = parser.parse_args()
    prepare(options.cache, options.sdk, options.output, options.offline)
