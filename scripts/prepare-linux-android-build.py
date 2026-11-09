"""Prepare Debian ARM64 Android build programs and portable Android SDK jars for instrumentation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath

from debian_archive import atomic_file, elf_deps, fetch, payload

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/opt/android-sdk"
PROGRAMS = {
    "usr/lib/android-sdk/build-tools/debian/aapt": "aapt",
    "usr/lib/android-sdk/build-tools/debian/aapt2": "aapt2",
    "usr/lib/android-sdk/build-tools/debian/zipalign": "zipalign",
    "usr/bin/zip": "zip",
}
SDK_FILES = {
    "build-tools/36.0.0/lib/d8.jar": "lib/d8.jar",
    "build-tools/36.0.0/lib/apksigner.jar": "lib/apksigner.jar",
    "platforms/android-37.0/android.jar": "platform/android.jar",
    "build-tools/36.0.0/NOTICE.txt": "licenses/build-tools-NOTICE.txt",
    "platforms/android-37.0/package.xml": "licenses/platform-package.xml",
}
BASE_LIBS = {"ld-linux-aarch64.so.1", "libc.so.6", "libpthread.so.0", "libdl.so.2",
             "libm.so.6", "libgcc_s.so.1", "libstdc++.so.6"}


def prepare(cache, sdk, output, offline):
    lock = json.loads(Path(__file__).with_name("linux-android-build-packages.json").read_text())
    packages = lock["packages"]
    with ThreadPoolExecutor(max_workers=5) as workers:
        archives = list(workers.map(lambda row: fetch(row, cache, offline), packages))
    files, libraries, needed, programs = {}, {}, set(), set()

    def emit(relative, data, package, executable=False):
        guest = PREFIX + "/" + relative
        if guest in files:
            raise ValueError("Duplicate Android build file: " + guest)
        digest = hashlib.sha256(data).hexdigest()
        asset = "files/" + digest + ".bin"
        atomic_file(output / asset, data)
        files[guest] = dict(path=guest, asset=asset, bytes=len(data), sha256=digest,
                            mode=0o755 if executable else 0o644, package=package)

    for row, archive in zip(packages, archives):
        name = row["package"]
        with payload(archive) as tar:
            for member in tar:
                if not member.isfile():
                    continue
                path = member.name.removeprefix("./")
                if path in PROGRAMS:
                    data = tar.extractfile(member).read()
                    _, deps = elf_deps(data)
                    programs.add(PROGRAMS[path])
                    needed.update(deps)
                    emit("bin/" + PROGRAMS[path], data, name, True)
                elif path == "usr/share/android-framework-res/framework-res.apk":
                    emit("platform/framework-res.apk", tar.extractfile(member).read(), name)
                elif path.startswith(("lib/", "usr/lib/")) and ".so" in PurePosixPath(path).name:
                    data = tar.extractfile(member).read()
                    library, deps = elf_deps(data)
                    if path == "usr/lib/p7zip/7z.so" and library is None:
                        library = "7z.so"
                    if library:
                        if library in libraries:
                            raise ValueError("Duplicate Android dependency SONAME: " + library)
                        libraries[library] = data, name, deps
                elif path in (f"usr/share/doc/{name}/copyright", f"usr/share/doc/{name}/NOTICE.gz"):
                    emit("licenses/" + name + "-" + PurePosixPath(path).name, tar.extractfile(member).read(), name)
    if programs != set(PROGRAMS.values()) or PREFIX + "/platform/framework-res.apk" not in files:
        raise ValueError("Missing Android build tools or framework resources")
    resolved = set(BASE_LIBS)
    pending = sorted(needed)
    while pending:
        library = pending.pop()
        if library in resolved:
            continue
        data, name, deps = libraries[library]
        emit("lib/" + library, data, name)
        resolved.add(library)
        pending.extend(deps)
    if {row["source"] for row in lock["sdk"]} != set(SDK_FILES):
        raise ValueError("SDK input lock does not match required files")
    for row in lock["sdk"]:
        data = (sdk / row["source"]).read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("SDK file differs from the recorded revision: " + row["source"])
        emit(SDK_FILES[row["source"]], data, row["source"])
    manifest = dict(schema_version=1, name="linux-arm64-android-build-tools", packages=packages,
                    sdk=lock["sdk"], files=[files[key] for key in sorted(files)])
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(files)} Android build files, {sum(f['bytes'] for f in files.values())} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True, help="Android SDK with the revisions in the lock")
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-android-build")
    parser.add_argument("--offline", action="store_true")
    options = parser.parse_args()
    prepare(options.cache, options.sdk, options.output, options.offline)
