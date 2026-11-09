"""Build opt-in offline Gradle / Maven layers for the Android instrumentation APK."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
from debian_archive import atomic_file


ROOT = Path(__file__).resolve().parents[1]
GRADLE = "9.3.1"
# sha256sum-compatible manifest of bin/gradle, LICENSE, NOTICE, README and lib/**/*.jar.
GRADLE_TREE = "8329fe30cab969bc17807656501324f96703d65ee190fc12025d5b104de7bfa2"
MAVEN_LOCK = Path(__file__).with_name("linux-gradle-maven.lock")
JAVA = "/usr/lib/jvm/java-17-openjdk-arm64"


def launcher_files(home, cache):
    inputs = [home / p for p in ("bin/gradle", "LICENSE", "NOTICE", "README")]
    inputs.extend((home / "lib").rglob("*.jar"))
    tree = hashlib.sha256()
    for path in sorted(inputs, key=lambda f: f.relative_to(home).as_posix()):
        relative = path.relative_to(home).as_posix()
        data = path.read_bytes()
        tree.update(f"{hashlib.sha256(data).hexdigest()}  {relative}\n".encode())
        yield "/opt/gradle/" + relative, data, relative == "bin/gradle"
    if tree.hexdigest() != GRADLE_TREE:
        raise ValueError(f"Gradle {GRADLE} distribution contents differ from fixture lock")
    # The base compiler fixture supplies java, javac, lib/modules and the VM.
    jdk = runpy.run_path(str(Path(__file__).with_name("prepare-linux-jdk.py")))
    helpers = {"jre": {"lib/jspawnhelper", "lib/libinstrument.so", "lib/libprefs.so",
                       "lib/libmanagement_agent.so", "bin/keytool"},
               "jdk": {"bin/jlink", "bin/jmod", "bin/jar", "jmods/java.base.jmod"}}
    for package, wanted in helpers.items():
        found = set()
        with jdk["archive"](cache, jdk["PACKAGES"][package], True) as archive:
            for item in archive:
                name = item.name.removeprefix("./")
                relative = name.removeprefix(JAVA.strip("/") + "/")
                if relative in wanted and item.isfile():
                    found.add(relative)
                    yield JAVA + "/" + relative, archive.extractfile(item).read(), bool(item.mode & 0o111)
        if wanted != found:
            raise ValueError(f"Debian {package} missing {wanted - found}")


def maven_files(caches):
    for line in MAVEN_LOCK.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        group, module, version, filename, sha1, digest = line.split()
        local = Path(group) / module / version / sha1 / filename
        for cache in caches:
            candidate = cache / "modules-2/files-2.1" / local
            if candidate.is_file():
                data = candidate.read_bytes()
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("Maven artifact SHA-256 mismatch: " + str(local))
                yield f"/opt/maven/{group.replace('.', '/')}/{module}/{version}/{filename}", data, False
                break
        else:
            raise FileNotFoundError(f"{local} missing from the supplied Gradle caches")


def prepare(layer, files, inputs, output):
    folder = inputs / layer
    rows = {}
    for path, data, executable in files:
        if path in rows:
            raise ValueError("Duplicate fixture path: " + path)
        digest = hashlib.sha256(data).hexdigest()
        asset = f"files/{digest}.bin"
        atomic_file(folder / asset, data)
        rows[path] = dict(path=path, asset=asset, bytes=len(data), sha256=digest,
                          mode=0o755 if executable else 0o644)
    manifest = dict(schema_version=1, name=layer, files=[rows[k] for k in sorted(rows)])
    atomic_file(folder / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    packager = runpy.run_path(str(Path(__file__).with_name("prepare-toolbox-fixture.py")))
    packager["package"](inputs, output / layer / "profile.bin", (layer,))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", type=Path, help="Extracted Gradle 9.3.1 binary distribution")
    parser.add_argument("--gradle-cache", type=Path, action="append", default=[],
                        help="Gradle caches directory with modules-2/files-2.1 (repeatable)")
    parser.add_argument("--debian-cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--inputs", type=Path, default=ROOT / ".build/toolbox-inputs")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/linux-test-assets")
    args = parser.parse_args()
    if not args.gradle and not args.gradle_cache:
        parser.error("provide --gradle, --gradle-cache or both")
    if args.gradle:
        prepare("linux-gradle", launcher_files(args.gradle, args.debian_cache), args.inputs, args.output)
    if args.gradle_cache:
        prepare("linux-gradle-maven", maven_files(args.gradle_cache), args.inputs, args.output)
