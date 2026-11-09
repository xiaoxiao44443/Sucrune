"""Prepare Debian ARM64 Git, its HTTP transport and curl for a Sucrune project."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import posixpath
import re

from debian_archive import atomic_file, elf_deps, fetch, payload


ROOT = Path(__file__).resolve().parents[1]
LOCK = Path(__file__).with_name("git-curl-packages.json")


def path_in_tar(name):
    return "/" + name.removeprefix("./").lstrip("/")


def build(packages, paths, output):
    files = {}
    libraries = {}
    commands = {}
    certs = {}
    documentation = {}
    aliases = {}
    for package, archive_path in zip(packages, paths):
        owner = package["package"]
        with payload(archive_path) as tar:
            for member in tar:
                name = path_in_tar(member.name)
                if member.issym() or member.islnk():
                    base = posixpath.dirname(name) if member.issym() else "/"
                    aliases[name] = posixpath.normpath(posixpath.join(base,member.linkname))
                    continue
                if not member.isfile():
                    continue
                lib = re.fullmatch(r"/(?:usr/)?lib/aarch64-linux-gnu/([^/]+\.so(?:\.[A-Za-z0-9_.-]+)?)", name)
                selected = (owner == "git" and (name.startswith("/usr/lib/git-core/") or
                            name.startswith("/usr/bin/git") or name.startswith("/usr/share/git-core/templates/")))
                selected = selected or (owner == "curl" and name == "/usr/bin/curl")
                license_file = (name == f"/usr/share/doc/{owner}/copyright" or
                                name.startswith("/usr/share/common-licenses/"))
                ca = owner == "ca-certificates" and name.startswith("/usr/share/ca-certificates/mozilla/") and name.endswith(".crt")
                if not (lib or selected or license_file or ca):
                    continue
                data = tar.extractfile(member).read()
                entry = (owner, name, data, member.mode & 0o777)
                if lib and data.startswith(b"\x7fELF"):
                    soname, needs = elf_deps(data)
                    if soname:
                        if soname in libraries and libraries[soname][0][2] != data:
                            raise ValueError("Conflicting SONAME " + soname)
                        libraries[soname] = (entry, needs)
                elif selected:
                    commands[name] = entry
                elif ca:
                    certs[name] = data
                elif license_file:
                    documentation[name] = entry

    def publish(guest, entry):
        if (not guest.startswith("/") or "\\" in guest or ".." in guest.split("/") or
                entry[3] & ~0o777 or guest in files):
            raise ValueError("Invalid or repeated target " + guest)
        owner, member, data, mode = entry
        artifact = "files" + guest
        atomic_file(output / artifact, data)
        files[guest] = dict(path=guest, asset=artifact, bytes=len(data), mode=mode,
                            sha256=hashlib.sha256(data).hexdigest(), package=owner, member=member)

    def resolve(name):
        for _ in range(8):
            if name not in aliases:
                return name
            name = aliases[name]
        raise ValueError("Package link cycle")

    required = set()
    for guest in ("/usr/bin/git","/usr/bin/curl","/usr/bin/git-upload-pack","/usr/bin/git-receive-pack",
                  "/usr/bin/git-upload-archive","/usr/lib/git-core/git-remote-http","/usr/lib/git-core/git-remote-https"):
        entry = commands[resolve(guest)]
        required.update(elf_deps(entry[2])[1])
        publish(guest, entry)
    for name, entry in commands.items():
        if name.startswith("/usr/share/git-core/templates/"):
            publish(name, entry)
    # The rootfs owns these exact glibc, libgcc and libstdc++ ABI names.
    provided = {"ld-linux-aarch64.so.1","libc.so.6","libdl.so.2","libpthread.so.0","libm.so.6",
                "libgcc_s.so.1","libstdc++.so.6"}
    while required - provided:
        name = min(required - provided)
        if name not in libraries:
            raise ValueError("Missing ARM64 library " + name)
        entry, needs = libraries[name]
        publish("/usr/lib/aarch64-linux-gnu/" + name, entry)
        required.update(needs)
        provided.add(name)
    if len(certs) < 100 or any(not data.startswith(b"-----BEGIN CERTIFICATE-----")
                               for data in certs.values()):
        raise ValueError("Missing Debian Mozilla certificates")
    ca_derivation = "sorted concatenation of /usr/share/ca-certificates/mozilla/*.crt"
    bundle = b"".join(certs[name].rstrip()+b"\n" for name in sorted(certs))
    for guest in ("/etc/ssl/certs/ca-certificates.crt", "/usr/lib/ssl/cert.pem"):
        publish(guest, ("ca-certificates", ca_derivation, bundle, 0o644))
    for name in sorted(documentation):
        publish(name, documentation[name])
    manifest = dict(schema_version=1, name="debian-bookworm-arm64-git-curl",
                    packages=packages, ca_count=len(certs),
                    files=[files[name] for name in sorted(files)])
    atomic_file(output / "manifest.json", (json.dumps(manifest,indent=2)+"\n").encode("utf-8"))
    print(f"Prepared {len(files)} files, {len(certs)} CA certificates")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-git-curl")
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args()


def main():
    args = arguments()
    packages = json.loads(LOCK.read_text(encoding="utf-8"))["packages"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        paths = list(pool.map(lambda row: fetch(row, args.cache, args.offline), packages))
    if args.fetch_only:
        print(f"Verified {len(paths)} Debian packages")
        return
    build(packages, paths, args.output)


if __name__ == "__main__":
    main()
