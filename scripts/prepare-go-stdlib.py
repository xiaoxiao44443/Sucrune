"""Build a test-only ARM64 standard library for the separate compile/link probe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from debian_archive import atomic_file


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/usr/local/go-prebuilt/linux_arm64"


def prepare(go, cache, output, profile):
    # Pin the host compiler to the same release as the Linux/ARM64 tools under test.
    version = json.loads(profile.read_text(encoding="utf-8"))["version"]
    cache = cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOOS="linux", GOARCH="arm64", GOARM64="v8.0", CGO_ENABLED="0",
               GOENV="off", GOFLAGS="", GOTOOLCHAIN="local", GOEXPERIMENT="", GO111MODULE="off",
               GOWORK="off", GOCACHE=str(cache), GOPROXY="off", GOSUMDB="off")

    def run(*args):
        return subprocess.check_output([go, *args], cwd=ROOT, env=env, text=True).strip()

    actual = run("env", "GOVERSION")
    if actual != version:
        raise ValueError(f"Both toolchains must be {version}; local compiler is {actual}")
    packages = run("list", "-trimpath", "-export", "-deps", "-f",
                   "{{if .Export}}{{.ImportPath}}={{.Export}}{{end}}", "runtime", "strconv")
    files = []

    def add(path, data):
        digest = hashlib.sha256(data).hexdigest()
        asset = "files/" + digest + ".bin"
        if not (output / asset).is_file() or hashlib.sha256((output / asset).read_bytes()).hexdigest() != digest:
            atomic_file(output / asset, data)
        files.append(dict(path=path, asset=asset, bytes=len(data), mode=0o644, sha256=digest))

    configs = []
    for line in sorted(packages.splitlines()):
        if not line:
            continue
        name, file = line.split("=", 1)
        archive = Path(file).read_bytes()
        signature = f"go object linux arm64 {version} ".encode()
        if not archive.startswith(b"!<arch>\n__.PKGDEF") or signature not in archive[:1024]:
            raise ValueError(f"Archive architecture or release mismatch in {name}")
        dest = f"{PREFIX}/{name}.a"
        add(dest, archive)
        configs.append(f"packagefile {name}={dest}\n")
    if not any(row.startswith("packagefile runtime=") for row in configs):
        raise ValueError("Missing runtime archive")
    add(f"{PREFIX}/importcfg", "".join(configs).encode())
    manifest = dict(schema_version=1, name="linux-go-stdlib", version=version,
                    source="Host-cross-compiled standard library, GOOS=linux GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0",
                    files=sorted(files, key=lambda row: row["path"]))
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(configs)} precompiled standard-library archives, {sum(row['bytes'] for row in files)} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/go-stdlib-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-go-stdlib")
    parser.add_argument("--profile", type=Path, default=ROOT / ".build/toolbox-inputs/linux-go/manifest.json")
    args = parser.parse_args()
    prepare(args.go, args.cache, args.output, args.profile)
