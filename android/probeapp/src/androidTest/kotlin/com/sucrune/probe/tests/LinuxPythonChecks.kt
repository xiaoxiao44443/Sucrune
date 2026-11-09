package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

internal fun linuxPythonCases(client: RuntimeClient, project: String, execute: ToolboxExec): List<Pair<String, () -> String>> {
    val cwd = "/workspace"
    fun python(args: List<String>, env: List<String> = emptyList(), timeout: Long = 60_000L): String {
        val result = execute("/usr/bin/python3", listOf("-B") + args, cwd,
            listOf("PYTHONDONTWRITEBYTECODE=1") + env, timeout)
        check(result.optString("state") == "exited" && result.optInt("exit_code", -1) == 0) {
            "python3 ${args.first()} failed (${result.optString("state")}/${result.optInt("exit_code", -1)}): " +
                result.optString("stdout").takeLast(2200) + "\n" + result.optString("stderr").takeLast(2200)
        }
        return result.getString("stdout")
    }
    return listOf(
        "linux_python_socket_nonblocking" to {
            val source = """
                import array, errno, fcntl, os, socket, termios
                with socket.socket() as server, socket.socket() as peer, peer.dup() as alias:
                    assert not (fcntl.fcntl(peer, fcntl.F_GETFL) & os.O_NONBLOCK)
                    fcntl.ioctl(alias, termios.FIONBIO, array.array('i', [1]))
                    assert fcntl.fcntl(peer, fcntl.F_GETFL) & os.O_NONBLOCK
                    server.setblocking(False)
                    server.bind(('127.0.0.1', 0))
                    server.listen(1)
                    assert peer.connect_ex(server.getsockname()) in (0, errno.EINPROGRESS)
                print('tcp-flags-ok')
            """.trimIndent()
            check(python(listOf("-c", source), listOf("SUCRUNE_NETWORK_POLICY=loopback")).trim() == "tcp-flags-ok")
            "Python configured TCP nonblocking mode through an alias and connected to a guest loopback listener."
        },
        "linux_python_script_and_stdlib" to {
            val source = """
                import bz2, gzip, hashlib, json, lzma, os, pathlib, sqlite3, ssl, sys, sysconfig
                assert sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 11, 2)
                assert sys.platform == "linux" and sysconfig.get_config_var("MULTIARCH") == "aarch64-linux-gnu"
                data = pathlib.Path("python-input.json").read_bytes()
                for codec in (bz2, gzip, lzma):
                    assert codec.decompress(codec.compress(data)) == data
                assert len(hashlib.sha256(data).digest()) == 32
                assert ssl.create_default_context().cert_store_stats()["x509_ca"] > 0
                db = sqlite3.connect(":memory:")
                db.execute("create table inputs(value integer)")
                db.executemany("insert into inputs values (?)", [(x,) for x in json.loads(data)])
                total, = db.execute("select sum(value) from inputs").fetchone()
                db.close()
                output = pathlib.Path("python-result.txt")
                output.write_text(f"{total}\n", encoding="utf-8")
                mtime = 1600000000123456789
                os.utime(output, ns=(mtime, mtime))
                assert output.stat().st_mtime_ns == mtime
                print(f"CPython {sys.version.split()[0]} total={total}")
            """.trimIndent()
            client.writeFile(project, "$cwd/python-case.py", source.toByteArray())
            client.writeFile(project, "$cwd/python-input.json", "[2,3,8]".toByteArray())
            check(python(listOf("python-case.py")).trim() == "CPython 3.11.2 total=13")
            check(client.readFile(project, "$cwd/python-result.txt").toString(Charsets.UTF_8) == "13\n")
            "Debian CPython read JSON, round-tripped gzip/bzip2/xz, loaded root CAs and queried SQLite; the manager read its output file."
        },
        "linux_python_subprocess_pipes" to {
            val source = """
                import subprocess, sys, time
                start = time.monotonic()
                time.sleep(0.01)
                assert time.monotonic() - start >= 0.009
                child = subprocess.run(
                    [sys.executable, "-B", "-c", "import sys; print(sys.stdin.read().upper()); print('child-error', file=sys.stderr); sys.exit(7)"],
                    input="piped", text=True, capture_output=True, timeout=15)
                assert (child.returncode, child.stdout, child.stderr) == (7, "PIPED\n", "child-error\n"), child
                print("subprocess-ok")
            """.trimIndent()
            check(python(listOf("-c", source)).trim() == "subprocess-ok")
            "Python launched a second guest CPython, exchanged separate stdin/stdout/stderr streams and received exit code 7."
        },
        "linux_exec_project_owner_permissions" to {
            val source = """
                import errno, os, pathlib, subprocess
                p = pathlib.Path.cwd() / "file-mode-probe"
                p.write_bytes(pathlib.Path("/usr/bin/hello").read_bytes())
                try:
                    p.chmod(0o641)
                    assert p.stat().st_uid == os.geteuid()
                    for direct in (True, False):
                        try:
                            if direct:
                                os.execv(str(p), [str(p)])
                            subprocess.run([str(p)], check=True)
                        except PermissionError as e:
                            assert e.errno == errno.EACCES
                        else:
                            raise AssertionError("execution with other-x bypassed the owner class")
                    p.chmod(0o700)
                    got = subprocess.check_output([str(p), "--greeting=permissions-ok"], text=True)
                    assert got.strip() == "permissions-ok"
                finally:
                    p.unlink()
                print("owner-class-ok")
            """.trimIndent()
            check(python(listOf("-c", source)).trim() == "owner-class-ok")
            "Guest execve and a forked Python child both rejected mode 0641 for the owner; the same ELF ran with mode 0700."
        },
        "linux_python_pip_offline_wheel" to {
            val wheel = "$cwd/sucrune_probe_dep-1.0-py3-none-any.whl"
            val target = "$cwd/python-packages"
            client.writeFile(project, wheel, pythonFixtureWheel())
            python(listOf("-m", "pip", "-vv", "--isolated", "--disable-pip-version-check", "--no-input",
                "install", "--no-index", "--no-cache-dir", "--no-deps", "--no-compile", "--target", target, wheel),
                timeout = 120_000L)
            val imported = python(listOf("-c",
                "import importlib.metadata, sucrune_probe_dep as p; print(importlib.metadata.version('sucrune-probe-dep'), p.add(20, 22))"),
                listOf("PYTHONPATH=$target"))
            check(imported.trim() == "1.0 42")
            "Debian pip installed a local wheel into the project and a separate CPython process imported the installed module."
        }
    )
}

private fun pythonFixtureWheel(): ByteArray {
    val dist = "sucrune_probe_dep-1.0.dist-info"
    val files = linkedMapOf(
        "sucrune_probe_dep.py" to "def add(left, right):\n    return left + right\n",
        "$dist/METADATA" to "Metadata-Version: 2.1\nName: sucrune-probe-dep\nVersion: 1.0\n\n",
        "$dist/WHEEL" to "Wheel-Version: 1.0\nGenerator: sucrune\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    val rows = files.map { (name, content) ->
        val data = content.toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        "$name,sha256=${Base64.getUrlEncoder().withoutPadding().encodeToString(digest)},${data.size}"
    }
    files["$dist/RECORD"] = (rows + "$dist/RECORD,,").joinToString("\n", postfix = "\n")
    val output = ByteArrayOutputStream()
    ZipOutputStream(output).use { archive ->
        for ((name, content) in files) {
            archive.putNextEntry(ZipEntry(name))
            archive.write(content.toByteArray())
            archive.closeEntry()
        }
    }
    return output.toByteArray()
}
