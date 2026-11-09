package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONArray
import java.security.MessageDigest

internal fun linuxShebangCases(client: RuntimeClient, project: String, execute: ToolboxExec): List<Pair<String, () -> String>> {
    val cwd = "/workspace/shebang"
    fun script(name: String, source: String, executable: Boolean = true) {
        val bytes = source.toByteArray()
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        client.importFile(project, "$cwd/$name", bytes.inputStream(), bytes.size.toLong(), sha, executable)
    }
    fun run(path: String, args: List<String>): List<String> {
        val record = execute(path, args, cwd, listOf("PYTHONDONTWRITEBYTECODE=1", "MARK=shebang"), 45_000)
        check(record.optInt("exit_code", -1) == 0) {
            "$path: ${record.optString("stderr").takeLast(1000)} ${record.optString("stdout").takeLast(500)}"
        }
        return record.getString("stdout").trimEnd().lines()
    }
    fun prepare() {
        client.makeDirectory(project, cwd)
        script("argv.py", "#!/usr/bin/python3\nimport json, os, sys\n" +
            "print(json.dumps(sys.argv)); print(os.getcwd()); print(os.environ['MARK']); print(os.readlink('/proc/self/exe'))\n")
        script("entry", "#! \t./argv.py\talpha  beta\tgamma  \t\n")
    }
    fun checkOutput(lines: List<String>, expected: List<String>) {
        check(lines.size == 4) { lines.toString() }
        val args = JSONArray(lines[0])
        check((0 until args.length()).map(args::getString) == expected &&
            lines.drop(1) == listOf(cwd, "shebang", "/usr/bin/python3")) { lines.toString() }
    }
    return listOf(
        "linux_guest_exec_long_strings" to {
            client.makeDirectory(project, cwd)
            val code = """
                import os, sys
                # Construct the large values inside the guest, as a shell or Node child_process.spawn does.
                script = "import os; assert os.environ['MARK'] == 'env-' * 2048; print('long exec ok')" + "\n#" + 'x' * 45000
                def replace():
                    os.execve(sys.executable, [sys.executable, '-c', script], {'MARK': 'env-' * 2048})
            """.trimIndent()
            check(run("/usr/bin/python3", listOf("-c", code + "\nreplace()")) == listOf("long exec ok"))
            val fork = "\npid=os.fork()\nif pid==0: replace()\nassert os.waitpid(pid,0)[1]==0"
            check(run("/usr/bin/python3", listOf("-c", code + fork)) == listOf("long exec ok"))
            "Both exec paths preserved a 45 KiB script argument and an 8 KiB environment value."
        },
        "linux_guest_exec_compiler_argument_vector" to {
            client.makeDirectory(project, cwd)
            script("args.py", "#!/usr/bin/python3\nimport sys\n" +
                "assert sys.argv[1:] == [str(i) for i in range(300)]\nprint('300 ordered arguments')\n")
            val code = """
                import errno, os
                def replace():
                    for argv, env in [(['arg']*1025, os.environ), (['arg'], {'E'+str(i):'v' for i in range(65)}),
                                      (['x'*1024]*70, os.environ)]:
                        try: os.execve('./args.py', argv, env)
                        except OSError as exc: assert exc.errno == errno.E2BIG, exc
                        else: raise AssertionError('expected E2BIG')
                    os.execve('./args.py', ['ignored'] + [str(i) for i in range(300)], os.environ)
            """.trimIndent()
            val expected = listOf("300 ordered arguments")
            check(run("/usr/bin/python3", listOf("-c", code + "\nreplace()")) == expected)
            val fork = "\npid=os.fork()\nif pid==0: replace()\nassert os.waitpid(pid,0)[1]==0"
            check(run("/usr/bin/python3", listOf("-c", code + fork)) == expected)
            "Both in-place and fork-child execve preserved 300 ordered arguments and rejected argv, env and text overflows."
        },
        "linux_shebang_direct_and_env" to {
            prepare()
            checkOutput(run("$cwd/entry", listOf("one two", "")),
                listOf("./argv.py", "alpha  beta\tgamma", "$cwd/entry", "one two", ""))
            script("env-script", "#!/usr/bin/env python3\nimport sys\nprint(sys.argv[1])\n")
            check(run("$cwd/env-script", listOf("env-interpreter-ok")) == listOf("env-interpreter-ok"))
            "Direct script entry used the project cwd, a relative script interpreter, one opaque argument, and env PATH lookup."
        },
        "linux_shebang_exec_and_fork_errors" to {
            prepare()
            script("cycle", "#!./cycle\n")
            script("missing", "#!/missing-interpreter\n")
            script("empty", "#! \t \n")
            script("long", "#!" + "x".repeat(270) + "\n")
            script("no-permission", "#!/bin/bash\n", executable = false)
            val code = """
                import errno, os
                def replace():
                    for path, error in [('cycle',errno.ELOOP),('missing',errno.ENOENT),('empty',errno.ENOEXEC),('long',errno.ENOEXEC),('no-permission',errno.EACCES)]:
                        try: os.execve('./'+path, ['unused'], os.environ)
                        except OSError as exc: assert exc.errno == error, (path, exc)
                        else: raise AssertionError(path)
                    os.execve('./entry', ['invented-argv-zero','tail',''], os.environ)
            """.trimIndent()
            val expected = listOf("./argv.py", "alpha  beta\tgamma", "./entry", "tail", "")
            checkOutput(run("/usr/bin/python3", listOf("-c", code + "\nreplace()")), expected)
            val fork = "\npid=os.fork()\nif pid==0: replace()\nstatus=os.waitpid(pid,0)[1]\nassert status==0,status"
            checkOutput(run("/usr/bin/python3", listOf("-c", code + fork)), expected)
            "In-place and post-fork execve discarded the supplied argv[0], preserved the tail, and kept running after five distinct preflight errors."
        }
    )
}
