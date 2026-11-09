package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

internal fun linuxBaseToolCases(
    client: RuntimeClient,
    project: String,
    execute: ToolboxExec
): List<Pair<String, () -> String>> {
    fun output(record: JSONObject): String {
        check(record.optString("state") == "exited" && record.optInt("exit_code", -1) == 0) { record.toString() }
        return record.getString("stdout")
    }

    fun workflow(name: String, commands: String, expected: String, shell: String = "/bin/bash"): Pair<String, () -> String> =
        "base_$name" to {
            val cwd = "/base-$name"
            client.makeDirectory(project, cwd)
            val source = "set -ex\nset -o pipefail\n" + commands.trimIndent() + "\n"
            client.writeFile(project, "$cwd/run.sh", source.toByteArray())
            val result = execute(shell, listOf("run.sh"), cwd, emptyList(), 60_000L)
            val actual = output(result)
            check(actual == expected) { "Expected <$expected> but got <$actual>. " + result.optString("stderr") }
            actual.trimEnd()
        }

    return listOf(
        "base_applet_catalog" to {
            val result = execute("/bin/busybox", listOf("--list"), "/", emptyList(), 30_000L)
            val applets = output(result).lineSequence().toSet()
            check(applets.containsAll(listOf("sh", "awk", "patch", "find", "tar", "sha256sum", "xargs")))
            "Debian ARM64 BusyBox enumerated its compiled applets."
        },
        "base_ps_project_visibility" to {
            val result = execute("/bin/ps", listOf("-o", "pid,comm"), "/", emptyList(), 30_000L)
            val lines = output(result).lineSequence().drop(1).filter(String::isNotBlank).toList()
            val pid = result.getJSONObject("result").getJSONObject("native").getInt("pid")
            val fields = lines.single().trim().split(Regex("\\s+"), limit = 2)
            check(fields.size == 2 && fields[0].toInt() == pid && fields[1].isNotBlank()) {
                "Expected the command's own PID $pid, got $lines"
            }
            "ps listed only the guest PID $pid and its command name."
        },
        "base_pipeline_sibling_group" to {
            // Hold the leader alive using a pipe. Only the second child calls
            // setpgid for itself, so a parent-side Bash call cannot hide a denial.
            val source = """
                import errno, os
                ready, announce = os.pipe()
                hold, release = os.pipe()
                leader = os.fork()
                if leader == 0:
                    os.close(ready)
                    os.close(release)
                    os.setpgid(0, 0)
                    os.write(announce, b'R')
                    os._exit(0 if os.read(hold, 1) == b'X' else 19)
                os.close(announce)
                os.close(hold)
                assert os.read(ready, 1) == b'R'
                parent_sid = os.getsid(0)
                leader_sid = os.getsid(leader)
                leader_group = os.getpgid(leader)
                assert leader_group == leader and leader_sid == parent_sid
                member = os.fork()
                if member == 0:
                    try:
                        os.setpgid(0, 1)
                    except OSError as err:
                        if err.errno != errno.EPERM:
                            os._exit(20)
                    else:
                        os._exit(21)
                    try:
                        os.setpgid(0, leader)
                    except OSError:
                        print('parent_sid=%d leader=%d leader_sid=%d leader_group=%d self=%d self_sid=%d self_group=%d' %
                              (parent_sid, leader, leader_sid, leader_group, os.getpid(), os.getsid(0), os.getpgid(0)),
                              flush=True)
                        raise
                    os._exit(0 if os.getpgid(0) == leader else 22)
                child_status = os.waitpid(member, 0)[1]
                os.write(release, b'X')
                leader_result = os.waitpid(leader, 0)
                assert child_status == 0 and leader_result == (leader, 0), (child_status, leader_result)
                print('owned-sibling-group sid=%d' % parent_sid)
            """.trimIndent()
            val result = execute("/usr/bin/python3", listOf("-B", "-c", source), "/workspace", emptyList(), 30_000L)
            val actual = output(result).trimEnd()
            check(actual.matches(Regex("owned-sibling-group sid=[0-9]+"))) { result.toString() }
            "$actual. The second child joined its live sibling's group and rejected an unrelated PGID."
        },
        workflow("ash_script", """
            mkdir text
            printf 'alpha\nbeta\n' > text/input
            chmod 600 text/input
            awk '{print toupper($1)}' text/input | sort
            awk '{print ($1 > 0 ? "guest-proc" : "invalid")}' /proc/self/stat
        """, "ALPHA\nBETA\nguest-proc\n", shell = "/bin/ash"),
        workflow("text_pipeline", """
            printf 'item pear\nskip\nitem apple\nitem pear\n' > items
            grep '^item ' items | sed 's/^item //' | awk '{print toupper($1)}' | sort | uniq | tee report
            cmp report report
            head -n 1 report | tr A-Z a-z
            tail -n 1 report | cut -c1-2
            wc -l < report | awk '{print $1}'
        """, "APPLE\nPEAR\napple\nPE\n2\n"),
        workflow("file_workflow", """
            mkdir -p nested/src empty
            printf 'alpha\n' > nested/src/a.txt
            cp nested/src/a.txt tmp
            mv tmp nested/src/b.txt
            touch marker
            test -f marker
            find nested -type f -name '*.txt' | sort | xargs -n 1 basename
            dirname nested/src/b.txt
            ls -1 nested/src | sort
            rm nested/src/b.txt
            rmdir empty
            /bin/pwd
        """, "a.txt\nb.txt\nnested/src\na.txt\nb.txt\n/base-file_workflow\n"),
        workflow("archives", """
            mkdir src restored
            printf 'a file with spaces\n' > 'src/a b.txt'
            tar -cf tree.tar src
            gzip -c tree.tar > tree.tgz
            gunzip -c tree.tgz > restored.tar
            tar -xf restored.tar -C restored
            cmp 'src/a b.txt' 'restored/src/a b.txt'
            gzip -c 'src/a b.txt' > plain.gz
            gunzip -c plain.gz
            zcat plain.gz | cmp - 'src/a b.txt'
            sha256sum 'src/a b.txt' > checksums
            sha256sum -c checksums
        """, "a file with spaces\nsrc/a b.txt: OK\n"),
        workflow("patch", """
            printf 'before\n' > original
            printf 'after\n' > desired
            if diff -u original desired > change; then exit 1; else test "$?" = 1; fi
            patch original < change > patch.log
            cmp original desired
            cat original
        """, "after\n"),
        workflow("links_and_modes", """
            printf 'same\n' > one
            chmod 640 one
            stat -c '%a' one
            ln one two
            printf 'inode\n' >> two
            cat one
            unlink two
            [ -f one ]
            [ ! -e two ]
            realpath ./one
        """, "640\nsame\ninode\n/base-links_and_modes/one\n"),
        workflow("columns", """
            seq 3 > nums
            tac nums | paste -sd, -
            printf 'abc\n' | rev
            printf 'X\tY\n' | expand -t 2
            printf 'abcdef\n' | fold -w 3
            printf 'first\r\nsecond\r\n' > dos
            dos2unix < dos
            printf 'A\nB\n' | nl | awk '{print $1 $2}'
            /usr/bin/printf '%04d\n' 23
            /usr/bin/expr 3 + 5
        """, "3,2,1\ncba\nX Y\nabc\ndef\nfirst\nsecond\n1A\n2B\n0023\n8\n"),
        workflow("bytes_and_digests", """
            printf abc > raw
            base64 raw > encoded
            cat encoded
            base64 -d encoded | cmp - raw
            xxd -p raw
            hexdump -v -e '3/1 "%02x"' raw; /bin/echo
            od -An -tu1 raw | awk '{print $1, $2, $3}'
            md5sum raw | cut -d ' ' -f 1
            for h in sha1sum sha256sum sha512sum; do "${'$'}h" raw > digest; "${'$'}h" -c digest; done
            dd if=raw of=slice bs=1 count=2 2> dd.log
            truncate -s 1 slice
            cat slice; /bin/echo
        """, "YWJj\n616263\n616263\n97 98 99\n900150983cd24fb0d6963f7d28e17f72\nraw: OK\nraw: OK\nraw: OK\na\n"),
        workflow("process_and_clock", """
            /bin/true
            if /bin/false; then exit 1; fi
            /usr/bin/test -r /bin/sh
            /usr/bin/env SUCRUNE_TOOL_MARK=from-env /bin/sh -c 'printf "%s\n" "${'$'}SUCRUNE_TOOL_MARK"'
            which jq
            test "$(id -u)" -gt 0
            test "$(date -u +%s)" -gt 0
            test "$(uname -m)" = aarch64
            sleep 0.01
            kill -0 "$$"
            awk '{print ($1 > 0 ? "guest-proc" : "invalid")}' /proc/self/stat
        """, "from-env\n/usr/bin/jq\nguest-proc\n"),
        workflow("additional_archives", """
            printf 'alternate codecs\n' > raw
            bzip2 -c raw > raw.bz2
            bzcat raw.bz2 | cmp - raw
            bunzip2 -c raw.bz2 | cmp - raw
            # The pinned BusyBox build decodes xz. The fixture is lzma.compress(b"alternate codecs\n").
            printf '%s\n' '/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAQYWx0ZXJuYXRlIGNvZGVjcwoAAAAA0MGkk/bAz6QAASkRMgpwDh+2830BAAAAAARZWg==' > raw.b64
            base64 -d raw.b64 > raw.xz
            xzcat raw.xz > decoded
            cmp decoded raw
            unxz -c raw.xz | cmp - raw
            xz -dc raw.xz | cmp - raw
            cat decoded
        """, "alternate codecs\n"),
        workflow("read_archives", """
            printf '%s\n' 'UEsDBBQAAAAIAAAAISgEM3WREAAAAA4AAAAIAAAAdGV4dC50eHSryizQLcovzUspKcos4AIAUEsBAhQAFAAAAAgAAAAhKAQzdZEQAAAADgAAAAgAAAAAAAAAAAAAAIABAAAAAHRleHQudHh0UEsFBgAAAAABAAEANgAAADYAAAAAAA==' | base64 -d > fixture.zip
            unzip -p fixture.zip text.txt
            printf '%s\n' 'ITxhcmNoPgp0ZXh0LnR4dC8gICAgICAgMCAgICAgICAgICAgMCAgICAgMCAgICAgMTAwNjQ0ICAxMyAgICAgICAgYAphci1yb3VuZHRyaXAKCg==' | base64 -d > fixture.a
            ar t fixture.a
            ar p fixture.a text.txt
        """, "zip-roundtrip\ntext.txt\nar-roundtrip\n"),
        workflow("shell_utilities", """
            /bin/ash -c 'printf "ash\n"'
            name=$(mktemp artifact.XXXXXX)
            test -f "${'$'}name"
            printf 'short\n' > "${'$'}name"
            less < "${'$'}name"
            readlink -f ./run.sh
            printf '\001binary-marker\000' | strings
            du -k . | tail -1 | awk '$1 > 0 { print "disk-usage" }' > usage
            grep -Fx disk-usage usage
            getopt -o a: -- -a 7 | grep -q -- '-a'
            TERM=xterm clear > terminal
            test -s terminal
            if tty -s; then exit 1; fi
            set +o pipefail
            yes answer | head -n 1 > first
            set -o pipefail
            cat first
        """, "ash\nshort\n/base-shell_utilities/run.sh\nbinary-marker\ndisk-usage\nanswer\n"),
        workflow("ripgrep", """
            mkdir -p src ignored
            printf 'first\nneedle\n' > src/input.txt
            printf 'needle\n' > ignored/artifact.txt
            printf 'ignored/\n' > .ignore
            rg --threads 1 --color never --no-heading -n -g '*.txt' needle . | sed 's|^\./||'
        """, "src/input.txt:2:needle\n"),
        workflow("jq", """
            printf '%s\n' '{"items":[{"id":2,"name":"pear"},{"id":1,"name":"apple"}]}' > items.json
            jq -r '.items | sort_by(.id)[] | select(.name | test("^[ap]")) | .name' items.json
        """, "apple\npear\n")
    )
}
