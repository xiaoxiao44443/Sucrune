package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

/** The HTTP protocol (h2/h1) and the Git wire protocol (v0/v1/v2) negotiate independently. */
private fun uploadPackAdvertisement(data: ByteArray): String {
    var offset = 0
    fun nextPacket(): String? {
        check(data.size - offset >= 4) { "Truncated pkt-line header at byte $offset" }
        var size = 0
        repeat(4) {
            val digit = data[offset++].toInt().toChar().digitToIntOrNull(16)
            check(digit != null) { "Invalid pkt-line length at byte ${offset - 1}" }
            size = size * 16 + digit
        }
        if (size == 0) return null // flush-pkt
        check(size in 4..65520 && size - 4 <= data.size - offset) { "Invalid advertisement pkt-line length at byte ${offset - 4}" }
        val payload = String(data, offset, size - 4, Charsets.ISO_8859_1)
        offset += size - 4
        return payload.removeSuffix("\n")
    }
    var packet = nextPacket()
    val service = packet == "# service=git-upload-pack"
    if (service) {
        check(nextPacket() == null) { "Missing flush after Git HTTP service announcement" }
        packet = nextPacket()
    }
    val version = when (packet) { "version 2" -> 2; "version 1" -> 1; else -> 0 }
    check(service || version == 2) { "Missing Git smart-HTTP service announcement" }
    if (version > 0) packet = nextPacket()
    val objectId = Regex("(?:[a-f0-9]{40}|[a-f0-9]{64})")
    val capability = Regex("[A-Za-z0-9_-]+")
    var count = 0
    while (packet != null) {
        if (version == 2) {
            check(capability.matches(packet.substringBefore('='))) { "Malformed v2 capability at packet $count" }
        } else if (packet.startsWith("shallow ")) {
            check(count > 0 && objectId.matches(packet.substringAfter(' '))) { "Malformed shallow object at packet $count" }
        } else {
            check(count != 0 || packet.contains('\u0000')) { "Missing advertised capabilities on the first Git ref" }
            val record = packet.substringBefore('\u0000')
            check(objectId.matches(record.substringBefore(' ')) && record.contains(' ') && record.substringAfter(' ').isNotEmpty()) {
                "Malformed Git ref advertisement at packet $count"
            }
        }
        count++
        packet = nextPacket()
    }
    check(offset == data.size && (count > 0 || version == 2)) { "Incomplete or trailing Git advertisement data" }
    return "Git protocol v$version, service announcement=$service, $count advertisement packets"
}

internal fun linuxGitCurlCases(
    client: RuntimeClient,
    project: String,
    execute: ToolboxExec,
    traceGitHttps: Boolean = false,
    includeComparisons: Boolean = false
): List<Pair<String, () -> String>> {
    val workspace = "/workspace"
    val repo = "$workspace/git-source"
    val checkout = "$workspace/git-checkout"
    val sha1 = Regex("[0-9a-f]{40}")
    val gitEnv = listOf("GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat")
    val network = listOf("SUCRUNE_NETWORK_POLICY=outbound")
    // This case always targets a public repository in a fresh test project.
    // Keep payloads, cookies and unrelated headers out of its diagnostic output.
    val trace = listOf("GIT_TRACE_CURL=1", "GIT_TRACE_CURL_NO_DATA=1", "GIT_TRACE_REDACT=1")
    fun gitTransport(stderr: String): String {
        val markers = listOf("Trying ", "Connected to ", "has been found in DNS", "Could not resolve",
            "Establish HTTP proxy", "CONNECT tunnel", "ALPN", "SSL connection", "certificate verification",
            "Send header: GET ", "Send header: POST ", "Recv header: HTTP/", "> GET ", "< HTTP/", "Operation too slow")
        return stderr.lineSequence().filter { line -> markers.any { line.contains(it, ignoreCase = true) } }
            .map { it.substringAfter("http.c:").trim().take(220) }.distinct().take(32).joinToString("\n")
    }

    fun run(path: String, args: List<String>, cwd: String, env: List<String>, timeout: Long): JSONObject {
        val result = execute(path, args, cwd, env, timeout)
        check(result.getString("state") == "exited" && result.optInt("exit_code", -1) == 0) {
            val native = result.optJSONObject("result")?.optJSONObject("native")
            "$path ${args.firstOrNull()} in $cwd, state=${result.optString("state")} " +
                "exit=${result.optInt("exit_code", -1)} stage=${native?.optString("stage")} " +
                if ("GIT_TRACE_CURL=1" in env) "transport=\n" + gitTransport(result.optString("stderr")) +
                    "\n" + result.optString("stderr").lineSequence().lastOrNull { it.startsWith("fatal:") }.orEmpty()
                else "stderr=${result.optString("stderr").takeLast(1200)}"
        }
        return result
    }
    fun git(cwd: String, vararg args: String): String =
        run("/usr/bin/git", args.toList(), cwd, gitEnv, 30_000).getString("stdout").trimEnd()
    val remote = "https://github.com/proot-me/proot.git"
    fun remoteHead(http11: Boolean): String {
        val options = listOf("-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=18") +
            if (http11) listOf("-c", "http.version=HTTP/1.1") else emptyList()
        val diagnostics = traceGitHttps || http11
        val result = run("/usr/bin/git", options + listOf("ls-remote", remote, "HEAD"), workspace,
            gitEnv + network + (if (diagnostics) trace else emptyList()), 40_000)
        val fields = result.getString("stdout").trim().split('\t')
        check(fields.size == 2 && sha1.matches(fields[0]) && fields[1] == "HEAD") { "Unexpected ls-remote HEAD response" }
        return "git-remote-https retrieved the upstream PRoot HEAD" +
            if (diagnostics) "\n" + gitTransport(result.getString("stderr")) else ""
    }

    return listOf(
        "linux_toolbox_null_device" to {
            val script = """
                set -e
                test -c /dev/null && test -r /dev/null && test -w /dev/null || exit 1
                test -c /dev/urandom
                dd if=/dev/urandom of="$workspace/toolbox-random.bin" bs=32 count=1 2>/dev/null
                exec 3<>/dev/null
                (printf discarded >&3)
                /bin/sh -c 'printf discarded >&3 && cat <&3'
                exec 3>&-
                printf 'null-device-ok\n'
            """.trimIndent()
            val result = run("/bin/sh", listOf("-c", script), workspace, emptyList(), 25_000)
            check(result.getString("stdout") == "null-device-ok\n" && result.getString("stderr").isEmpty()) {
                result.toString()
            }
            val random = client.readFile(project, "$workspace/toolbox-random.bin")
            check(random.size == 32 && random.any { it.toInt() != 0 })
            "character-device metadata, random bytes, EOF, discarded writes and descriptor inheritance verified"
        },
        "linux_toolbox_git_worktree" to {
            val version = git(workspace, "--version")
            check(version.startsWith("git version 2."))
            client.makeDirectory(project, repo)
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Sucrune Probe")
            git(repo, "config", "user.email", "sucrune-probe@example.invalid")
            val content = "tracked by guest Git\n"
            client.writeFile(project, "$repo/note.txt", content.toByteArray())
            check(git(repo, "status", "--porcelain=v1") == "?? note.txt")
            git(repo, "add", "note.txt")
            check(git(repo, "status", "--porcelain=v1") == "A  note.txt")
            git(repo, "commit", "-m", "first project commit")
            val head = git(repo, "rev-parse", "--verify", "HEAD")
            check(sha1.matches(head) && git(repo, "status", "--porcelain=v1").isEmpty())
            git(repo, "switch", "-c", "test-branch")
            check(git(repo, "branch", "--show-current") == "test-branch")
            client.writeFile(project, "$repo/note.txt", "edited by agent\n".toByteArray())
            check(git(repo, "diff", "--", "note.txt").contains("+edited by agent"))
            git(repo, "restore", "--", "note.txt")
            check(client.readFile(project, "$repo/note.txt").decodeToString() == content)
            git(workspace, "clone", "--local", repo, checkout)
            check(git(checkout, "rev-parse", "--verify", "HEAD") == head)
            check(git(checkout, "show", "HEAD:note.txt") == content.trimEnd())
            check(client.readFile(project, "$checkout/note.txt").decodeToString() == content)
            "$version init/status/add/commit/switch/diff/restore/clone verified"
        },
        "linux_toolbox_curl_https" to {
            val version = run("/usr/bin/curl", listOf("--version"), workspace, emptyList(), 15_000).getString("stdout")
            check(version.startsWith("curl ") && version.contains("OpenSSL/") && version.contains("https"))
            val output = "$workspace/curl-example.html"
            val response = run("/usr/bin/curl", listOf(
                "--silent", "--show-error", "--fail", "--connect-timeout", "12", "--max-time", "25",
                "--output", output, "--write-out", "%{http_code} %{ssl_verify_result}", "https://example.com/"
            ), workspace, network, 32_000)
            check(response.getString("stdout") == "200 0") { response.toString() }
            check(client.readFile(project, output).decodeToString().contains("Example Domain"))
            "curl HTTPS response body, HTTP 200 and certificate verification checked"
        },
        "linux_toolbox_git_https" to { remoteHead(false) }
    ) + if (includeComparisons) listOf(
        "linux_compare_git_http11" to { remoteHead(true) },
        "linux_compare_curl_git_http2" to {
            val output = "$workspace/git-advertisement.bin"
            val result = execute("/usr/bin/curl", listOf("--http2", "--verbose", "--silent", "--show-error", "--fail",
                "--user-agent", "git/2.39.5", "--header", "Git-Protocol: version=2", "--speed-limit", "1", "--speed-time", "18",
                "--max-time", "35", "--output", output, "--write-out", "%{http_version} %{http_code} %{ssl_verify_result} %{content_type}",
                "$remote/info/refs?service=git-upload-pack"), workspace, network, 40_000)
            val outcome = result.getString("stdout").trim()
            val transport = gitTransport(result.getString("stderr"))
            check(result.optInt("exit_code", -1) == 0 && outcome == "2 200 0 application/x-git-upload-pack-advertisement") {
                "curl exit=${result.optInt("exit_code", -1)}, protocol/status/verify/type=$outcome\n$transport"
            }
            val description = uploadPackAdvertisement(client.readFile(project, output))
            "Standalone curl fetched and decoded the advertisement over HTTP/2 ($description).\n$transport"
        }
    ) else emptyList()
}
