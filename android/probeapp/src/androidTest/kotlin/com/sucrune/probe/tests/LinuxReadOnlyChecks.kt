package com.sucrune.probe.tests

internal fun linuxReadOnlyFileCase(execute: ToolboxExec, expectDirectRead: Boolean): Pair<String, () -> String> =
    "linux_distro_readonly_file_io" to {
        // Use identical interpreter startup and data for both modes. The O_RDWR control
        // should still go through the broker. The second run changes only the test FD.
        val source = """
            import ctypes, errno, os, sys
            name = 'readonly-io.bin'
            data = bytes(range(256)) * 256
            with open(name, 'xb') as writer:
                writer.write(data)
            os.symlink(name, name + '.link')
            fd = os.open(name + '.link', os.O_RDONLY)
            rw = os.open(name, os.O_RDWR)
            alias = os.dup(fd)
            os.rename(name, name + '.old')
            os.unlink(name + '.old')
            with open(name, 'xb') as replacement:
                replacement.write(b'new')
            with open(name + '.link', 'rb') as replacement:
                assert replacement.read() == b'new'
            os.unlink(name + '.link')
            os.unlink(name)
            assert os.read(fd, 2) == data[:2]
            a, b = bytearray(2), bytearray(3)
            assert os.readv(alias, [a, b]) == 5 and a + b == data[2:7]
            assert os.pread(fd, 65536, len(data)-3) == data[-3:]
            assert os.pread(alias, 1, len(data)) == b''
            assert os.lseek(fd, 0, os.SEEK_CUR) == 7
            syscall = ctypes.CDLL(None, use_errno=True).syscall
            syscall.restype = ctypes.c_long
            # Python validates buffer arguments, so invoke the Linux arm64 ABI
            # directly for the zero-length and competing-fault cases.
            bad = ctypes.c_void_p(-1)
            assert syscall(63, fd, bad, ctypes.c_size_t(0)) == 0
            assert syscall(67, fd, bad, ctypes.c_size_t(0), ctypes.c_long(0)) == 0
            for count, expected in ((1, errno.EFAULT), (4097, errno.EINVAL)):
                ctypes.set_errno(0)
                assert syscall(67, fd, bad, ctypes.c_size_t(count), ctypes.c_long(-1)) == -1
                assert ctypes.get_errno() == expected
            assert os.lseek(alias, 0, os.SEEK_CUR) == 7
            child = os.fork()
            if child == 0:
                os._exit(0 if os.read(alias, 2) == data[7:9] else 47)
            assert os.waitpid(child, 0) == (child, 0)
            os.close(fd)
            # Force guest slot reuse while an alias to the original description is live.
            os.dup2(rw, fd)
            assert os.read(fd, 2) == data[:2] and os.read(alias, 1) == data[9:10]
            assert os.lseek(alias, 0, os.SEEK_CUR) == 10
            try:
                os.write(alias, b'x')
            except OSError as err:
                assert err.errno == errno.EBADF
            else:
                raise AssertionError('write accepted on read-only alias')
            read_fd = alias if sys.argv[1] == 'readonly' else rw
            for i in range(64):
                if i % 2:
                    assert os.lseek(read_fd, 0, os.SEEK_SET) == 0
                    assert os.read(read_fd, len(data)) == data
                else:
                    assert os.pread(read_fd, len(data), 0) == data
            assert os.pwrite(rw, b'z', 0) == 1 and os.pread(alias, 1, 0) == b'z'
            os.ftruncate(rw, 1)
            assert os.pread(alias, 8, 0) == b'z'
            for handle in (fd, rw, alias):
                os.close(handle)
            print('readonly-io-ok')
        """.trimIndent()
        fun run(mode: String): Triple<Long, Long, Long> {
            val record = execute("/usr/bin/python3", listOf("-I", "-S", "-B", "-c", source, mode),
                "/workspace", emptyList(), 30_000)
            check(record.optInt("exit_code", -1) == 0 && record.optString("stdout").trim() == "readonly-io-ok") {
                "$mode failed: " + record.optString("stderr").takeLast(1400)
            }
            val report = record.getJSONObject("result").getJSONObject("native")
            return Triple(report.getLong("direct_read_calls"), report.getLong("direct_read_bytes"),
                report.getLong("guest_direct_read_bytes"))
        }
        val (controlCalls, controlBytes, controlGuestBytes) = run("readwrite")
        val (readCalls, readBytes, readGuestBytes) = run("readonly")
        if (expectDirectRead) {
            // The test file contributes 64 extra reads totaling 4 MiB when both read
            // paths use the grant. Allow minor differences in the interpreter's own I/O.
            check(readCalls - controlCalls >= 48 && readGuestBytes - controlGuestBytes >= 3L * 1024 * 1024) {
                "Missing direct guest file reads: readonly $readCalls calls/$readGuestBytes guest bytes, " +
                    "readwrite control $controlCalls calls/$controlGuestBytes guest bytes"
            }
        }
        "Shared offsets, readv, pread, fork, dup2 reuse, unlinked inode and writable access passed. " +
            "Native direct reads (calls/bytes/guest bytes): readonly $readCalls/$readBytes/$readGuestBytes, " +
            "readwrite control $controlCalls/$controlBytes/$controlGuestBytes."
    }
