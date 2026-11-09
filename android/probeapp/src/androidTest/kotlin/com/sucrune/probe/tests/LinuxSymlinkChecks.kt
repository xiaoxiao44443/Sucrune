package com.sucrune.probe.tests

internal fun linuxDistroSymlinkCase(execute: ToolboxExec): Pair<String, () -> String> =
    "linux_distro_symlink_resolution" to {
        val source = """
            import errno, os, stat
            root = '/workspace/distro-links'
            os.makedirs(root + '/usr/bin')
            os.chdir(root)
            os.symlink('usr/bin', 'bin')
            os.symlink(root + '/bin/tool', 'chain')
            with open('usr/bin/actual', 'w') as out:
                out.write('inside')
            directory = os.open('bin', os.O_RDONLY | os.O_DIRECTORY)
            os.symlink('../bin/actual', 'tool', dir_fd=directory)
            assert open('chain').read() == 'inside'
            assert stat.S_ISLNK(os.lstat('chain').st_mode)
            assert os.stat('chain').st_ino == os.stat('usr/bin/actual').st_ino
            assert os.readlink('tool', dir_fd=directory) == '../bin/actual'
            symlink_fd = os.open('tool', os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
            assert os.readlink('', dir_fd=symlink_fd) == '../bin/actual'
            os.close(symlink_fd)
            def fails(path, expected, flags=os.O_RDONLY):
                try:
                    os.close(os.open(path, flags))
                except OSError as err:
                    assert err.errno == expected, (path, err)
                else:
                    raise AssertionError(path)
            fails('chain', errno.ELOOP, os.O_NOFOLLOW)
            os.rename('tool','moved',src_dir_fd=directory,dst_dir_fd=directory)
            fails('chain',errno.ENOENT)
            os.symlink(root + '/chain', 'tool', dir_fd=directory)
            fails('chain',errno.ELOOP)
            os.unlink('tool',dir_fd=directory)
            os.symlink('missing','tool',dir_fd=directory)
            with open('chain','w') as out:
                out.write('created-through-dangling')
            assert open('usr/bin/missing').read() == 'created-through-dangling'
            os.symlink('../../../../../outside','escape',dir_fd=directory)
            fails('bin/escape',errno.EPERM)
            os.chdir('bin/..')
            assert os.getcwd() == root + '/usr'
            os.chdir(root)
            os.unlink('bin')
            assert os.readlink('moved', dir_fd=directory) == '../bin/actual'
            assert open('usr/bin/actual').read() == 'inside'
            os.close(directory)
            print('guest-symlink-semantics-ok')
        """.trimIndent()
        val record = execute("/usr/bin/python3", listOf("-B", "-c", source), "/workspace", emptyList(), 30_000)
        check(record.optInt("exit_code", -1) == 0 && record.optString("stdout").trim() == "guest-symlink-semantics-ok") {
            record.optString("stderr").takeLast(1200)
        }
        "Validated relative, absolute, dangling and cyclic links, physical cwd, dirfd operations, no-follow and project containment."
    }
