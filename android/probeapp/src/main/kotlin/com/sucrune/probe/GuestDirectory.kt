package com.sucrune.probe

import android.os.ParcelFileDescriptor

/** Host-owned storage mounted at /workspace for one Linux execution and its descendants.
 * Paths are slash-separated relative names; the empty string represents the root.
 * Implementations validate paths and signal Linux errors with android.system.ErrnoException.
 * open transfers ownership of a seekable regular file descriptor to the runtime.
 */
interface GuestDirectory {
    /** Linux mode, size, mtime in milliseconds, optionally followed by stable device and inode IDs. */
    fun stat(path: String): LongArray
    fun list(path: String): Array<String>
    fun open(path: String, flags: Int, mode: Int): ParcelFileDescriptor
    fun mkdir(path: String)
    fun remove(path: String, directory: Boolean)
    fun rename(source: String, target: String, flags: Int)
}

/** An embedding-app grant to expose a directory from one Sucrune environment at a guest path.
 * Both paths are canonical absolute guest paths. The manager resolves the environment's
 * storage root from its catalog; guest environment variables cannot request a bind. */
data class GuestDirectoryBind(val sourceEnvironmentId: String, val sourcePath: String, val targetPath: String) {
    init {
        for (path in listOf(sourcePath, targetPath)) {
            require(path.startsWith('/') && '\u0000' !in path && path.toByteArray(Charsets.UTF_8).size < 1024 &&
                path.drop(1).split('/').none { it.isEmpty() || it == "." || it == ".." }) {
                "Directory bind paths must be canonical, absolute and below the guest root"
            }
        }
    }
}
