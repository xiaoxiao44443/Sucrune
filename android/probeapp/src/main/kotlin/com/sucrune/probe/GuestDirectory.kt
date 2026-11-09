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
