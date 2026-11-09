package com.sucrune.probe

/** JNI shell/probe bridge. coreCall lazily opens Go in the manager only. */
internal object NativeProbe {
    init { System.loadLibrary("sucrune_probe") }

    @JvmStatic
    external fun runProbe(): String

    @JvmStatic
    external fun runElfProbe(): String

    // Capability measurement only. Borrowed descriptors remain owned by PFDs.
    @JvmStatic external fun runNetworkProbe(mode: Int, borrowedFd: Int,
                                           loopbackPort: Int, timeoutMs: Int): String
    @JvmStatic external fun runProcessProbe(runnerPath: String): String

    @JvmStatic external fun coreCall(dataDir: String, request: String): String
    // Per-execution broker socket, never a guest directory FD.
    // Success: [client socket, completion pipe read end]; failure: [-errno].
    @JvmStatic external fun openWorkspace(path: String): IntArray
    // Explicit manager policy: 0=none, 1=loopback TCP/UDP, 2=outbound TCP and managed DNS. Policy is fixed
    // before the worker starts; changing a guest environment cannot grant it.
    @JvmStatic external fun openWorkspaceWithNetwork(path: String, policy: Int): IntArray
    @JvmStatic external fun openScopedWorkspace(path: String, networkPolicy: Int, networkHandle: Long, build: Boolean, scope: Int): IntArray
    @JvmStatic external fun openWorkspaceWithImage(path: String, networkPolicy: Int, networkHandle: Long,
        build: Boolean, scope: Int, guestPath: String, image: ByteArray): IntArray
    // Typed POSIX removal relative to a directory FD already held by the Android host.
    @JvmStatic external fun unlinkDirectoryEntry(parentFd: Int, child: String, directory: Boolean): Int
    @JvmStatic external fun renameDirectoryEntry(fromFd: Int, fromName: String, toFd: Int, toName: String, flags: Int): Int
    @JvmStatic external fun directoryOpenFlag(): Int
    @JvmStatic external fun checkDocumentOpenMode(fd: Int, access: Int, append: Boolean): Int
    @JvmStatic external fun openWorkspaceWithDirectory(path: String, networkPolicy: Int, networkHandle: Long,
        build: Boolean, scope: Int, guestPath: String?, image: ByteArray?, directory: GuestDirectory): IntArray
    @JvmStatic external fun openBuildWorkspace(path: String, policy: Int, networkHandle: Long): IntArray
    @JvmStatic external fun openWorkspaceOnNetwork(path: String, policy: Int, networkHandle: Long): IntArray
    @JvmStatic external fun runShell(brokerFd: Int, script: String, cwd: String,
                                    stdoutFd: Int, stderrFd: Int): String
    @JvmStatic external fun runProgram(brokerFd: Int, programId: String, args: Array<String>,
                                      env: Array<String>, cwd: String, stdoutFd: Int, stderrFd: Int,
                                      stdinFd: Int): String
    @JvmStatic external fun listPrograms(): String
    @JvmStatic external fun runLinux(brokerFd: Int, path: String, args: Array<String>,
                                    env: Array<String>, cwd: String, stdoutFd: Int, stderrFd: Int,
                                    stdinFd: Int, stopFd: Int): String
}
