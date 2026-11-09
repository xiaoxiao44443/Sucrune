package com.sucrune.probe

/** Native PTY measurements. openPair transfers both returned descriptors to
 * the caller; endpoint/controlling borrow a descriptor for the call only. */
object PtyNative {
    init { System.loadLibrary("sucrune_probe") }
    @JvmStatic external fun direct(): String
    @JvmStatic external fun openPair(): IntArray
    @JvmStatic external fun endpoint(fd: Int, mode: Int, nonce: Int): String
    @JvmStatic external fun controlling(fd: Int): String
    @JvmStatic external fun masterControlling(fd: Int, nonce: Int): String
    @JvmStatic external fun sendRight(socketFd: Int, fd: Int): Int
    @JvmStatic external fun receiveRight(socketFd: Int): IntArray
}
