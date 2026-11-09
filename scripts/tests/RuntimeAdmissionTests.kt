package com.sucrune.probe

fun main() {
    val option = "SUCRUNE_RESIDENT_COMPANION=1"
    fun launch(mode: String? = null, companion: Boolean = true, id: String = "project",
               program: String = "/usr/bin/node", args: List<String> = listOf("/opt/sugar/worker.cjs"),
               cwd: String = "/workspace", env: List<String> = emptyList()): RuntimeClient.ExecutionSlot {
        val settings = env + listOfNotNull(option.takeIf { companion }, mode?.let { "SUCRUNE_WRITE_SCOPE=$it" })
        return RuntimeClient.executionSlot(id, program, args, settings, cwd, true, RuntimeClient.writeScope("linux", settings))
    }
    val normal = launch()
    val read = launch("read-only")
    val write = launch("workspace-write")
    fun slots(vararg entries: RuntimeClient.ExecutionSlot) = RuntimeClient.executionSlotCount(entries.toList())
    check(slots(normal, read, write) == 1 && slots(normal, read, write, write) == 2)
    check(slots(launch(companion = false), launch("read-only", false), launch("workspace-write", false)) == 3)
    check(slots(normal, launch("read-only", id = "another"), launch("read-only", program = "/bin/sh"),
        launch("read-only", args = listOf("different")), launch("read-only", cwd = "/tmp"),
        launch("read-only", env = listOf("MODE=other"))) == 6)
    check(runCatching { RuntimeClient.executionSlot("p", "/bin/sh", emptyList(), listOf(option), "/", false, 0) }.isFailure)
    check(runCatching { RuntimeClient.writeScope("program", listOf("SUCRUNE_WRITE_SCOPE=read-only")) }.isFailure)
    check(runCatching { RuntimeClient.writeScope("linux", listOf("SUCRUNE_WRITE_SCOPE=typo")) }.isFailure)
    check(runCatching { RuntimeClient.writeScope("linux", List(2) { "SUCRUNE_WRITE_SCOPE=read-only" }) }.isFailure)
    println("PASS resident admission: default per execution, explicit companions, per-entry and per-scope bounds")
}
