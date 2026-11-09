# Packaged runner process capability probe

The Android 15 application run passed the mechanism fixture in 30 ms. The
report records `mechanism_verified=true`, `cleanup_verified=true`, actual
runner exit 0, subreaper ECHILD, and lease EOF. The original
`process-capability-first.txt` has SHA-256
`ef27c22842c6091a6d94b165354ae3aa87e1305c170efe7e87db236902292b9a`.
The separate guest executable cases are documented in `linux-process-design.md`.

The `process_capability` instrumentation branch binds a dedicated, non-exported isolated `ProcessProbeService`. It invokes JNI with the installed `nativeLibraryDir/libsucrune_runner.so` path. No guest-supplied executable or command is accepted. Android API level, ordinary manager UID, isolated service UID/PID, native wrapper UID/PID and runner PID are reported separately.

The native wrapper temporarily becomes a child subreaper and requires no pre-existing children. It blocks signals before Bionic fork, establishes a private process group, sets parent-death SIGKILL, closes inherited descriptors using a bounded raw `/proc/self/fd` scan and executes the installed runner. Its two retained descriptors are an event socket and a lifetime lease writer. No stdin content, credentials, guest environment or model requests are involved.

The fresh runner starts a Bionic helper pthread before Bionic fork. The child retains an unfiltered supervisor and uses raw ARM64 clone to start a raw worker thread. The worker installs a thread-local seccomp filter that returns EACCES for getppid. The supervisor must still obtain its parent PID, then exec the same packaged runner while the filtered worker remains alive. The new image must obtain its parent PID too. This tests the proposed separation between filtered execution thread and unfiltered exec supervisor while retaining Android's existing baseline policy. It does not remove or bypass that baseline.

The raw worker never calls Bionic, reads errno, allocates, or takes a copied lock. Its inherited TLS pointer is unused. This is deliberately narrower than production guest continuation: proper guest CPU/TLS/gate restoration, copied guest libc atfork callbacks, broker sessions and process state are not exercised here. A fresh image identity event proves successful exec; a failed exec reports its raw negative errno instead of emitting a premature success event.

The child owns a separate lease through exec. Its parent confirms both waitpid and lease EOF. Another bounded scenario forks a guardian and leaf: the leaf first installs PDEATHSIG and confirms its parent, then acknowledges readiness; only then does the guardian exit. The subreaper must actually reap the leaf with SIGKILL status. The test does not send SIGKILL directly to that leaf on the success path.

The wrapper's main deadline is six seconds, with bounded cleanup afterward and a twelve-second service watchdog. It observes leader death using waitid(WNOWAIT), keeping the leader PID reserved while signalling only its private process group to remove unexpected survivors. It then reaps the leader and all adopted descendants, and checks lifetime lease EOF. `cleanup_verified` requires these independent observations; Binder death additionally confirms disposal of the isolated Service but does not substitute for descendant evidence. A timeout or incomplete cleanup cannot establish `mechanism_verified`.

Each operation reports attempted, actual rc, errno, PID, UID and a detail integer (wait status for wait operations). The intentionally denied worker getppid has success=false and errno=EACCES; the separate `mechanism_verified` predicate recognizes this expected denial. A denied prerequisite leaves later operations absent rather than falsely marked attempted. A fatal kernel signal is preserved as runner_signal when no returning errno exists. An instrumentation MEASURED result means valid, cleaned-up capability evidence; it does not mean every capability was granted.

The probe uses no ADB shell evidence as a replacement for an application run. x86_64 builds report unsupported architecture for the raw ARM64 experiment. Compiling either ABI establishes source/link validity only. Production support still needs guest program evidence, preserved process FD/OFD and cwd semantics, child notifications and wait states, a shared execution deadline, and all descendant cleanup barriers. Original node-pty/Bash additionally requires PTY allocation, session/process-group semantics and controlling-terminal capability measurements.
