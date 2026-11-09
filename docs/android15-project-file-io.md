# Android 15 project file I/O

Measured on a PKR110 ARM64 phone with Android 15. This section measures native file and broker costs with two ordinary shell-UID processes (UID 2000). Guest syscall translation, guest address validation and app lifecycle are outside these timers. The application measurements below exercise the isolated worker.

## Where the time goes

The direct client used Android file syscalls relative to an open workspace directory. The broker client sent the corresponding production protocol requests over an AF_UNIX SOCK_SEQPACKET socket to the real build-profile workspace broker in a second process. Both clients used the same 16 files at each depth, with warm filesystem caches. The benchmark checked inode and size for metadata calls, ENOENT for missing names, and the length and boundary bytes of reads. A link-time timer measured the manager interval from completion of request receipt until it began sending the response. An empty control sent an unsupported operation and received ENOSYS without touching a file.

| Operation | Direct µs | Broker round trip(s) µs | Manager handling within round trip(s) µs | Requests |
|---|---:|---:|---:|---:|
| Empty control | — | 16.07 | 0.04 | 1 |
| Existing file, no intermediate directory, lstat | 0.38 | 16.77 | 2.82 | 1 |
| Existing file, six intermediate directories, lstat | 0.77 | 21.71 | 9.32 | 1 |
| Missing file, six intermediate directories, lstat | 0.63 | 26.49 | 9.12 | 1 |
| Open descriptor, fstat | 0.13 | 15.14 | 1.81 | 1 |
| Open descriptor, pread 4 KiB | 0.37 | 14.13 | 0.51 | 1 |
| Six directories, open + read 4 KiB + close | 1.93 | 57.56 | 12.61 | 3 |

Each value is the median of seven round means with 768 operations per round and normal CPU placement. The empty exchange includes protocol checks, kernel messaging and scheduling between the two processes. The manager handles project-relative resolution, descriptor ownership and permitted file types. Its directory-walk cost rises with depth. Separate medians make a subtraction between rows unsuitable for exact cost attribution. The phone's scheduling and frequency scaling also affect short timings.

## Changes measured in isolation

For idle blocking receives, the transport can let recvmsg wait for a packet directly. Finite deadlines retain nonblocking I/O and bounded polling. With two processes exchanging a production-format request and a synthetic reply, four paired rounds of 20,000 exchanges produced the following median round means. Both processes could run on CPUs 6 and 7.

| Reply bytes | Original µs | Transport change µs | Pairs faster |
|---:|---:|---:|---:|
| 0 | 16.92 | 15.68 | 3/4 |
| 128 | 17.23 | 15.74 | 4/4 |
| 4096 | 17.56 | 16.43 | 4/4 |

The path change uses the known type of the pinned project root and cwd. When resolving a final component that must follow links, it can inspect an ordinary leaf beneath its pinned parent with a no-follow stat. Symlinks retain guest resolution and managed hard-link handling. The final operation still checks the leaf under that parent.

Four builds (original, transport only, path only, both) ran in balanced order over eight rounds. The client used CPU 6 and the manager CPU 7. In the open/read/close workload, changing only path handling reduced median manager time from 14.11 to 11.34 µs at the root and from 31.16 to 28.34 µs at six directories. It reduced manager time in all eight matched rounds at both depths. The combination measured 11.45 and 28.66 µs respectively. At six directories the combined end-to-end median was 208.14 µs versus 206.42 µs originally, with five of eight matched rounds faster. These measurements establish a reduction in manager work. End-to-end latency remained scheduling-sensitive. This fixed-placement experiment has different absolute timings from the unpinned decomposition above.

Android shell-UID transport tests passed all five groups, including SCM_RIGHTS, malformed messages, descriptor cleanup and bounded waits. The workspace broker suite passed the exercised path, lock, I/O and cleanup cases. Android denied creation of the FIFO fixture with EACCES, so one FIFO subcase was skipped.

## DSH startup on the same phone

DSH Sugar used its existing image, plugins and user configuration. The original APK was `c0bbb450c8f365bafe3617456689cad5b527ac308871c10fbeb8c914c3e8d470`; the candidate was `ef992216748f0f7c1489d0f7c0a57c50938f77a95474258696ca4c9c8013e664`. Only the two packaged ARM64 runtime libraries differed in the APK member comparison. The four test blocks alternated original, candidate, original, candidate. Each block had two force-stop/launch timings and one separate instrumented launch. File caches remained warm. The UI timer ended when a visible, enabled chat editor passed hit-testing.

| Median seconds, with range | Original (4 starts) | Candidate (4 starts) |
|---|---:|---:|
| First preload JS to publication of the local login address | 7.88 (6.84–8.52) | 5.74 (5.57–7.76) |
| Launch command to usable chat | 11.25 (10.26–12.00) | 8.99 (8.85–10.84) |

The four individual chat times for the original were 10.92, 12.00, 11.57 and 10.26 seconds. The corresponding candidate timings were 8.93, 8.85, 10.84 and 9.06 seconds. These samples include Android process scheduling, local authorization and WebView activity. The observed ranges overlap. A larger sample would be needed to estimate a typical startup gain across devices.

In the separate instrumented launches, the resident Node process exercised 15 installed DSH files covering JavaScript, package manifests and locales. It checked the results and measured five batches of 150 calls per operation in each of two processes per version. The first batch ran shortly after address publication and could overlap with startup. Median batch means for open/read/close were 182.7 → 192.9 µs, native realpath 438.7 → 471.2 µs, and missing lstat 50.9 → 76.5 µs. These application results do not establish a general file-operation speedup.


## File operations after the chat became idle

The same main Node process benchmark on the same 15 installed files started 10 seconds after the authenticated chat editor was usable. The four independent app starts followed candidate, original, original, candidate order. Every operation had 75 warm-up calls and five timed batches of 360 calls per start. Each cell below is the median batch mean for that individual process, in microseconds per operation.

| Operation | Candidate 1 | Original 1 | Original 2 | Candidate 2 |
|---|---:|---:|---:|---:|
| stat | 75.8 | 73.2 | 77.6 | 64.5 |
| lstat | 66.6 | 60.8 | 80.4 | 84.4 |
| Missing lstat | 50.4 | 50.6 | 73.7 | 79.6 |
| fstat on open file | 43.6 | 52.1 | 45.0 | 49.5 |
| Positioned read, up to 4 KiB | 49.2 | 59.4 | 51.1 | 54.2 |
| Open + close | 117.9 | 125.8 | 149.7 | 102.5 |
| Open + read up to 4 KiB + close | 195.2 | 206.6 | 196.0 | 167.2 |
| Node native realpath | 372.1 | 417.0 | 467.6 | 450.9 |

For both idle candidate starts, open/close and open/read/close took less time than in either original start. The stat variants varied across runs. Only two independent Node processes were measured per version in this follow-up. The batches within one process share its scheduler and device state.

## Isolated runner and file descriptor experiment

An Android process snapshot with the chat open showed the Sugar manager under the app UID, an Android runtime worker under a separate isolated UID, and its native runner child under that same isolated UID. The runner hosted the resident Node/DSH process. For file operations the runner exchanges requests with a workspace broker thread in the manager. The worker supervises execution and reaps the runner. The startup coordinator also launches a short-lived bundled shell execution to remove the one-time login handoff files after use.

A temporary variant, signed with the same certificate and replacing only the runner, tested a project-private regular file created by the main guest Node. The manager passed an already open read-only FD over a secondary broker session with SCM_RIGHTS. The isolated runner (UID 99755 for this execution) verified the access mode and regular file type, used pread at offset 287, and checked all 65,521 returned bytes. The caller verified the payload and that the original handle's sequential offset still pointed to byte zero. The installed candidate was restored afterwards. The experiment demonstrates permission for this file type and device. Ordinary reads in the candidate still use the broker protocol. A fast path for shared regular-file descriptions needs to preserve offsets across read, seek, dup and fork, enforce access mode and lifetime, and fall back for unsupported storage or devices.

The non-debuggable Sucrune instrumentation target also passed all 3 checks in the focused distro symlink run. The Python guest exercised absolute, relative, dangling and cyclic links, no-follow opens, dirfd after renaming, and attempts to escape the project. Instrumentation verified the test workspace was removed.

## Direct read compared with proxy read in the DSH process

2026-11-07, PKR110, Android 15, ARM64. Four fresh DSH Node processes, each running inside the normal Android isolated runner. After the chat was ready and quiet for 10 seconds, Node created a 2 MiB project-private fixture and checked it once to warm the file cache. In each pair both paths used the same open regular file, caller buffer, file offsets and JS fs.readSync call. The original path used the normal broker protocol, sending up to 4 KiB per reply. On the experimental path, the broker passed the already open read-only FD using SCM_RIGHTS and the isolated runner called pread into checked guest memory. Both paths went through the guest syscall handler. A native counter checked which calls reached the direct path.

Each independent process alternated broker-first and direct-first order in six pairs per size. The timed operation ends on return from fs.readSync. The test compared every byte with a deterministic 2 MiB reference outside the timed region and verified the sequential guest file offset before and after each positioned-read session. Each path completed 1,800 checked reads across the four processes, covering 194,641,920 verified bytes per path, including warm-ups. This test exercised a cached regular file in app-private storage.

### Read latency with a previously granted FD

Times below are microseconds per positioned read. Each cell is the median of the four process medians. Within a process, each of the six batches averaged 48, 18 or 5 timed calls respectively. The ratio divides the two reported latency values. The last column counts within-process pairs with lower direct latency, out of 24.

| Read size | Broker µs | Direct µs | Broker/direct | Direct faster |
|---|---:|---:|---:|---:|
| 4 KiB | 62.5 | 12.6 | 5.0× | 24/24 |
| 64 KiB | 773.6 | 28.5 | 27.2× | 24/24 |
| 1,024 KiB | 12,018.0 | 312.9 | 38.4× | 24/24 |

Per-process medians below give four independent observations (µs, broker / direct).

| Read size | Launch 1 | Launch 2 | Launch 3 | Launch 4 |
|---|---:|---:|---:|---:|
| 4 KiB | 61.7 / 13.3 | 71.9 / 12.7 | 63.4 / 12.5 | 59.3 / 10.5 |
| 64 KiB | 754.4 / 29.3 | 831.5 / 28.7 | 762.8 / 28.2 | 784.5 / 25.3 |
| 1,024 KiB | 11,130.4 / 305.9 | 12,676.4 / 319.9 | 11,937.1 / 324.2 | 12,099.0 / 262.8 |

### First read and setup costs

Each new guest FD was opened read-only against the same cached fixture. The diagnostic created a secondary broker session to isolate FD transfer and verified the access mode. The first-read pairs alternated order on that same FD. The broker and grant-plus-read columns start after the common file open and diagnostic channel setup. The final column also charges the direct path the actual time to set up a fresh diagnostic session on every FD. Column three includes the JS control call, FD grant and the full first pread. Common file open, a one-byte offset sentinel and control calls used only for verification are outside these columns.

| Read size | First broker read µs | Grant + first direct read µs | Fresh diagnostic session + grant + first direct read µs |
|---|---:|---:|---:|
| 4 KiB | 83.3 | 104.3 | 1,215.0 |
| 64 KiB | 882.9 | 132.3 | 1,155.0 |
| 1,024 KiB | 13,681.7 | 484.0 | 1,407.5 |

With a prepared channel, grant plus first pread was faster in 8/24 pairs at 4 KiB, 24/24 at 64 KiB and 24/24 at 1 MiB. When each direct result also included creating a fresh secondary diagnostic session, the corresponding counts were 0/24, 2/24 and 24/24. The channel-creation cost in this diagnostic depends on the transfer design. A production implementation could reuse a broker session across files.

Across sizes, median-of-process-medians time was 66.0 µs inside the runner for the FD request, SCM_RIGHTS receipt and regular read-only file checks; 87.7 µs as observed by JS for the same grant. A new diagnostic session setup took 988.8 µs, and the common normal open took 134.5 µs. The median back-to-back JS timer interval was 3.0 µs. No timer subtraction was applied.

The signed diagnostic APK SHA-256 was `520157b76e95be2dc3644b3179aad348d51ba8c21f36fc0dfaf9474a3e02f103`. Its only changed ZIP member was `lib/arm64-v8a/libsucrune_runner.so`. After the trials, the original handoff module and installed APK (`ef992216748f0f7c1489d0f7c0a57c50938f77a95474258696ca4c9c8013e664`) were verified and the benchmark files removed. Idle chat was checked again. This experiment did not time a full DSH cold start, external document providers, uncached storage, writes or sequential reads through a direct FD. The installed release still sends ordinary reads through the broker.

## 正式版只读 FD 与 DSH 冷启动

2026-11-07，Android 15 ARM64 真机 PKR110。Linux runner 的只读普通文件打开操作通过现有项目 broker 通道，在原应答中接收可选的 SCM_RIGHTS 文件描述符。runner 对读缓冲区执行原有的客体内存检查；代理保留来源相同的打开文件描述，可继续处理定位、控制及回退。执行 ELF 的权限与项目内路径检查、快照和映射边界仍适用。

旧包和新版各冷启动 6 次，顺序为 AB、BA、AB、BA、AB、BA。每轮保留应用数据与已展开的 Linux 镜像，确认聊天空闲，结束主 App 进程，覆盖安装对应 APK，再从桌面启动 Intent 计时。各轮使用同一系统文件缓存条件，没有重启手机或主动清缓存。两版 APK 逐项比较，仅 ARM64 runner 和运行时管理库内容发生变化。

后端就绪取 DSH 发出登录地址并完成交接的时刻。观测进程每 80 毫秒检查一次不含登录信息的标记。聊天可操作取本机 WebView 中第一个可见、启用并通过点击命中检测的聊天输入框；未发送模型请求。首段 JS 到后端就绪由同一 Node 的单调时钟计时。启动至首段 JS 通过前两段时间相减估算，含 Android 进程启动、Linux runner 和 Node 初始化。

| 指标（秒） | 旧版中位数（范围） | 新版中位数（范围） | 两版中位数之差 | 耗时降幅 | 相邻配对差的中位数 | 新版更快 |
|---|---:|---:|---:|---:|---:|---:|
| 发出启动命令到 DSH 后端就绪 | 6.34 (5.25–6.85) | 3.38 (3.22–6.14) | 2.96 | 46.7% | 3.04 | 5/6 |
| 发出启动命令到聊天框可操作 | 8.13 (6.94–8.46) | 4.94 (4.73–7.67) | 3.19 | 39.2% | 3.29 | 5/6 |
| 启动到首段 JS（估算） | 1.52 (1.44–1.62) | 0.58 (0.56–0.60) | 0.94 | 61.8% | 0.95 | 6/6 |
| 首段 JS 到 DSH 后端就绪 | 4.81 (3.78–5.33) | 2.79 (2.65–5.56) | 2.02 | 41.9% | 2.09 | 5/6 |

| 启动轮次 | 版本 | 首段 JS 到后端（秒） | 启动到后端（秒） | 启动到聊天（秒） |
|---:|---|---:|---:|---:|
| 1 | 旧版 | 4.452 | 6.042 | 7.673 |
| 2 | 新版 | 5.556 | 6.144 | 7.674 |
| 3 | 新版 | 2.685 | 3.245 | 4.783 |
| 4 | 旧版 | 5.150 | 6.661 | 8.207 |
| 5 | 旧版 | 4.623 | 6.243 | 8.049 |
| 6 | 新版 | 2.647 | 3.215 | 4.733 |
| 7 | 新版 | 2.795 | 3.392 | 4.983 |
| 8 | 旧版 | 4.990 | 6.435 | 8.246 |
| 9 | 旧版 | 3.782 | 5.255 | 6.944 |
| 10 | 新版 | 2.822 | 3.402 | 4.980 |
| 11 | 新版 | 2.787 | 3.368 | 4.898 |
| 12 | 旧版 | 5.327 | 6.853 | 8.458 |

同一份 Node/ARM64 ELF 回归在旧版和新版的 DSH 主进程通过四组检查，覆盖定位读和顺序读、短读与 EOF、符号链接、重命名和删除后读取、可写描述符、目录、dup/dup3、fork/exec、CLOEXEC 和文件编号复用。非调试 Sucrune App 另外用 Python 对比 O_RDONLY 与 O_RDWR 打开的同一类文件，验证实际命中直读和通过 broker 回退的读取共享 Linux 文件偏移。

linux_distro_readonly_file_io: PASS Shared offsets, readv, pread, fork, dup2 reuse, unlinked inode and writable access passed. Native direct reads (calls/bytes/guest bytes): readonly 130/14291724/4252564, readwrite control 66/10097420/58260.

旧 APK SHA-256 为 `ef992216748f0f7c1489d0f7c0a57c50938f77a95474258696ca4c9c8013e664`，新版为 `a02666fcac0afbc707ab4f85a11dffa7416548a6e7fbbbc3e7ad69c73ec95efc`。最终手机已覆盖安装新版，核对启动脚本与 APK 镜像一致，聊天可用。本轮数据是单台手机上的进程冷启动。
