# Sucrune 设备验证

常用发行版命令、Git、curl、Python 和原版 DSH 持久 Bash 的前台验收入口见[工具兼容性验证](linux-toolbox.md)。

运行时和探针从普通 APK 身份启动。ADB 用于安装、启动 instrumentation、采集结果，以及重启测试中的 force-stop；不以 adb shell 身份代替客体执行，不申请 root 或修改系统设置。

当前使用不可调试的 validation 构建，版本 0.7.0-linux-dev，逐轮结果见 [Linux 开发证据](validation/android15-linux-progress.json)。[0.6.0 IO](validation/android15-io.md)、[0.5.0 exec](validation/android15-exec.md)、[0.4.0 Lua/stdin](validation/android15-tools.md)、[0.3.0 libc](validation/android15-libc.md)、[0.2.0 运行时](validation/android15-runtime.md)、[阶段一](validation/android15-arm64.md)和[阶段二](validation/android15-arm64-elf.md)保留历史范围，不能替代本轮回归。

## 构建与覆盖安装

```powershell
.\scripts\build-android.ps1 -Zig 'C:\Tools\Zig\zig.exe' -Go 'C:\Tools\Go\bin\go.exe' -JdkHome 'C:\Tools\JDK' -SdkRoot 'C:\Android\Sdk' -Variant validation
```

脚本先核对 Lua 源码并构建、检查 Linux 验证程序，再构建两 ABI 的 Go c-shared、APK 并运行 lint。Zig 必须为固定的 0.17.1，下载校验说明见 [程序构建](../native/programs/README.md)。validation 设置 debuggable=false，沿用本地开发签名。APK 应包含 assets/third_party/musl 下的 COPYRIGHT、ZIG-LICENSE、NOTICE.md，以及 assets/third_party/lua 下的 LICENSE、NOTICE.md。

直接 Gradle 或 Android Studio 前，先准备两类客体／管理库：

```powershell
.\scripts\build-linux-programs.ps1 -Zig 'C:\Tools\Zig\zig.exe'
.\scripts\build-go-android.ps1 -Go 'C:\Tools\Go\bin\go.exe' -SdkRoot 'C:\Android\Sdk'
.\gradlew.bat -Psucrune.testBuildType=validation :probeapp:assembleValidation :probeapp:assembleValidationAndroidTest :probeapp:lintValidation
```

按用户要求，主 APK 和测试 APK 保留在手机，后续使用相同签名覆盖安装：

```powershell
adb -s SERIAL install -r android/probeapp/build/outputs/apk/validation/probeapp-validation.apk
adb -s SERIAL install -r android/probeapp/build/outputs/apk/androidTest/validation/probeapp-validation-androidTest.apk
```

SERIAL 仅为占位符，不将真实序列号写入仓库。-r 的含义是重装并保留数据，见 [Android ADB 文档](https://developer.android.com/tools/adb)。保留现用签名密钥；不能为解决签名不匹配而擅自卸载、清空应用数据或重建密钥。厂商安装确认界面是否再次出现由设备决定。

## Linux、Node 与 DSH 开发验证

先按 [固定来源准备流程](node-dsh-target.md)生成测试资产并重建测试 APK。包含
Node、DSH CLI 和 SDK 资产时，完整套件目前为 36 项：

```powershell
adb -s SERIAL shell am instrument -w -r -e probe linux -e node true -e dsh true -e sdk true -e keep_foreground true -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

`keep_foreground=true` 显式启动测试 Activity，证据仅覆盖前台运行。此设备曾出现
退后台后整个执行链停滞、回前台后恢复；系统机制尚未确定。测试结束会删除本次
创建的项目和导入临时文件，保留执行历史。SDK 检查包括依赖解包、EOF 启动与
交互式 initialize/shutdown，不发送模型或工具请求。其他回归组也可传入此参数。

## FD 与文件标准流：十二组集成测试

```powershell
adb -s SERIAL shell am instrument -w -r -e probe io -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

| 组 | 检查范围 |
| --- | --- |
| io_shell_lua_file_streams | Shell → Lua 的文件输入／输出、精确产物、跨项目不可见与随后复用 |
| io_builtin_restore_append | builtin 输入、覆盖／追加、cat stdin、返回后标准流恢复 |
| io_redirection_errors_and_order | 失败 exec 后恢复、重复／FD／here-doc 语法拒绝、两种打开顺序的文件副作用 |
| io_nested_exec_redirection | 嵌套 Shell／source 返回恢复，嵌套 exec 继承输入输出且不返回 |
| io_shared_offsets_flags | dup/fcntl 别名共享偏移与 O_APPEND、CLOEXEC 独立、关闭与编号复用 |
| io_errors_capacity_recovery | 无效 dup3/fcntl 不破坏目标、64 槽耗尽与复用、满表 open 无文件副作用 |
| io_aliases_across_exec | exec 关闭带标志的别名，保留其余共享偏移及底层资源 |
| io_standard_stream_aliases | 标准流别名换号、stderr 路由、0/1/2 被文件复用后的 read/write/stat/seek |
| io_last_stdin_alias_close | close(0) 后别名继续保持输入；关闭最后一个别名使写入任务在 worker 活着时完成 |
| io_exec_closes_saved_input | Shell 文件重定向后 exec，CLOEXEC 备份不留下隐藏读端；背压写入任务完成后取消并保留产物 |
| io_repeated_redirect_no_leak | 200 条重定向命令在 64 槽内完成，检查标准流恢复和无备份泄漏 |
| io_parallel_project_streams | 两项目独立输入／输出，同名产物分离、不同 PID/UID 和实际原生执行区间重叠 |

正常返回检查 fd_limit=64、fd_peak 不超限、fds_live=0、resources_live=0，以及
既有 TLS／handler／栈恢复和四项结束条件。原 stdin 的存活测试需先观测到仍有别名
时 feeder 未完成，再观测最后引用关闭后 feeder 已完成且执行仍 running；仅在
最终 worker 死亡后看到 EOF，不能证明别名所有权正确。Shell 保存输入的测试同样
不能依靠 worker 退出消除泄漏，必须在后继 Lua 的 CPU 循环仍运行时检查完成状态。

这些检查不提供任意程序、PTY、管道、子进程、非阻塞 I/O 或恶意代码隔离证明。
本轮实际通过状态见验证记录，不能把此用例清单当成已执行结果。

## execve 镜像替换：十一组集成测试

```powershell
adb -s SERIAL shell am instrument -w -r -e probe exec -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

| 组 | 检查范围 |
| --- | --- |
| exec_shell_lua_artifacts | Shell 转 Lua、Unicode argv/env/cwd、产物持久化与跨项目分离；原脚本不继续 |
| exec_failure_and_redirection | 未知／宿主路径拒绝、失败后继续；直接和继承重定向成功交给 Lua，检查目标产物 |
| exec_static_shell_static_chain | libc → ET_DYN Shell → 静态 Lua，保留环境与有限 stdin |
| exec_nested_shell_replacement | 嵌套 Shell 成功 exec 后子层与外层均不返回 |
| exec_native_state_preserved | 同 PID/TID、cwd、非 CLOEXEC 文件偏移、文件与 stderr CLOEXEC、TLS/BSS/arena 重建、剩余 stdin、虚拟 SIGUSR1 掩码和独立 argv[0]/AT_EXECFN |
| exec_invalid_requests_preserve_image | EFAULT/E2BIG/ENOENT 等预检查错误后旧镜像、TLS、FD 标志和偏移不变 |
| exec_standard_stream_cloexec | stdin/stdout 的 CLOEXEC 独立生效；虚拟关闭和宿主流所有权正确 |
| exec_chain_limit | 成功替换 32 次，第 33 次 ELOOP，仍可正常输出退出 |
| exec_deadline_and_reuse | 替换前后共用原 3000 ms 期限；CPU 循环终止、四项清理后复用 |
| exec_cancel_and_reuse | 带输入背压的 CPU-only 后继镜像可取消，清理完成后复用 |
| exec_parallel_projects | 两项目独立替换、不同 PID/UID、同名产物分离和原生区间实际重叠 |

正常结束核对 initial kind、last_program、exec_count、exec_limit=32，以及
host_context_restores=exec_count+1；检查恢复宿主 TLS、备用信号栈、handler 和
线程回收。超时／取消不伪造 exit_code，仍核对 worker death、输出 EOF、broker
清理及 stdin 完成。PID/TID 继承由客体前后比较，不把“同一请求 ID”当作充分证据。

此套件不验证任意 ELF、fork、动态链接、PATH/shebang 或恶意代码隔离。

原生文件代理可另行运行独立功能测试，检查描述符、exec commit、路径边界、
rename 与 completion。若该二进制由 adb shell/UID 2000 启动，应明确单独记录，
不能把它算作本版 60 项 App 身份验收，也不能据此宣称 Android 隔离服务权限通过。

## Lua 与有限 stdin：十组集成测试

```powershell
adb -s SERIAL shell am instrument -w -r -e probe tools -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

| 组 | 检查范围 |
| --- | --- |
| tool_catalog_and_input_limits | 原生目录 Lua 版本、未知程序和超过 1 MiB 的 stdin 在取得占用前拒绝 |
| lua_language_arguments_environment | 循环、函数、table、Unicode、argv/env |
| lua_script_modules_project_files | 项目脚本、纯 Lua 模块、文件产物、跨项目边界及 Shell 复用 |
| lua_stdin_script_and_eof | lua - 从 stdin 读取脚本，空输入得到 EOF |
| lua_binary_stdin_backpressure | 1 MiB 二进制含 NUL 完整往返、输入复制与摘要、实际读取数 |
| tool_ignored_and_closed_stdin | Lua 忽略输入可结束；固定 musl-smoke 关闭 FD 0 后持续 CPU 循环，确认 worker 仍存活时写入任务已关闭，再取消和复用 |
| lua_timeout_full_stdin_and_reuse | 不读输入的 CPU 循环在背压下取消／超时，四项清理确认后复用 |
| lua_errors_and_unsupported_operations | 语法／运行错误非零退出、不可用进程／动态库／宿主路径不被放行 |
| lua_cpu_clock_and_calendar | worker 进程 CPU 时钟与日期时间 |
| lua_parallel_projects | 独立 PID/UID、同名文件分离和实际执行区间重叠 |

每次结束须核对 stdin_feeder_completed；stdin_bytes_written 为已排入 socket 的
字节，stdin_bytes_read 为原生客体读取计数，两者不能混为一谈。完整输入消费用例
核对请求长度、摘要、原生读取计数和导出文件；早关或忽略输入允许只消费前缀。
Lua CPU 循环取消用例不依赖客体继续发出 syscall，验证监督器仍能停止 worker。
这些用例不等同于恶意脚本安全审计或性能基准。

Lua 上游不允许关闭标准文件对象；实际 FD 0 早关通过
`musl-smoke --close-stdin-loop` 检查，不修改 Lua 源码，也不把 Lua 的拒绝关闭
行为当成运行时 syscall 失败。

## libc 程序：七组集成测试

```powershell
adb -s SERIAL shell am instrument -w -r -e probe program -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

| 组 | 检查范围 |
| --- | --- |
| musl_tls_memory_files_utf8 | musl 启动/TLS、argv/env Unicode、errno、工具链分配器与内存正负例、stdio 文件、exit 42 |
| program_cwd_and_shell_reuse | cwd 下生成产物、另一项目不可见、同项目随后 Shell 可读 |
| parallel_program_workers | 两个独立 PID/UID、实际原生执行区间重叠 |
| program_timeout_and_reuse | libc sleep 已开始后超时、结束条件与项目再执行 |
| program_cancel_and_reuse | 启动即取消、libc sleep 执行中取消、Shell/program 共用项目占用 |
| program_fault_cleanup | musl TLS 下真实 SIGSEGV、lost 且无 exit_code、清理确认后复用 |
| program_request_boundaries | 未知程序、NUL、数量／字节上限、env 格式／重复、cwd 和参数边界 |

必须核对 guest_tls_seen、host_tls_restored、signal_gate_entries、heap_peak_bytes、
program_parser_checks 与精确输出／退出码；不能仅凭看到打印就认定 TLS 和内存边界通过。
program 正常结束的监督器条件仍包括 worker death、双输出 EOF、broker completion
EOF 和 stdin 写入任务关闭完成。当前旧 ProgramChecks 辅助函数逐项断言前三项，
没有在每个用例独立断言 stdin_feeder_completed；该字段的显式断言由 IO、Exec、
Tools 套件覆盖。未实现 syscall 返回 ENOSYS，fixture 通过不代表整个工具链 libc
或所有上游 musl 功能都可用。

## Shell 回归：十组集成测试

```powershell
adb -s SERIAL shell am instrument -w -r -e probe runtime -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

仅在 ARM64 设备上执行，x86_64 不计为 Shell 验收通过。RuntimeChecks 直接调用同一 RuntimeClient，覆盖真实 Kotlin 管理者、Go 核心、隔离 worker、内嵌 ELF 和文件代理。

| 组 | 检查范围 |
| --- | --- |
| parallel_project_isolation | 两个项目同路径不同内容、不同 worker PID/UID、原生执行时间重叠 |
| file_api_unicode_persistence | 中文／emoji 名称与内容，Go 和客体读写一致，另一项目路径不可见 |
| script_file_and_reuse | sh FILE 执行，文件跨 worker 保留并可由字节 API 导出 |
| quotes_redirection_cwd | 引号、覆盖／追加、条件连接、cd 与指定 cwd |
| unsupported_is_explicit | 管道返回 2、未知命令返回 127，没有宿主命令回退 |
| timeout_and_reuse | 执行超时、清理确认、同项目再次执行 |
| cancel_and_reuse | 启动即取消、执行中取消与再次执行 |
| event_cursor_and_no_subscriber | 游标去重、不轮询时仍排空并持久化输出 |
| bounded_output_drains | 双流各超过 64 KiB，独立排空、限长与截断标记 |
| workspace_boundaries_and_busy | 越界路径、宿主 proc 路径、同项目活动执行／删除冲突 |

正常结束检查 native 恢复、备用栈、线程回收；旧 RuntimeChecks 显式检查 worker 身份、debuggable=false、Binder death、双流 EOF 和 broker completion，没有逐例断言 stdin_feeder_completed。Shell 没有 ByteArray 输入任务，该清理条件直接满足；监督器仍以四项条件决定终态，stdin 完成字段的显式断言由 IO、Exec、Tools 套件覆盖。启动即取消也可通过“RUN 从未发送”的分支，不伪造 worker 死亡证据。

Runner 自动创建并清理自己建立的项目。失败时先处理仍活动的执行，再删除对应测试项目；不要扩大到用户项目或清空整个应用。

## 管理进程真实重启：两个阶段

这一测试故意留下 running 记录，需要在 prepare 成功后强制停止本应用，再运行 verify；它不是在同一 JVM 里重开对象冒充重启。

```powershell
adb -s SERIAL shell am instrument -w -r -e probe runtime_recovery -e phase prepare -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
adb -s SERIAL shell am force-stop com.sucrune.probe
adb -s SERIAL shell am instrument -w -r -e probe runtime_recovery -e phase verify -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

prepare 保存一次实际 running 执行、含 Unicode 的文件和应用私有回执。verify 要求管理进程 PID 改变、旧记录为 lost、reason=manager_restarted、process_resumed=false、无虚构 exit_code，并核对文件、原请求与新执行。成功后删除本次项目和回执；执行历史按既定 API 保留。

有未完成回执时不要重复 prepare，应先核对并完成 verify。该流程会停止本应用的所有执行，只应在无用户活动任务的验证时段运行。它覆盖受控 force-stop 恢复，不代表已验证系统低内存回收或长期后台保活。

## 保留的机制回归

```powershell
# 默认 seccomp_sigsys_return：普通服务两次、隔离服务两次
adb -s SERIAL shell am instrument -w -r -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation

# 受控 ARM64 ELF：普通服务两次、隔离服务两次
adb -s SERIAL shell am instrument -w -r -e probe arm64_elf -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

每例有 15 秒期限，报告后要求 Binder death 才继续同服务下一例。seccomp 检查一次受控陷阱、424242、真实 PID/TID 控制和信号清理；ELF 检查精确输出 Hello from Sucrune ELF! 加换行、exit 42、两个 syscall、初始栈／BSS、自身恢复与 26 个默认 4 KB 解析器负例。16 KB 参数正例不等于 16 KB 真机执行。

## 判断与记录

读取最终 Bundle 的 passed、failed、expected_tests 和 INSTRUMENTATION_CODE。成功应为全部通过、failed=0、code=-1；不能只看 adb 的进程退出码。io 预期 12 组，exec 11 组，tools 10 组，program 7 组，runtime 10 组，recovery 每阶段 1 组，机制探针各 4 例；全部执行时合计 60 个验收条目。unsupported、缺失报告、无效证据或退出未确认均不能计为通过。

记录设备类别、API、内核、ABI、页大小、应用版本、签名类型和 debuggable。新配置必须另行验证，不从 Android 版本自动推断支持。APK 签名、zipalign 和 ELF 段对齐检查与设备执行分别记录。

## 保留应用，清理临时产物

**当前用户要求：保留 com.sucrune.probe 和 com.sucrune.probe.test，后续 install -r 覆盖。** 不运行 uninstall 或 pm clear，不为清理测试重置整个 App；保留匹配的本地签名密钥与应用内持久执行历史供查看。

清理范围只包括本轮创建的临时项目／恢复回执、原始日志、截图及其他 scratch。先保存精简的已核对结论，再枚举本轮路径，确认均在对应工作目录内后删除。不要清空设备 logcat、整个 .build、SDK、共享工具链或用户已有项目。

可用 `adb -s SERIAL shell pm list packages com.sucrune.probe` 确认两包仍安装。旧两份验证报告中的“已卸载”是当时事实，不按新规则改写历史。

## 尚未覆盖

Android 10 基线、x86_64 AVD 运行、16 KB 真机、真实 Activity 退后台／重建、系统低内存回收、更多原生异常类型、恶意 ELF 和性能基准仍需专门验收。本版已覆盖 musl TLS 下受控 SIGSEGV 的 worker 清理；受控程序与并行测试仍不能扩展为通用 Linux 兼容性或强安全容器结论。
