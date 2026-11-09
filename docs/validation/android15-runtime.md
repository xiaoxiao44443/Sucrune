# Android 15 ARM64 Shell Preview 验证记录

2026-11-07，0.2.0-shell-preview 的真实 Android 集成测试在 OnePlus PKR110 上完成：运行时十组全部通过；外部 force-stop 后的 prepare／verify 两阶段分别 1/1 通过。使用不可调试 validation 构建，本轮未把 debug 构建结果混入。

## 配置与范围

| 项目 | 本次配置 |
| --- | --- |
| 设备 | OnePlus PKR110 |
| Android | Android 15，API 35 |
| ABI／页大小 | ARM64，4 KB |
| 内核 | 6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k |
| 系统身份 | user build，ro.debuggable=0，SELinux Enforcing |
| 应用 | 0.2.0-shell-preview；minSdk 29，targetSdk 37 |
| 构建 | validation，debuggable=false，本地开发签名 |
| 权限 | 未使用 root，未改变系统设置 |

本版 Go c-shared 在主应用管理进程加载，独立 isolated worker 执行固定内嵌 ARM64 Linux ELF Shell。文件操作经过管理者的 workspace broker；不是在 adb shell 中运行 Android 命令代替客体。

## 运行时：10/10

通过的十组为：

1. 两项目并行与文件内容分离。
2. 文件 API、中文和 emoji 往返及跨项目不可见。
3. 脚本文件执行、跨 worker 文件保持和导出字节。
4. 引号、覆盖／追加重定向、条件连接与 cwd。
5. 管道明确失败、未知命令返回 127。
6. 超时终止、清理后项目复用。
7. 启动即取消、执行中取消和再次执行。
8. 事件游标、不持续订阅时输出仍完整保存。
9. stdout、stderr 各 64 KiB 保留上限、双流截断和持续排空。
10. workspace 路径边界、宿主 proc 路径不回退、活动项目执行／删除冲突。

并行用例的原生执行区间重叠 **1,996 ms**，worker PID 分别 7616、7630，隔离 UID 分别 99250、99251。这证明该用例确实同时执行，不能作为零开销或性能基准。

完成记录核对了隔离身份、不可调试标志、输出和退出结果，以及 Binder death、双流 EOF、文件代理 completion EOF。正常退出还检查宿主恢复、线程回收、原信号处理器恢复和备用栈。启动前取消允许记录 RUN 从未发送，而不是捏造 worker 死亡。

## 管理进程重启：prepare 1/1、verify 1/1

prepare 留下一次实际 running 执行、Unicode 文件与私有回执；外部 `am force-stop com.sucrune.probe` 后再运行 verify。管理进程 PID 从 8623 变为 8808。

旧执行恢复为 lost，reason=manager_restarted、process_resumed=false，没有虚构正常退出码。原请求和项目名称保留，Unicode 文件内容精确一致；同项目可以重新执行并读取产物。本次项目和恢复回执已删除。

这验证了受控 force-stop 后的重开路径，不是进程暂停后续跑，也不证明系统低内存回收或后台保活。未终结时尚在内存的实时输出不承诺保存。

## 主机与包检查

- Go 格式、vet、单元测试和 CLI 构建通过。
- Windows Shell 解析器／内建测试 31/31 通过，使用模拟 syscall 和部分 I/O。
- Go c-shared 与 native ARM64／x86_64 构建、严格编译检查及 lint 通过。
- APK 签名与 zipalign 检查通过，Go／probe 两 ABI 库的 LOAD 段对齐检查通过。
- Linux CTest 尚未执行；16 KB LOAD 对齐不等于 16 KB 设备已经通过。

本轮原 seccomp 回归 4/4、受控 ARM64 ELF 回归 4/4 通过。汇总为以下 **20/20 instrumentation 验收条目**，不是只启动了 20 个执行进程：

| 验收套件 | 结果 |
| --- | --- |
| runtime | 10/10 组 |
| runtime_recovery prepare | 1/1 |
| runtime_recovery verify | 1/1 |
| seccomp_sigsys_return | 4/4 |
| arm64_elf | 4/4 |

主界面和项目终端已在真实手机打开，并通过截图核对布局可用；这次手动检查没有创建用户项目，不等于 Activity 退后台或重建测试。

## 保留与清理

按用户最新要求，主 APK 和测试 APK 保留安装，后续使用相同签名 install -r 覆盖；不卸载、不执行 pm clear。测试创建的项目和恢复回执已经删除，应用内终态执行历史按 API 保留供用户查看。

本轮五份原始日志、两张临时截图及对应 raw 目录已删除，确认 .build/device-results 中没有残留条目。没有卸载应用，也没有执行 pm clear。

保留产物位于项目 .build/artifacts：sucrune-runtime-preview.apk、sucrune-runtime-tests.apk、sucrune-sh.elf 和 runtime-verification.json。这里只保存必要配置、结果计数和证据结论，不保存真实设备序列号、完整 fingerprint 或原始日志；后续复验需重新运行。

## 结论边界

结果支持这台 Android 15 ARM64 4 KB 设备上的可信内嵌 Shell、项目文件操作、多项目受控并行、取消与恢复语义。它不证明任意 ELF 安全隔离、POSIX／Bash 兼容、通用 Linux rootfs、外部工具或包管理器可用。

Android 10、x86_64 AVD 执行、16 KB 设备、Activity 退后台／重建、恶意代码、资源耗尽和性能测试仍未覆盖。复验命令见 [设备验证流程](../device-validation.md)。
