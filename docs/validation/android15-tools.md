# Android 15 ARM64 Tools Preview 验证记录

日期：2026-11-07。版本：0.4.0-tools-preview。

**最终不可调试 validation 构建真机验收 37/37 通过，失败 0。**
Go、Android 双 ABI 构建、lint、解析器、签名及对齐检查已完成，UI 已检查。
临时项目、恢复回执、截图、原始日志和设备 XML 已清理；应用和持久执行历史保留。

## 变更范围

加入官方 Lua 5.4.9 的固定 ARM64 静态 ELF、原生程序目录和最多 1 MiB 的有限
二进制 stdin。Lua 支持项目脚本、纯 Lua 模块及文件产物；无动态 C 模块、外部
进程、网络、PTY 或任意 ELF 导入。Shell 保留独立入口，尚无外部命令启动功能。

stdin 使用独占读端与非阻塞写入任务；worker 的 Kotlin 层把读端所有权交给
native，guest close(0) 不留下隐藏的重复读端。管理者逐次发送使用
MSG_DONTWAIT | MSG_NOSIGNAL，
检查取消、期限与 worker 状态；终态必须等待写端关闭和任务完成，连同 worker
停止、输出 EOF、文件代理完成共四项结束条件。已排入 socket 与客体已读取的
字节数分别记录，早关或忽略输入允许只消费前缀。

Lua 使用原版上游源码，链接的是 Zig 0.17.1 的 musl-based Linux libc；该 libc
包含 musl 与 Zig 的实现。来源澄清与旧 ELF 的符号核验见
[0.3.0 记录中的更正](android15-libc.md#libc-来源更正2026-11-07)。

## 已完成主机检查

- Lua 5.4.9 官方源码压缩包 SHA-256 核对通过，源码及逐文件摘要已纳入项目；
  构建前重新核对源码，无 Sucrune 补丁。
- 两个 Linux ELF 静态构建及头部检查通过：AArch64 ET_EXEC、固定基址
  0x20000000、四个 16 KB 对齐 LOAD，无 PT_INTERP、PT_DYNAMIC 或重定位。
- Lua 为 361,072 字节，SHA-256 为
  `B875009D96A419F9CA3881FDB0464CBA11379944207F4E8FF15A0E8643B763D7`。
  新增 FD 0 早关模式后的 musl-smoke 为 45,368 字节，SHA-256 为
  `F3FAC5AFB0C0F66C499F3C04A5A9ADF36D9140CEB58540EFFEC67FB59E410E36`。
- 实际解析器测试保留旧 ET_DYN 的 26 项负例，静态程序有 28 项负例及五项新增
  合法布局；4 KB／16 KB 参数均通过，两份实际 ELF 也通过这两种布局检查。
- Lua 的 PT_TLS 只有四字节零初始化数据。加载器检查已修正：仅 p_filesz 的
  模板要求可读取 LOAD 和文件内容；独立检查 p_memsz 的大小、对齐与溢出。
- Android 双 ABI Go/native/Kotlin 及测试 APK 的最终集成构建成功，用时 38 秒。
  lint 为零错误、三个现有警告，涉及备份配置、Context 和国际化。
- Go 格式、vet、测试与开发 CLI 构建通过。
- musl、Zig、Lua 许可证与来源说明保留在源码和 APK assets 输入；历史 libc
  来源已用最终 ELF 的代码字节、符号和 DWARF 核验，更正了整体“未修改 musl”描述。
- 最终 APK 内两份客体 ELF 与构建产物逐字节匹配；musl 来源说明和 Lua 许可证／
  来源说明与当前源码一致。四个 ARM64／x86_64 共享库 LOAD 均按 16 KB 对齐。
- 主 APK 与测试 APK 的 v2 签名验证通过，证书相同；两者 16 KB zipalign 通过。

上述检查没有在 Windows 上运行 Linux ELF，也没有在 16 KB 真机执行。

## 本版设备验收

使用 Android 15/API 35、ARM64、4 KB 真机，不可调试 validation 构建，
minSdk 29、targetSdk 37。未使用 root，不记录真实设备序列号。

首轮 tools 为 9/10。失败来自测试误以为 Lua 能关闭标准输入文件对象；上游 Lua
明确拒绝关闭标准文件。改用可信 `musl-smoke --close-stdin-loop` 执行实际 close(0)，
随后在 CPU 循环中保持存活，检查管理者写入任务已结束，再取消并复用项目。
用例更名为 tool_ignored_and_closed_stdin；Lua 本身仍保持上游源码不变，测试总数
仍为十组。首轮失败没有计入成功结果；下表全部结果来自修正后的最终 APK。

同时，lint 指出 Os.fcntlInt 需要 API 30，与最低 Android 10/API 29 冲突。
写入路径已改为逐次 MSG_DONTWAIT | MSG_NOSIGNAL，不改变 socket 的 O_NONBLOCK
状态；保留有限 poll、取消与期限检查。最终 lint 与本次设备回归均通过；
这不代替 Android 10 真机执行。

| 套件 | 预期条目 | 当前结果 |
| --- | --- | --- |
| tools | 10 | 10/10 通过 |
| program | 7 | 7/7 通过 |
| runtime | 10 | 10/10 通过 |
| runtime_recovery prepare | 1 | 1/1 通过 |
| runtime_recovery verify | 1 | 1/1 通过 |
| seccomp_sigsys_return | 4 | 4/4 通过 |
| arm64_elf | 4 | 4/4 通过 |

各项检查与命令见 [设备验证](../device-validation.md)。已核对每个 suite 的总数、
failed=0、INSTRUMENTATION_CODE=-1，以及精确输出、退出码和清理证据；没有仅凭
adb 进程返回值计为通过。Lua 的函数／循环／模块／文件产物、1 MiB 含 NUL 输入
往返、有限输入 EOF、忽略输入、实际 FD 0 早关、背压下取消与超时均通过。

Lua 双项目原生执行区间实际重叠 **600 ms**，worker PID 22529/22545、隔离 UID
99352/99353；同名文件保持各自内容。它证明该用例确实并行，不是性能基准，
不表示四项目已测、零开销或硬件资源互不影响。

## 最终集成、UI 与清理

最终主 APK 为 8,742,707 字节，SHA-256 为
`EA7CE3555B606E6B17D697869C2AEB2126686661F0528CD76261037175942BA5`；
测试 APK 为 110,228 字节，SHA-256 为
`0C7E121103106A5EDB282197AED699EC07AA8CA8240A4F5D3C8205E7CDE357BA`。
独立产物审计同时核对版本、minSdk、原生目录／JNI 入口、内嵌程序及解析器输出。

两个 APK 使用相同签名执行 install -r，均返回 Success；应用数据保留。
已查看真机项目终端截图：选中 Lua 5.4.9，argv 为 `-`，stdin 显示 Hello 示例，
字段没有重叠。项目选择区显示“请先新建项目”，本轮临时项目未遗留。
该检查不替代完整交互、真实退后台或系统回收测试。

最终精简验证记录与产物已保存到 `.build/artifacts`：
`tools-verification.json`、`sucrune-tools-preview.apk`、`sucrune-tools-tests.apk`、
`sucrune-lua.elf` 和 `sucrune-tools-musl-smoke.elf`。旧版产物保持原名与原摘要。

独立审计核对 37/37 后，已删除本轮 `.build/device-results/tools-20261107`，
包括八份原始日志（含首轮失败）、中间套件 JSON 和截图；设备临时 XML 确认不存在。
测试项目已删除，恢复测试确认回执已删除。两个安装包的 pm path 仍存在，按用户
要求保留主 App、测试 App、匹配签名密钥、应用数据和持久执行历史。
未卸载、未执行 pm clear，也未删除其他项目数据。

## 结论边界

本版仍只加载固定可信机器码。允许 Lua 脚本不代表已审计恶意脚本或字节码；
项目路径代理与 syscall 子集也不等于通用恶意 ELF 安全容器。64 MiB 数据 arena
不是整个 worker 的 RSS 配额。Lua os.clock 使用 worker 进程 CPU 时间，不是
独立客体计费；异步客体信号、fork、线程与动态链接仍不支持。

Android 10、16 KB 真机、x86_64 客体执行、更多厂商、长期后台运行、低内存回收
与性能基准均不能从这次单机回归推导，需另行验证。
