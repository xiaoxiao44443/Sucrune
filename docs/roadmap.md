# Sucrune 阶段目标

当前版本为 0.6.0-io-preview。每阶段分别记录源码实现、主机检查与设备证据，不把编译通过当作设备功能通过。

## 阶段一：机制探针

已实现受控 syscall 陷阱、SIGSYS 写回、备用栈和清理，以及普通／隔离服务重复测试。Android 15 ARM64 4 KB 真机的 debug、validation 各 4/4 通过，见 [历史记录](validation/android15-arm64.md)。它只证明指定陷阱链成立，不代表全 syscall 拦截或安全容器。

## 阶段二：受控 ELF

已实现内嵌无 libc ARM64 ET_DYN 的加载、初始栈、真实 CPU 入口、write／exit 与宿主恢复。同一 Android 15 ARM64 4 KB 真机 validation 4/4 通过，输出和退出码准确，原 seccomp 回归 4/4 通过，见 [历史记录](validation/android15-arm64-elf.md)。

4 KB／16 KB 参数正例和 26 个默认 4 KB 负例是解析器验证，不是 16 KB 真机证明。尚不支持任意静态程序、动态链接或独立客体 TLS。

## 阶段三：Shell、文件与多项目预览

- [x] Go 核心接入主应用，ARM64／x86_64 c-shared；worker 不加载 Go。
- [x] 环境、字节文件 API、持久执行记录及 manager 重启时 lost 恢复。
- [x] 固定内嵌 ARM64 Linux Shell，受限语法、内建文件命令和脚本文件。
- [x] 每执行独立 isolated worker，按项目代理；全局四个、每项目一个执行。
- [x] 双流排空、限长、事件游标、查询、等待、取消与期限。
- [x] worker death、输出 EOF、broker completion EOF 三项结束条件。
- [x] 同应用 Kotlin API 与最小项目终端，未来 Agent 可复用。
- [x] Go 格式、vet、测试、CLI 构建通过。
- [x] Shell 主机解析／内建测试在 Windows 31/31 通过。
- [x] Android 双 ABI 构建、严格原生编译及 lint 通过。
- [x] Android 15 ARM64 4 KB validation 十组运行时集成验收，10/10 通过。
- [x] 外部 force-stop 的管理进程重启，两阶段各 1/1；Unicode 文件保持、旧执行 lost、项目可再执行。
- [x] 本版 seccomp 与受控 ELF 回归各 4/4，主界面和项目终端布局真机检查。

详见 [0.2.0 真机记录](validation/android15-runtime.md)。双项目用例实际重叠 1,996 ms；四项目上限是实现限制，不代表四项目性能已经测量。

本阶段验证可信 Shell 处理受控脚本、项目文件访问和进程生命周期，不是任意恶意 ELF 的安全审计，也没有完成性能基准。

## 阶段四：受控静态 musl 程序

- [x] Windows 原生 Zig 0.17.1 交叉编译使用 musl-based libc 的 Linux ARM64 程序，固定版本与下载摘要。
- [x] ET_EXEC/PT_TLS 加载、固定地址碰撞检查，不替换宿主映射；拒绝动态解释器与重定位。
- [x] SIGSYS 汇编入口切换客体／宿主 TLS 与 x18，退出恢复宿主状态。
- [x] 64 MiB 数据 arena、受限 brk/mmap/mprotect/munmap，readv/writev 和文件元数据等 syscall。
- [x] executeProgram、argv/env、项目终端程序模式、七组 program 验收代码，含真实异常清理。
- [x] 真实 ELF 构建／头部检查；Windows 实际解析器源码原 26 项、新 20 项负例通过，真实程序 4 KB／16 KB 参数布局通过。
- [x] 本版 Android 双 ABI Go/native/Kotlin 集成与 lint 通过。
- [x] 本版 APK 签名匹配、16 KB zipalign 和四个打包库 LOAD 对齐检查通过。
- [x] Android 15 program 七组、Shell 十组、恢复两阶段及机制回归全部通过，共 27/27。

结果见 [0.3.0 libc 验证记录](validation/android15-libc.md)，其中已更正工具链 libc 来源。两个程序 worker 原生区间实际重叠 2,001 ms；这不是性能基准。本阶段只完成受控 libc 程序通路，不开放任意 ELF；syscall 子集、无客体线程／子进程／动态链接／POSIX 信号交付等限制仍在。UI 与清理单独记录。

## 阶段五：Lua 与有限 stdin（0.4.0）

- [x] 固定官方 Lua 5.4.9 源码及逐文件摘要，静态构建、ELF 检查与许可证打包。
- [x] 正确接受纯零初始化 TLS；主机保留 26 项旧负例、扩展到 28 项静态程序负例与 5 项新增合法布局，实际两程序按 4 KB／16 KB 解析通过。
- [x] 原生内嵌程序目录统一提供 musl-smoke 和 lua，Kotlin 与 UI 使用同一目录。
- [x] executeProgram 接收最多 1 MiB 二进制 stdin；非阻塞写入任务和独占读端所有权。
- [x] 释放项目的条件增加 stdin 写入任务关闭并完成，不将已写入字节等同于已消费字节。
- [x] CLOCK_PROCESS_CPUTIME_ID 提供 Lua os.clock 所需的 worker CPU 时间。
- [x] 本版 Go 检查、Android 双 ABI 集成、lint 与最终 APK 签名／对齐／内嵌程序审计。
- [x] Android 15 Lua 脚本／模块／文件产物、stdin 背压、早关、取消和超时十组验收。
- [x] 本版 libc、Shell、重启恢复和机制回归；最终 APK 合计 37/37 通过。
- [x] 真机 Lua 终端 UI 检查、临时项目及设备 XML 清理。
- [x] 保存精简证据与最终产物，清理本轮截图、原始日志及中间结果；两 App 与数据保留。

Lua 是固定可信解释器，不新增任意机器码入口。有限 stdin 不是 PTY 或交互终端；
该阶段的 Shell 尚无 exec。源码实现和主机编译结果不替代相应版本设备证据。

详见 [0.4.0 真机记录](validation/android15-tools.md)。双 Lua 项目实际重叠 600 ms，
不是性能基准；Android 10 与 16 KB 真机仍待验证。

## 阶段六：固定程序 execve 替换（0.5.0）

- [x] 内嵌程序虚拟路径映射，只匹配 `/bin/lua`、`/bin/musl-smoke`、`/bin/sucrune-sh`。
- [x] execve 参数有界复制和预检查；失败返回原镜像，成功经宿主栈/TLS 重建镜像、栈和数据 arena。
- [x] 同一 PID/TID、cwd、剩余 stdin、虚拟信号掩码和非 CLOEXEC FD 偏移继承；提交时应用 CLOEXEC。
- [x] 同一执行和绝对期限、取消与四项清理条件；替换次数限 32，不新增 fork 或子进程。
- [x] Shell exec、全部变量导出、失败状态及继续语义；直接／继承重定向明确拒绝。
- [x] Shell 主机回归 44/44；NDK ARM64 freestanding 编译链接通过。mock 成功 exec 不执行 ELF。
- [x] 本版 Go 检查、Android 双 ABI 构建和 lint；lint 0 错误、3 警告。
- [x] Android 15 exec 十一组首次执行 11/11；双项目重叠 604 ms，原 3000 ms 期限实测 3050 ms。
- [x] 此前 37 项回归；本版完整应用身份验收 48/48，各套件 failed=0、code=-1。
- [x] 最终安装版本与项目终端 UI 检查，测试项目未遗留，设备临时 XML 已清理；无新增截图。
- [x] 最终 APK 签名、ZIP／四个 SO 的 16 KiB 对齐、三份内嵌 ELF 精确字节和独立设备日志审计。
- [x] 精简证据与最终产物归档；八份原始日志、中间 JSON、设备 XML 及检查 scratch 清理完成，两 App 与数据继续保留。

成功替换不会返回到原程序，不能替代 Shell 顺序运行多个外部命令所需的子进程
支持。PATH、shebang、动态链接、任意 ELF 导入和 fork 仍未实现。不可逆替换阶段
的资源失败终结执行，不承诺回滚。详见 [0.5.0 验证记录](validation/android15-exec.md)。

## 阶段七：共享 FD 与文件标准流（0.6.0）

- [x] 64 槽客体 FD 表与引用计数；客体编号、代理句柄、宿主 FD 分开。
- [x] dup/dup3、F_DUPFD/F_DUPFD_CLOEXEC、独立 CLOEXEC、共享偏移与 O_APPEND。
- [x] 最低空槽复用，包括 0/1/2；满表 open 在文件副作用前返回 EMFILE，错误 dup3 不修改目标。
- [x] stdin 最后一个引用关闭后释放读端；输出 PFD 继续归 Kotlin 最终清理。
- [x] Shell 每命令最多一个 `<` 与一个 `>`／`>>`；先展开路径、按出现顺序真实 remap。
- [x] 返回及部分失败恢复标准流与原标志；exec 继承重定向并关闭包括嵌套层的全部备份。
- [x] cat 无参数／`-` 读取 stdin；重复重定向、FD 语法、here-doc 明确拒绝。
- [x] Shell 主机回归 72/72；纯 FD 所有权测试 10/10；严格 ARM64 Shell 编译链接。
- [x] 原生 broker 功能测试在 Android 15 adb shell／UID 2000 通过，独立于应用身份验收。
- [x] 新增 `probe=io` 十二组集成代码，调整旧 exec 的重定向预期。
- [x] 本版 Go 检查、完整 Android 双 ABI 构建及 lint。
- [x] Android 15 同一 APK 的 IO 12 项与已有 48 项回归，共 60/60 应用身份验收。
- [x] 200 条重定向无备份泄漏；双项目独立文件流实际重叠 602 ms，不作为性能基准。
- [x] 最终设备版本及项目终端空列表核对，设备临时 XML 已删除，两 App 继续保留。
- [x] 最终 APK 签名／对齐／内嵌 ELF 独立审计，重编译六个关键原生对象与构建产物逐字节相同。
- [x] 最终两份 APK、Shell 和更新的 musl-smoke ELF 归档；Lua 字节保持不变。
- [x] 原始日志独立审计：九套结果合计 60 个唯一 PASS／成功事件，failed=0、code=-1，无 runner／清理错误；五份精简检查 JSON 归档。
- [x] Shell、FD 与独立产物／broker 检查 scratch 已清理，精简检查记录保留。
- [x] 本轮九份应用原始日志清理完成，确认目录不存在；保留两 App、签名密钥和持久执行历史。

本阶段没有实现 Shell 管道、任意 FD 语法、PTY、fork、wait 或动态链接，也没有
开放任意程序。Shell mock 与纯 FD 测试不执行 Linux 客体；UID 2000 的 broker
测试不证明应用或隔离服务权限。设备结果以 [0.6.0 验证记录](validation/android15-io.md)
为准，旧版 48/48 不自动转为本版通过。

## 阶段八：ARM64 Linux 与 Node 开发配置（0.7 开发中）

- [x] 项目内 ELF/PT_INTERP 加载、上游 glibc 与动态库；独立原生 runner。
- [x] 客体 VMA 与指针范围检查、受限内存调用、默认 W^X 和显式 Node JIT 策略。
- [x] 真实 pthread/TLS/futex、标准自身信号、pipe/eventfd/epoll 与退出清理。
- [x] 原版 Linux Node 的文件、ESM、Worker、Atomics、定时器、加密和 JIT；双项目并行。
- [x] 原版 DSH CLI、原生扩展、由客体 Node 验证安装的完整 SDK 测试依赖。
- [x] SDK profile 启动、有限输入 EOF 退出、交互式 initialize/shutdown 实际响应。
- [ ] DSH 模型调用、工具执行、Web、通用子进程、网络与包管理工作流。
- [ ] 后台运行保障、更多 Android 版本/页大小和长期压力测试。

新配置不替代前述历史版本的证据。最新通过项、失败轮次及回归范围见
[Linux 开发证据](validation/android15-linux-progress.json)，接口与限制见
[Linux 配置](linux-profile.md)。网络探针仅用于测量 Android 权限，尚未实现
客体网络；SDK 初始化成功也不表示完整 Agent 工作流已经通过。

## 后续验证与扩展

- Android 10 基线、x86_64 AVD 探针、16 KB 真机和更多厂商内核。
- 实际 Linux CTest、符号链接测试及 CI 结果；Windows 无法创建符号链接时明确跳过。
- Activity 真正退后台、系统回收、更多原生异常类型、资源耗尽和长期反复运行；本版已覆盖 musl TLS 下受控 SIGSEGV 清理。
- 更多 syscall、通用子进程与 exec、共享文件映射、网络和 PTY。
- 选定 Shell／Python／Node.js／Git 与包管理工作流，不笼统承诺任意发行版兼容。
- 强制资源限制、调用者授权、跨应用 SDK、恶意代码隔离验证。
- 在 1、2、4 个项目下记录耗时、内存、失败与设备状态，再决定优化方向。

Agent 接入保持独立：先通过客户端完成导入字节、执行脚本、查询和导出产物，再增加模型工具适配，不为每个项目复制 Agent。
