# ARM64 Linux 开发配置

Sucrune 在普通 Android 应用中加载项目自己的 Linux ARM64 ELF。
目前有 Android 15/API 35、4 KiB 页、非调试 APK 的真机证据；minSdk 29
是支持目标，Android 10 与 16 KiB 真机仍需分别验收。

## 调用与环境准备

`RuntimeClient.importFile(envId, path, input, expectedSize, sha256, executable)`
通过 64 KiB 缓冲导入最多 256 MiB 的普通文件。Kotlin 与 Go 分别校验字节数和
SHA256，临时文件完成后原子发布；权限由显式 executable 选择 0700 或 0600。
运行中的项目拒绝导入，路径不能指向 Android 宿主文件。

### 直接挂载项目目录

应用可给 `executePath` 传入 `workspaceDirectory: GuestDirectory`。需要先在项目根中创建
`/workspace` 目录。代理将客体访问该目录的请求交给目录提供方，普通文件用提供方返回的
原始 FD 进行读写。客体可以在此创建、读取、重命名文件，枚举子目录，亦可用相对路径
访问已打开的目录。项目已有的根文件系统继续提供程序、库及 `/tmp`。

提供方接收相对挂载根的 UTF-8 路径。目录的 `..` 按客体文件系统解析。
已打开的目录身份在再次使用时校验，底层目录被替换会报错。挂载及文件描述符随
`fork` 和 `exec` 继承，外层只读策略继续生效。客体可以对 `/workspace`
或其上级添加 Landlock 规则，挂载内部单独路径的规则返回 `EOPNOTSUPP`。
文件操作受宿主授权和提供方能力约束。跨挂载重命名返回 `EXDEV`，
挂载内不支持链接、修改 POSIX 权限或显式设置时间戳。

准备好 Node、它声明的 PT_INTERP、动态库和所需数据文件后：

```kotlin
val id = client.executePath(
    projectId, "/usr/bin/node", listOf("-e", "console.log(6*7)"),
    env = listOf(
        "LC_ALL=C.UTF-8", "LANG=C.UTF-8",
        "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu",
        "SUCRUNE_MEMORY_POLICY=linux-jit"
    ),
    timeoutMs = 30_000
)
val record = client.waitFor(id, 35_000)
```

argv 不包含 argv[0]；cwd 是项目内绝对路径。`executePath` 的 stdin 是最多
1 MiB 的有限字节流，写完即 EOF。
`executePath` 尚无终端 UI 和跨 App SDK；`executeProgram` 的固定程序接口保持不变。
Go 活跃执行索引与历史持久化的关系见 [管理索引说明](manager-active-index.md)。

需要请求与响应交替进行时，使用 `executePathInteractive`；它沿用 path、argv、env、
cwd、timeoutMs 参数并返回执行 ID，初始输入为空且保持打开。`writeInput(id, bytes)`
复制整块输入后入队，返回接受的字节数；这不等于已写入内核，更不等于客体已消费。
每次执行累计最多接受 1 MiB，超限整块拒绝。`closeInput(id)` 首次关闭返回 true，
排空已接受的输入后发送 EOF；仍在表中的已关闭输入返回 false。已经回收的 ID
返回 `not_found`。一次性执行拒绝这两个输入操作并返回 `input_mode`。

关闭后的写入返回 `input_closed`，超过累计预算返回 `input_limit`；失败不接受
部分数据。输出继续通过 `getExecution` 或 `poll` 读取。取消、超时、客体关闭读端
或退出会结束写入任务并丢弃未发送数据，四个清理条件全部满足后才释放项目。
输入内容不进入执行历史；交互执行保存输入模式与预算，结果区分接受和写入计数。
这不是 PTY，也不能在 Android 杀死管理进程后恢复会话。

`prepare-linux-rootfs.ps1` 构造固定版本的测试 rootfs；DSH 的离线包与安装器见
[目标与准备流程](node-dsh-target.md)。离线预置和客体解包不表示手机内的
`npm install`、安装脚本或所有包管理命令已经通过。

## 客体 Landlock

ARM64 Linux 程序可以通过 `landlock_create_ruleset`、`landlock_add_rule`、
`prctl(PR_SET_NO_NEW_PRIVS)` 和 `landlock_restrict_self` 安装文件访问规则。
版本查询返回文件系统 ABI 3。项目文件代理按目录和文件身份检查权限，保留打开时的
截断权限。后续规则与已生效的规则取交集。项目边界始终生效，一个项目内的规则只能
进一步收紧这个项目的权限。[Linux 接口语义](https://docs.kernel.org/userspace-api/landlock.html)

当前支持单线程安装，新建线程、fork 子进程和 exec 后的程序继承已生效的规则。
已有多个活动线程时，单独给一个线程安装规则会返回 `EOPNOTSUPP`。
网络由宿主的项目网络策略控制。ABI 3 的权限位覆盖文件内容和目录项操作，
chmod 等元数据操作沿用项目原有的权限检查。
虚拟 `/dev/null` 可单独授权，其他虚拟设备沿用对 `/` 的授权。受限进程通过
`linkat(AT_EMPTY_PATH)` 创建硬链接时会收到错误。

宿主可以给 `RuntimeClient.executePath` 传入 `TrustedExecutable(guestPath, bytes)`，
为一个确定的绝对执行路径指定静态 ARM64 ELF。Sucrune 使用密封的字节快照，并检查
项目原文件的执行权限。普通的文件读取继续读取项目内容。Android 仪器测试
`-e probe landlock` 覆盖嵌套规则、已打开的 FD、fork/exec、软链接及同名程序替换。

## 执行与内存

Kotlin 隔离服务启动 APK 内的原生 PIE runner，避免 ART 与固定地址 ET_EXEC
冲突。runner 不加载 Go 或 ART；Linux 指令由 ARM64 CPU 执行。上游动态链接器
自行重定位，文件、解释器和库都经项目 broker 解析。

客体拥有一块稀疏地址保留区，必要时另有精确 ET_EXEC 区间。逻辑 VMA 描述
实际映射和权限；MAP_FIXED 只能替换客体已有区间。完整客体区间都受 syscall
过滤，包括后续动态库和 JIT 代码。64 GiB 地址保留不是物理内存配额。

默认 W^X。显式 `SUCRUNE_MEMORY_POLICY=linux-jit` 允许主客体区间的匿名 RWX
映射，并在 native 结果中记录 `memory_policy`。文件快照和 ELF 段仍拒绝 W+X。
Node `--jitless` 已在默认策略下验证；普通模式的 JIT 通过实际 TurboFan 编译
和计算结果验证。该选项及本运行时都不构成已审计的恶意代码隔离边界。

## 已验证的主要行为

- 原版 Debian 动态 hello、glibc、PT_INTERP 和 UTF-8 argv。
- 真实 Linux pthread/TLS/futex、并发创建与 join、自身信号处理和 rt_sigreturn。
- 管道、eventfd、epoll、向量 I/O、FD 别名及关闭后复用。
- Node 同步与异步文件、ESM、Unicode 路径和参数、timers/promises、crypto、
  worker_threads、共享 Atomics、JIT，以及两个独立 UID/PID 的项目同时运行。
- 真实 Node 解压并逐文件验证 SDK 依赖、检查 gzip CRC/EOF 后发布目录。
- 原版 DSH CLI version/help、require-builtin 原生扩展调用，以及 `sdk-minimal`
  启动、配置生成、无未激活插件警告和有限 stdin EOF 后正常退出。
- 交互式 Node 大块输入、两次请求/响应及显式 EOF；原版 DSH SDK 在 stdin
  保持打开时响应 `initialize`，随后响应 `shutdown` 并正常退出。协议验证没有
  发起模型或工具请求，具体证据见 [SDK 验证说明](linux-sdk-protocol-validation.md)。

正常退出要求真实宿主线程 join；exit_group 尚有活动线程时，runner 直接终止
整个进程，结果明确记录 `process_exit_group`。父级 waitpid 加输出 EOF、broker
结束和 stdin feeder 完成后才能释放项目，不伪造 thread_joined 或信号恢复。

## 执行限制与历史覆盖

Linux 路径执行每个客体进程有 1,024 个 FD 槽位，系统调用累计次数只用于诊断。普通命令默认可运行 30 分钟，显式声明的常驻进程无固定期限。
客体最多有 63 个子线程槽（join 后可复用）。Android 管理层合计允许四次活动执行，每个项目可有一个普通命令及多个常驻服务。详见[执行配置](api.md)。
期限与取消由 Android 监督器强制终止 runner，不依赖客体主动进入 syscall。
这个机制仍依赖 Android 调度监督进程。本机曾在测试 App 不处于前台时出现管理者、
worker 和 Java watchdog 一起不推进的现象；切回前台后恢复并执行超时处理。
当时标准诊断报告并未显示 cached/frozen，因此具体系统或 OEM 原因尚未确认。
长流程验收现使用显式 `-e keep_foreground true`，不承诺后台持续执行或停止调度时
仍能按墙钟即时终止；恢复后沿用原期限，不重新计时。

文件 mmap 目前是 MAP_PRIVATE 快照；共享写回、越过 EOF 的 SIGBUS、文件
MADV_DONTNEED 重载没有完整实现。`msync` 按逻辑 VMA 校验对齐、标志和完整覆盖，
包含 PROT_NONE 映射；对当前私有映射成功返回，不承诺共享文件写回。长度取整
或地址溢出保守返回 ENOMEM。信号覆盖标准的自身投递与返回，外部异步
信号、实时队列、作业控制、客体备用栈尚未完成。robust mutex owner-death、
通用 fork/exec、网络、PTY、符号链接跟随和完整 proc 文件系统仍有缺口。
`/proc/self/exe` 返回客体路径，不暴露 Android runner。
已接入现有本地 FD 的 getsockname/getpeername 和受限 getsockopt 查询，供 Node
正确识别 stdin；命名 UNIX 地址显式拒绝，不暴露宿主名称。这没有开放 socket
创建、连接或监听的客体调用。

上述网络与终端范围以及[0.7 逐轮证据](validation/android15-linux-progress.json)
描述初版 Linux 后端。0.8 已另行实测 Node DNS/TCP/TLS、PTY、交互 Bash 和
前台作业控制，见[进程与终端说明](linux-process-design.md)。跨项目读取、任意
宿主 proc 枚举以及任意符号链接跟随仍不开放。

0.8 的项目文件代理支持普通文件的逻辑硬链接，多个名称共享同一 inode 的
内容、权限及锁。对于原版 DSH 的文件发布和会话恢复，代理还实现了按已打开的
目录解析相对路径、`fchmodat` 和 `ftruncate`。截断只接受已打开的普通文件，
一次最多设为 256 MiB，大于此值返回 `EFBIG`。缩短或扩展不会改变已打开句柄的
偏移；扩展的区域读为零。权限修改只接受普通权限位，不允许设置 set-ID 位。
普通文件的 `read` / `pread` 可以在一次客体调用中读取最多 1 MiB：管理进程进行
一次内核读取，再按 4 KiB 传输已读数据。这样 Node 的 `fs.promises.readFile` 不会
把传输包边界识别为文件结尾。真实 EOF 仍然返回短读；`pread` 不移动共享文件偏移。
原版 DSH 的真实模型、工具、恢复及取消使用[单独的真机验收流程](run-dsh-on-device.md)。

独立的[网络能力测量](validation/android15-network-capability.json)已验证 Android 15
隔离服务能够收发主进程传入的 TCP FD，并对传入的未连接 FD 完成连接与 epoll
等待；直接创建 socket、listen 和 accept 被拒绝。该探针不是 Linux 客体网络支持，
SCM_RIGHTS、独立 native runner、DNS 与外网仍未验证。后续实现见
[网络代理设计](linux-network-design.md)。
