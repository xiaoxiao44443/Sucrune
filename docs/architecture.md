# Sucrune 架构

Sucrune 独立提供项目环境、文件与执行能力。Agent 是未来的客户端，不参与底层进程生存期管理；一个 Agent 可以复用多个项目环境。

## 当前分工

0.6.0-io-preview 最低 Android 10／minSdk 29，无 root。ARM64 执行内嵌 Shell、musl-smoke 或 Lua，并可在同一执行内通过 execve 替换这些固定镜像；本版加入共享 FD 表和标准流真实重映射。x86_64 用于管理层构建和探针研究，不执行 ARM64 客体。

```text
同应用客户端 / 项目终端
        │ RuntimeClient
        ▼
主应用管理进程：Kotlin 监督器 + Go c-shared 核心
        │                    │
        │ Binder 控制        └─ 持久环境、文件与执行记录
        ▼
每次执行独立的 isolated worker（不加载 Go）
        │ 内嵌 Linux ARM64 ELF（Shell、libc 检查程序或 Lua）→ syscall → SIGSYS 汇编入口
        ├─ stdin ← 管理进程有限输入任务；非阻塞写入、关闭后 EOF
        ├─ stdout / stderr → 管理进程持续排空
        └─ 有界 socket 消息 → 管理进程文件代理 → 项目 workspace
```

Go 负责持久数据、路径规则、执行占用与终态提交；桥缓存同目录的单一 Service。Kotlin 创建和监督 Android 服务、处理超时与取消、汇总输出。C/汇编负责 ELF、初始栈、TLS/信号切换、寄存器恢复、受限内存和文件代理。Zig 工具链在主机编译静态客体；其 musl-based libc 包含 musl 与 Zig 的实现，部分 Zig 实现（如分配器）随客体链接，不加载 Zig 编译器。

## 项目与执行分离

```text
dataDir/
  environments/env_<32hex>/
    environment.json
    workspace/
    dependencies/
  executions/exec_<32hex>/
    initial.json
    terminal.json       # 完成后原子发布
```

项目创建只准备目录，不启动常驻 Linux 系统，也不安装 rootfs。`dependencies` 是保留目录，当前不含包管理或工具安装逻辑。删除项目清除其文件，终态执行历史仍可查询。

Catalog 元数据中的 `state=stopped` 表示持久环境本身没有常驻客体进程；运行时的 `env.get/list` 根据活动执行投影出 `running`。执行的真实生命周期以 `exec_*` 记录和监督器证据为准。

每个项目最多一个普通执行，可同时容纳显式常驻的 Linux 服务。Android 管理者全局提供四个并发槽，每次普通执行与常规常驻服务各占一槽。宿主显式声明的同一常驻服务可以为不同写策略共用一槽，详见[执行 API](api.md)。创建执行记录取得占用权，随后由 Kotlin 启动 worker。终态为 exited、cancelled、timed_out 或 lost。目录中先写完整临时文件、同步内容，再重命名发布。

## 结束与恢复

取消和超时会请求终止独立 worker。释放环境前检查四项：worker Binder death（或确认 RUN 从未发送）、双输出流 EOF、文件代理 completion EOF、stdin 写入任务关闭并完成。

stdin 限定为调用时复制的最多 1 MiB 字节流，不通过 Binder 传输大字节数组；Binder
只传递 socket 的读端。worker 将读端所有权交给 native；客体可通过 dup 保留明确的
别名，最后一个引用关闭时才关闭该读端。close(0) 不能关闭其他仍存活的客体别名，
管理者与 Kotlin worker 均不保留隐藏的重复读端。管理者单独拥有写端，采用逐次
send 的 MSG_DONTWAIT/MSG_NOSIGNAL 与有限 poll，检查取消、期限、worker 死亡和结果；写端关闭后
才报告任务完成。背压仍存在，但不应让阻塞 write 阻止取消。输入只记录大小与摘要，
记录的已写字节数不保证已被客体消费。此路径不使用 Android API 30 才提供的
Os.fcntlInt，保持 Android 10/API 29 基线；这仍需 Android 10 设备单独验收。

文件代理运行在管理进程中，worker 死亡时可能仍有排队或进行中的文件操作。代理只有关闭全部文件及根目录 FD 后才发出完成 EOF，因此它是独立的结束条件。未确认清理时保留 running 占用，不把“已发送取消”当作“已停止”。

管理者按应用生存期运行，没有承诺后台保活。主应用被系统杀死后，重新 Open 会把历史 running 标记 lost；不重新发送脚本，不恢复进程。已落盘文件继续存在，未提交的实时输出可能丢失。Activity 或轮询订阅退出本身不会停止管理进程中的排空线程。

## 文件边界

客户端路径中的 `/` 代表项目 workspace。Go 文件 API 拒绝 `..`、反斜杠、符号链接和特殊文件；客体代理允许项目内部的 `..`，拒绝跨越项目根，并逐层使用目录 FD 与 `O_NOFOLLOW` 解析路径。客体程序使用虚拟文件编号。Linux runner 打开只读普通文件时，代理可通过原有 Unix 套接字在同一条打开应答里传递一个只读宿主 FD。代理和 runner 引用同一打开文件描述，顺序读与代理上的 lseek 共享偏移，pread 保留偏移。runner 将这个 FD 限于内部使用，并继续校验客体内存。Android 未交付 FD 或拒绝直读时，runner 仍可通过原代理句柄读取。

内嵌程序模式提供可信 Shell、musl-smoke 和 Lua。Lua 可解释项目脚本，尚未审计恶意脚本或字节码；这些检查不能推导出任意恶意 ELF 的安全隔离。管理进程拥有项目目录，其他同 UID 代码不得竞争修改目录、移动根或制作指向外部数据的硬链接。跨进程锁、整体资源配额和恶意客体验证尚未实现。

## 描述符与标准流

内嵌工具的客体 FD 表有 64 槽，Linux 项目程序有 1,024 槽。FD 项保存独立的 CLOEXEC
标志，并引用带计数的资源。资源代表原 stdin、stdout、stderr，或文件代理中的
一个打开对象。客体 FD、代理句柄和宿主 FD 三者分开，不能直接互换。

dup(23)、dup3(24)、fcntl 的 F_DUPFD/F_DUPFD_CLOEXEC 只添加资源引用，不重新
打开路径或复制文件内容；因此别名共享同一个文件偏移及 O_APPEND。F_GETFD/
F_SETFD 操作每项的标志；F_GETFL 查询共享状态。代理普通文件和目录支持修改
O_APPEND/O_NONBLOCK，并将客体选择与内部强制非阻塞标志分开；O_ASYNC 尚未实现。
Linux 配置还支持本地 pipe/eventfd/epoll，详见 Linux 开发配置。dup/新增 open 使用最低空闲槽，可复用
0/1/2；满表返回 EMFILE，文件打开前先检查槽位，避免容量失败仍创建或截断文件。
dup3 在替换前验证源、目标和 flags，同号返回 EINVAL，不破坏原目标。

关闭一个别名只减少引用，最后一个引用才释放对应资源。代理文件在管理进程关闭，
原 stdin 读端由 native 关闭；stdout/stderr 的宿主 PFD 仍由 Kotlin 持有，到 worker
最终清理才关闭。客体虚拟关闭输出不提前冒充管理者已观察到输出 EOF。文件型 FD
即使编号为 0/1/2，也按文件资源执行读写、seek、stat；标准流别名换到其他编号也
继续保持原流的读写权限和非 seek 语义。

Shell 对每条命令最多接受一个 `<` 与一个 `>`／`>>`。先完成语法检查及两条路径
展开，再用 F_DUPFD_CLOEXEC 保存所有受影响的标准 FD，依源顺序 open/dup3。
所有 builtin 直接操作真实 fd 0/1，没有单独传递的替代输出通道。返回、失败 exec
或部分设置失败都会恢复映射、原 FD 标志和原本关闭的状态；恢复失败则终止脚本。
成功 exec 保留当前标准流并关闭所有备份，包含外层嵌套 Shell 保存的引用。输出
创建／截断已经完成的副作用不回滚。描述符语法、重复重定向、here-doc 和管道仍
显式拒绝，未新增子进程或交互 PTY。

## 兼容范围

Shell 保持无 libc、无重定位的 ARM64 ET_DYN。程序入口接受原生目录中登记的内嵌 musl-smoke 和 Lua：静态 ET_EXEC、PT_TLS、固定虚拟地址，无 PT_INTERP/PT_DYNAMIC 或运行时重定位。先保留目标地址且确认未碰撞；不可使用 MAP_FIXED 覆盖宿主映射。musl 保留原始启动逻辑，从 PHDR/auxv 初始化自己的 TLS。

SIGSYS 汇编入口先保存客体 TPIDR_EL0/x18、切回宿主状态，再进入 C 处理器；处理结束切回客体，正常退出则恢复原宿主 TLS 与调用约定。客体执行期间阻塞可阻塞的异步信号。rt_sigprocmask 的虚拟 bookkeeping 不承诺 POSIX 信号交付；没有客体信号 handler、客体线程或 fork，致命异常由 worker 终止路径处理。

## 客体内存与 syscall 范围

### 同一执行内的镜像替换

execve 只匹配原生目录中的 `/bin/lua`、`/bin/musl-smoke`、`/bin/sucrune-sh`，
路径不经过宿主 exec，不导入项目 ELF，也不解析 PATH 或 shebang。Shell 仍走
ET_DYN 加载，libc/Lua 走静态 ET_EXEC 加载；每个目标都使用同一套权限检查。
三个路径精确匹配，不跟随符号链接或规范化路径；它们没有安装成项目 `/bin`
里的文件。open/stat 仍由项目代理处理，exec 不读取同名项目文件内容。

陷阱处理器在旧镜像有效时检查指针并复制 argv/envp，保存到有界的宿主状态区；
该阶段不分配内存、不改变映射或描述符。请求错误以 errno 返回，旧镜像可继续。
已接受的请求经 signal-return 和汇编恢复回宿主栈/TLS，再卸载旧镜像、客体栈及
数据 arena，映射目标并构造新的初始栈。固定 ET_EXEC 共享地址，所以开始卸载
后不能承诺回滚；后续加载、内存或代理错误终止执行，native failed 对应管理层 lost。

成功替换保留同一 PID/TID、项目 cwd、剩余 stdin、虚拟信号掩码、非 CLOEXEC
描述符及其偏移；提交时按客体 FD 表逐项关闭标记 CLOEXEC 的描述符，未标记的
别名继续持有共享资源，只有最后一个引用消失才关闭底层对象。标准流也应用
对应关闭语义。stdout/stderr 的宿主 PFD 仍归 Kotlin worker 持有，到最终清理才
关闭；虚拟关闭不冒充宿主输出流立即 EOF。新镜像重新初始化 BSS、TLS 和数据
arena，clear-child-tid 等旧镜像私有状态不带入。

seccomp 过滤器不能从线程移除，每次成功替换为新映像安装过滤；最多替换 32 次，
系统调用累计次数用于诊断。管理者沿用同一 worker 和 execution，期限和取消
不重置，四项最终结束条件不变。原生报告保留初始 kind，另报 last_program、
exec_count/exec_limit 与 host_context_restores。计数是诊断证据，不是安全隔离证明。
原生结束报告另含 fd_limit、fd_peak、fds_live、resources_live，正常清理后后两项为
零；它们用于诊断资源释放，不能替代监督器的四项结束条件。

### 内存与其他调用

每次程序执行保留 64 MiB 数据 arena：前 8 MiB 用于 brk，后 56 MiB 用于匿名 mmap。页面按需开放；保留地址空间不是立即占用相同物理内存。mmap 仅接受私有匿名映射，拒绝可执行内存、文件映射和 MAP_FIXED。mprotect 仅改变 arena 已分配 mmap 页的 R/W/NONE 权限，不允许修改宿主、代码或栈；munmap 逻辑释放并保留地址预留，随后重新分配的内容应清零。

这些限制只约束被接管的内存 syscall，不是整个 worker 或 APK 的 RSS 配额，也不能抵抗可信范围外机器码直接访问共享地址空间。ELF、客体栈、管道、Go 和管理进程内存均另计。

处理范围覆盖固定程序的 writev/readv、文件元数据、受限 fcntl、内存、身份和时间等调用。clock_gettime 接受 CLOCK_REALTIME、CLOCK_MONOTONIC、CLOCK_PROCESS_CPUTIME_ID；后者供 Lua os.clock 使用，计量 worker 进程，不能当作独立客体 CPU 配额。set_tid_address 保存客体语义，不替换 Bionic 的宿主 clear-child-tid 地址。未实现的 syscall 返回 ENOSYS 并保留诊断计数，不回退到宿主命令。Lua 的 SIGINT 安装仍不受支持，由监督器提供取消。尚未实现任意程序导入、动态链接、子进程、网络、通用 rootfs 或包管理器。

匿名映射转为可执行、seccomp 和信号恢复依赖实际 Android 配置。4 KB／16 KB 解析器检查不等于对应设备执行验证。多个项目共享 CPU、存储和温控，四个并发槽位不表示零开销或性能互不影响。
