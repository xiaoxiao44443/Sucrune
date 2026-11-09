# ARM64 ELF 加载与 ABI

## 当前 0.6.0 静态程序、exec 与 FD 路径

原有无 libc ET_DYN 入口保持窄格式约束。新增
`sucrune_elf_validate_program`／`sucrune_elf_load_program` 支持内嵌、可信的
ARM64 静态 ET_EXEC 与 PT_TLS；当前执行入口登记 musl-smoke 与 Lua。
不接受 PT_INTERP、PT_DYNAMIC 或运行时重定位，不开放任意文件导入。

固定程序由 Zig 0.17.1 链接工具链的 musl-based Linux libc，具有 4 个 LOAD、PT_TLS、
GNU_RELRO，固定基址 0x20000000。解析器验证页范围、程序头、TLS 模板和
入口等边界；固定地址预留必须精确成功，碰撞立即失败，不能使用 MAP_FIXED
覆盖已有宿主内存。4 KB／16 KB 解析通过不代表这两类设备都已执行通过。

musl 从初始栈的 argc/argv/envp/auxv 和已映射 PHDR 初始化自己的 TLS，
包含初始化数据与零初始化数据。只有 PT_TLS 的 p_filesz 部分需要可读取的 LOAD
及对应文件内容；p_memsz 中的零初始化尾部由 libc 分配，不要求整个 TLS 区域
占据 ELF 的 LOAD。加载器仍独立限制大小、对齐、整数溢出和模板范围；纯 TBSS
可在镜像末端或 LOAD 间隙声明，不能因此放宽非空模板检查。
SIGSYS 首先进入 `signal_gate.S`，在任何
C/Bionic 调用之前保存客体 TPIDR_EL0/x18 并切回宿主状态；返回客体时反向
恢复。退出路径恢复宿主上下文，后端核对 host_tls_restored。

客体线程阻塞可阻塞的异步信号；虚拟 rt_sigprocmask 记录不实现 POSIX
信号交付，致命异常不能作为正常客体退出。没有客体线程、fork 或客体
信号 handler。64 MiB 数据 arena 和指针权限检查见 [架构](architecture.md)。

0.3.0 已使用 Windows 上实际 `elf_loader.c`／`loader_tests.c` 的纯验证模式，通过原
26 项与新增 20 项负例，并接受 libc fixture 在 4 KB／16 KB 参数下的布局。
该模式不映射和执行客体。Android 结果单独记录于
[历史 libc 验证](validation/android15-libc.md)。本轮 Lua ELF 含仅零初始化的 TLS
（p_filesz=0、p_memsz=4）。本轮主机解析检查保留旧 ET_DYN 的 26 项拒绝测试，
静态程序扩展到 28 项负例及 5 项额外合法布局，4 KB／16 KB 参数均通过；实际
Lua 和 libc fixture 也均通过两种页大小的解析。设备回归单独记录，不能把解析
通过计为新程序已经在手机执行。0.4.0 在 Android 15 ARM64 4 KB 的独立设备回归
完成 37/37，详见 [Tools 历史验证](validation/android15-tools.md)；0.5.0 的 48/48
单独记录于 [Exec 历史验证](validation/android15-exec.md)。0.6.0 的 FD／重定向
实现与本版 60/60 设备验收见 [IO 验证](validation/android15-io.md)，仍无 16 KB 真机证据。

本版 execve 只替换三个固定内嵌程序。参数复制与路径检查在旧镜像有效时完成，
无效请求可返回旧代码；接受后经信号返回路径恢复宿主栈/TLS，再释放旧镜像、栈
和 arena，按目标 ELF 类型重新加载。musl/Lua 的固定地址不会与旧镜像同时保留，
也不会使用 MAP_FIXED 覆盖宿主映射。新初始栈包含新的 argv/envp/auxv/AT_EXECFN，
TLS 和 BSS 重新初始化；不是把旧 TLS 指针交给另一程序。

因卸载后的映射失败不能安全恢复旧指令，进入不可逆阶段后错误会终结为 failed/lost。
成功替换不返回到旧 Shell 或 libc 调用点。新过滤器在同一客体线程叠加，替换次数
限制为 32；原执行期限、取消、syscall 预算和最终清理链继续生效。详见
[架构中的镜像替换](architecture.md#同一执行内的镜像替换)。

0.6.0 不扩大 ELF 格式范围，增加的是同一执行内的 FD 语义：64 槽客体表独立于
ELF 映射，dup 别名共享打开对象及偏移；重建镜像时仅关闭带 CLOEXEC 的 FD。
Shell 对 fd 0/1 的真实 remap 因此可由下一镜像继承，临时备份带 CLOEXEC，不把
旧 Shell 栈中的恢复状态带入新 ELF。宿主输出 PFD 所有权与最终清理屏障不变。

## 保留的阶段二诊断实验

以下内容描述阶段二诊断夹具的历史接口和范围；其中“无客体 TLS”等限制只限定这一旧夹具，不代表上文静态程序路径。应用内当前用法见 [运行时说明](runtime.md)。历史验证文件不改写。

此实验将构建时内嵌的无 libc Linux ARM64 ELF 映射到一次性 Android 服务进程，由 CPU 进入它的 ELF 入口。客体通过标准 Linux ARM64 write 和 exit ABI 产生输出与退出结果，SIGSYS 处理器接收请求，再恢复宿主线程。

该诊断接口没有调用 execve，也没有运行 Android 系统命令来代替客体，只面向仓库内的可信夹具。它通过探针服务调用，与 Go 管理的 Shell/program 执行接口分开。

Android 15、ARM64、4 KB 真机上的 validation 构建已通过普通服务两次和隔离服务两次验证，见 [本阶段真机记录](validation/android15-arm64-elf.md)。

## 可接受的 ELF 范围

| 项目 | 当前限制 |
| --- | --- |
| ELF 头 | ELF64、小端、EM_AARCH64、ET_DYN |
| 程序形态 | 位置无关、无 libc 的受控夹具 |
| 不支持项 | PT_DYNAMIC、PT_INTERP、PT_TLS、非空重定位表及需要解释器的程序 |
| LOAD 段 | 至少可读，拒绝同时可写可执行；按页不重叠且有序，最低加载页为 0 |
| 入口 | 位于文件支撑的可执行段内，按 ARM64 指令对齐 |
| 大小 | 文件及映像受 16 MiB 上限约束，最多 16 个 LOAD 段、32 个程序头 |
| 夹具对齐 | p_align 为 16 KB，代码与数据分别位于 RX、RW 段 |

该范围不等同于“支持所有静态链接程序”。普通静态二进制可能是 ET_EXEC，或依赖 TLS、libc、额外系统调用和进程语义，均不在本实验的兼容承诺内。

程序头的文件范围、内存范围和对齐按 [ELF Program Loading](https://gabi.xinuos.com/elf/07-pheader.html) 的字段语义处理，同时应用本项目更窄的约束。

## 加载与执行流程

1. `elf_loader.c` 校验 ELF 头、程序头、段边界、权限与入口，生成加载计划。运行前的解析器自检先验证真实夹具在 4 KB 和 16 KB 参数下的布局，再用默认 4 KB 参数检查 26 个被修改的负例；负例不会被映射执行。
2. 预留匿名 PROT_NONE 内存，为各 LOAD 段临时开放 RW，复制文件内容，利用匿名页的零初始化构成 BSS，然后设置最终 RX 或 RW 权限。代码段还执行指令缓存同步。
3. 创建带保护页的客体栈，填入 argc、argv、envp 及辅助向量。当前参数为 `sucrune-hello`，环境为 `SUCRUNE=1`；辅助向量包含映射后的 PHDR、入口、页大小、身份和随机区等数据。
4. 原生工作线程建立备用信号栈、启用 no_new_privs，并叠加只针对客体映像地址范围的 seccomp 过滤器。系统已有过滤器继续生效。
5. `guest_entry.S` 保存宿主调用约定要求的状态，设置 16 字节对齐的客体 SP，跳到加载后的 ELF 入口。
6. 客体执行 write 时，在 SIGSYS 中将受限、已检查范围内的数据复制到 stdout 收集缓冲区，并把写入长度写回返回寄存器。
7. 客体执行 exit 时，处理器记录退出码，将信号上下文指向宿主恢复桩。先由 rt_sigreturn 退出信号处理，再由汇编恢复宿主 SP 和保存的寄存器。
8. 工作线程检查结果并退出。控制线程 join 后恢复 SIGSYS 处理器并释放映射；Android 监督方随后确认服务进程死亡。

匿名内存由 RW 转 RX 是否被允许，取决于实际 Android 配置。本路径在已记录的 Android 15 真机上实测成立，不能据此承诺所有版本、厂商和进程身份都可用。

## 客体与宿主 ABI

客体使用 Linux ARM64 的 write 64 和 exit 93。夹具预期 stdout 为：

```text
Hello from Sucrune ELF!
```

输出包含末尾换行，共 24 字节，退出码为 42。它在输出前检查 argc=1、argv/env 的最小布局、AT_PAGESZ、AT_ENTRY、AT_RANDOM、16 字节栈对齐、BSS 零初始化与可写 data。argv/env 检查覆盖首字符和终止布局，不是通用参数解析测试。

宿主恢复桩保存 AAPCS64 的 callee-saved 状态及浮点控制状态。栈对齐依据 [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)。这个旧夹具始终保留 Android 的 x18 和 TPIDR_EL0，不建立客体 TLS；新增 musl 路径使用上文汇编切换入口。Android 明确保留 x18 用于平台机制，见 [Android ARM64 ABI](https://developer.android.com/ndk/guides/abis#arm64-v8a)。

seccomp 的 TRAP 不执行原 syscall，而是交付 SIGSYS；恢复时通过信号上下文传回结果。该机制及过滤器叠加规则见 [Linux seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html)。

## 报告与验收

报告 probe 为 `arm64_elf`。核心证据包括入口执行、两个 LOAD 段、精确 stdout、exit_code=42、write_calls=1、exit_calls=1、trap_count=2、备用栈、宿主恢复、线程回收及处理器恢复。

`guest_argc` 和 `stack_alignment` 表示本实验的构造值；有效性由夹具内部检查和成功退出路径共同核对。`bss_zeroed` 也是依据可信夹具的成功路径得出，不是任意 ELF 的独立内存审计。

验证构建和安装方法见 [设备验证流程](device-validation.md)。安装 validation 主 APK 与匹配测试 APK 后运行：

```powershell
adb -s SERIAL shell am instrument -w -r -e probe arm64_elf -e expect_debuggable false com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

SERIAL 为占位符。每种身份运行两次，全部四例通过才算验收成功。缺少报告、unsupported、崩溃或未确认进程死亡均不能算通过。x86_64 只做解析和其他机制研究，ELF 执行入口明确返回 unsupported。

原 getpid 探针仍是默认项，回归时省略 `-e probe`，保留 `-e expect_debuggable false`。

## 边界与后续工作

客体与宿主共享地址空间，地址范围过滤可以被恶意程序绕开；加载器和指针范围检查都不是安全边界。目前只加载内嵌可信夹具，不开放任意 ELF 输入。

阶段二这个探针的结论只覆盖 hello 夹具，不证明通用静态程序、动态链接、客体 TLS、文件系统或多项目兼容性；后续能力须看各自的新验证记录。4 KB／16 KB 解析器正例通过不代表 16 KB 设备执行通过；原 26 个负例也没有形成完整 16 KB 负例矩阵。
