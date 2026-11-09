# Android 15 ARM64 libc Preview 验证记录

日期：2026-11-07。版本：0.3.0-libc-preview。

**本版不可调试 validation 构建的真机验收 27/27 通过，失败 0。**
Go、Windows 解析器、Android 双 ABI 构建、lint、签名和对齐检查通过。
本轮 UI 已检查，临时文件清理完成，应用和持久执行历史保留。

## 变更范围

新增固定内嵌的 `musl-smoke`，由 Zig 0.17.1 交叉编译并静态链接未修改 musl。
ELF 为 AArch64 ET_EXEC、基址 0x20000000、4 个 16 KB 对齐 LOAD、真实 PT_TLS；
无 PT_INTERP/PT_DYNAMIC 或重定位。musl 使用自己的启动和 TLS，不替换为 Bionic。

executeProgram 接收明确 argv/env，仍运行在独立 Android isolated worker 中。
SIGSYS 汇编入口切换客体／宿主 TLS 与 x18，退出恢复宿主状态。内存 syscall
约束于 64 MiB 数据 arena（8 MiB brk、56 MiB mmap），文件继续由项目代理处理。

## 已完成主机检查

- 官方 Zig Windows 0.17.1 ZIP 已按官方 SHA-256 验证，工具和缓存均在本地项目目录。
- fixture 编译成功；构建脚本核对 ELF 头、LOAD 权限／对齐、TLS 和无动态加载；
  NDK llvm-readelf 另核对无重定位。实际 SHA-256 与 PHDR 见 `.build/linux-programs/manifest.json`。
- Windows 用实际 `elf_loader.c`／`loader_tests.c`，在纯验证模式下通过原 26 项、
  新增 20 项负例，真实 musl ELF 的 4 KB／16 KB 参数布局通过。
- musl COPYRIGHT、Zig LICENSE 和来源 NOTICE 保留在源码及 APK assets 输入中。
- Android 双 ABI 的 Go/native/Kotlin 构建及 lint 通过。
- Go 格式、vet、测试和 CLI 构建通过。
- 两 APK 签名验证通过且证书匹配；16 KB zipalign 通过，四个打包共享库的 LOAD 对齐均为 0x4000。
- 最终 musl ELF 为 45,072 字节，SHA-256 为
  `F7668B8762A13A317042138D9C30EFC394546E9DD6BAD93F2198A6C7C4B362F3`；
  manifest 与源码一致，嵌入 APK 的 ELF 与构建产物一致。

这些检查没有在 Windows 上执行 Linux ELF，也没有运行 Linux CTest。

## 真机验收

使用 OnePlus PKR110、Android 15/API 35、ARM64、4 KB，
不可调试 validation 构建，minSdk 29、targetSdk 37。未使用 root 或修改系统设置，
不记录真实序列号。

| 套件 | 预期条目 | 当前结果 |
| --- | --- | --- |
| program | 7 | 7/7 通过 |
| runtime | 10 | 10/10 通过 |
| runtime_recovery prepare | 1 | 1/1 通过 |
| runtime_recovery verify | 1 | 1/1 通过 |
| seccomp_sigsys_return | 4 | 4/4 通过 |
| arm64_elf | 4 | 4/4 通过 |

program 的七组为 musl_tls_memory_files_utf8、program_cwd_and_shell_reuse、
parallel_program_workers、program_timeout_and_reuse、program_cancel_and_reuse、
program_fault_cleanup、program_request_boundaries。已核对退出码、Unicode、TLS 恢复、x18 跨陷阱保持、内存限制、文件及 FD_CLOEXEC 往返、并行
区间及释放项目之前的三项结束证据。命令与判断规则见 [设备验证](../device-validation.md)。

故障用例在 musl TLS 已安装时发生真实 SIGSEGV，worker 死亡且结果为 lost、
没有 exit_code/native 正常退出报告；两流 EOF 和 broker 完成后，同项目可再次运行。
这不等于支持客体信号 handler 或 POSIX 信号交付。

双程序用例的原生执行区间重叠 **2,001 ms**，worker PID 15446/15470、
隔离 UID 99287/99288；Shell 并行用例重叠 **1,997 ms**。不同 PID/UID 和时间
交叠证明该用例并行运行，不代表测得零开销、四项目性能或硬件资源互不影响。

真实 force-stop 恢复测试中，manager PID 由 16555 变为 16663；旧执行为 lost、
无伪造 exit_code，Unicode 文件保留，同项目再次执行通过。测试环境和恢复回执已删除。

首轮 program 为 5/7：复制源码保留时间戳后，Ninja 复用了旧 broker 对象，
文件描述符标志测试暴露了旧构建产物。清除两 ABI 原生构建缓存并完整重建后，
检查最终库包含新的标志处理，再执行上述全部套件，最终 27/27 通过。
首轮失败没有计入成功结果，后续源码同步应避免时间戳导致的增量构建遗漏。

主 APK 和测试 APK 均已用相同签名覆盖安装并返回 Success，应用数据保留。
这不承诺以后每次覆盖安装都没有厂商确认界面。已在真机依次打开主界面、项目终端、
模式选择和“Linux 程序 · musl-smoke”；参数／环境文本显示正确，无布局重叠，未选择
项目时运行按钮禁用符合预期。本次 UI 检查没有创建用户项目，也不替代完整交互或后台生命周期测试。
上一版记录见 [0.2.0](android15-runtime.md)。

## 保留与清理

按用户要求保留主 App 和测试 App，使用相同签名覆盖安装；禁止卸载、pm clear
或为测试重建签名。应用数据、执行历史和匹配签名密钥保留，未执行卸载或 pm clear。
测试创建的临时项目和恢复回执已清理；核对并保存结果后，已删除包含首轮失败记录在内的
七份原始日志、一张截图及本轮 raw 目录，确认 `.build/device-results` 无残留条目。
四次 uiautomator dump 使用的设备临时 XML 均已在读取后删除，没有其他外部设备文件残留。
手机保留在程序模式页面，本次 UI 检查未创建用户项目。

本版已保存产物位于 `.build/artifacts`：`sucrune-libc-preview.apk`、
`sucrune-libc-tests.apk`、`sucrune-musl-smoke.elf` 和 `libc-verification.json`。

## 结论边界

### libc 来源更正（2026-11-07）

本记录早先的“静态链接未修改 musl”表述范围过大。实际是 Zig 0.17.1 提供的
**musl-based Linux libc**：musl 提供启动、TLS 等实现，工具链也链接 Zig 提供的
libc 实现；该 fixture 的 malloc/free 使用 Zig 的 SmpAllocator。Sucrune 未修改
这些工具链源码，也未把客体 libc 替换为 Android Bionic，但不能据此称整个 libc
或分配器均为上游 musl 原实现。

核验不是仅查看工具链源码：使用原构建参数、仅去掉 `-s` 重建后，带符号 ELF 的
整个 `.text` 与上述已验证的 45,072 字节 ELF 完全一致，共 31,504 字节，SHA-256 为
`0C6F6B6E9D9DDF90B174BD05957E20DF4A85DF7D6EE6F3D412036D7B5BBD4E20`。
符号与 DWARF 将 `malloc`、`free` 分别定位到 Zig `lib/c/malloc.zig`，
`heap.SmpAllocator.alloc` 定位到 `lib/std/heap/SmpAllocator.zig`；
`__libc_start_main`、`__init_tls` 定位到 musl 的 `src/env`。
该 fixture 没有使用 realloc，不能把工具链中存在的 realloc 实现当成已执行证据。

以上更正只限定库来源与测试结论，历史 ELF 摘要、27/27 真机结果和清理记录保持不变。

### 已验证范围

本阶段只针对固定可信 musl 程序。没有任意 ELF 导入、动态链接、fork、客体线程、
客体信号 handler、POSIX 信号交付、BusyBox、包管理器或通用 Linux rootfs。
虚拟信号掩码和 set_tid_address 处理不替代这些能力。固定地址碰撞必须失败。

64 MiB arena 是客体数据 syscall 预算，不是整个 worker 的 RSS 配额。
ARM64 4 KB 单机通过也不能推导 Android 10、16 KB 真机、x86_64 执行、多厂商兼容、
恶意机器码隔离或性能结论；这些仍需单独验证。
