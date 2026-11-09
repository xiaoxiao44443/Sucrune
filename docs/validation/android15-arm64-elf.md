# Android 15 ARM64 ELF 真机验证

2026-11-07，受控无 libc ARM64 ELF 在 OnePlus PKR110 的 validation 构建中，普通应用服务两次、隔离服务两次全部通过。原 getpid seccomp 探针随后按默认选择路径回归，另四例全部通过。本轮共 8/8，仅使用不可调试 validation，未重测 debug。

## 条件与范围

| 项目 | 配置 |
| --- | --- |
| 设备与系统 | OnePlus PKR110，Android 15，API 35 |
| ABI 与页大小 | ARM64，4096 字节 |
| 应用 SDK | minSdk 29，targetSdk 37 |
| 构建 | validation，debuggable=false，本地开发签名 |
| ELF 普通服务 | UID 10420 |
| ELF 隔离服务 | UID 99246、99247 |
| 权限 | 未使用 root，未修改系统设置 |

ADB 用于安装、instrumentation 和结果核对；ELF 由 APK 内的实际服务进程加载和执行。没有通过 execve 启动 Android 命令替代实验，也没有进行跨指令集模拟。

## 受控 ELF

readelf 检查得到：

| 字段 | 值 |
| --- | --- |
| Machine / Type | AArch64 / DYN |
| Entry | 0xe8，运行时加上 load bias |
| LOAD 代码段 | RX，vaddr 0，filesz 0x274，align 0x4000 |
| LOAD 数据段 | RW，vaddr 0x4000，filesz 8，memsz 0x50，align 0x4000 |
| GNU_STACK | RW |
| 动态依赖 | 无 INTERP、DYNAMIC 和重定位 |

夹具按标准 Linux ARM64 ABI 发出 write 64 和 exit 93。CPU 实际进入其 ELF 入口，依靠 SIGSYS 处理输出和退出，再恢复宿主执行。

## 结果

| 套件 | 普通服务 | 隔离服务 | 总计 |
| --- | --- | --- | --- |
| arm64_elf | 2/2 | 2/2 | 4/4 |
| 默认 seccomp 回归 | 2/2 | 2/2 | 4/4 |

ELF 四例均核对到：

- stdout 精确为 `Hello from Sucrune ELF!\n`，含末尾换行，共 24 字节。
- exit_code=42，一次 write、一次 exit，共两次 SIGSYS。
- 两个 LOAD 段加载成功；客体 argc/env/auxv、16 字节栈对齐、BSS 和 data 的夹具自检通过。
- returned_to_host、备用信号栈、处理器恢复、线程 join 与服务 Binder death 均通过。
- 每次运行的 26 个解析器负例全部通过。负例使用默认 4 KB 参数，正例覆盖 4 KB 和 16 KB 的解析布局。
- `-e expect_debuggable false` 自动核对目标应用和服务报告的不可调试标志。

安装产物的签名和 ZIP 对齐亦经检查。本地开发签名不构成正式发布签名验收。

## 结论与未覆盖项

本机配置下，匿名内存的段加载和权限转换、受控 Linux ARM64 初始栈、真实 CPU 入口执行、write／exit 处理及宿主恢复链路成立。

该结论不涵盖任意静态二进制、动态链接或 libc、客体 TLS、完整 Linux rootfs、全部 syscall 语义、并行多沙箱、恶意代码隔离或手机性能。当前客体必须保留宿主 x18 与 TPIDR_EL0。

Android 10、x86_64 ELF 执行、16 KB 设备执行、完整 16 KB 负例矩阵、异常注入和 UI 退后台未在本轮验证。x86_64 ELF 执行当前明确不支持。本轮未新增 debug 结果。

## 复验与清理

构建和运行方式见 [受控 ELF 加载](../elf-loader.md) 与 [设备验证](../device-validation.md)。原始设备序列号、fingerprint、报告和日志不保存在本记录中；本轮未生成截图。

本轮新安装的测试 APK 与主 APK 均已卸载，包列表查询为空。原始临时日志已删除，device-results 目录为空；本轮没有生成截图。

保留经核对的结果提要 `.build/artifacts/elf-verification.json` 和本次受控夹具 `.build/artifacts/sucrune-hello.elf`。这两个本地产物不替代原始设备日志；后续需要新增证据时应重新运行。
