# Android 15 ARM64 Exec Preview 验证记录

日期：2026-11-07。版本：0.5.0-exec-preview。

**最终不可调试 validation 构建应用身份真机验收 48/48 通过，失败 0。**
最终产物和独立日志审计均通过，精简结果已归档，临时文件清理完成。本轮重新执行全部 48 项，没有把旧版
37/37 直接计为本版通过。

## 变更范围

加入 Linux execve(221) 的固定镜像替换，只精确匹配 `/bin/lua`、
`/bin/musl-smoke`、`/bin/sucrune-sh`。这三个名字不是项目中安装的 `/bin`
文件，exec 不读取同名项目文件字节，也没有路径规范化、PATH 搜索、shebang、
符号链接解析、任意 ELF 或宿主命令执行。

Shell 可准备脚本和文件，再通过 exec 转入 Lua。成功后不返回，包括嵌套 Shell；
Shell 全部当前变量作为环境传递，直接或继承的 stdout 重定向明确拒绝。
直接 exec 重定向在打开／截断目标之前拒绝，外层重定向可能已经创建自己的文件。

同一 worker/thread 保留 PID/TID、cwd、剩余 stdin、虚拟信号掩码、非 CLOEXEC
描述符和偏移；提交时关闭标记 CLOEXEC 的客体描述符。新 ELF、栈、TLS/BSS 和
数据 arena 重新建立。链内共用执行 ID、项目占用、原绝对期限、取消、syscall
预算和四项清理条件；最多成功替换 32 次，第 33 次返回 ELOOP。

路径和参数预检查失败返回旧程序；开始不可逆替换后的资源／代理失败终结为
native failed、管理层 lost，不返回已卸载的旧镜像。原始 request 与 native.kind
保持初始入口，last_program 与 exec_count/exec_limit 单独记录最终镜像和次数。

## 已完成主机检查

- 实际 Shell parser/builtin 主机回归 **44/44**：原 31 项，加 argv/env/cwd、
  ENOENT/其他失败状态、失败继续、成功不返回、嵌套替换与重定向保护检查。
- 成功 exec 的主机 mock 用 longjmp 模拟非返回控制流，捕获 syscall 参数；
  不加载目标 ELF、不调用主机解释器或子进程，不计为 Android exec 通过。
- NDK ARM64 Shell freestanding 编译与链接通过，ET_DYN，RX/RW LOAD 对齐
  16 KiB。生成 Shell 为 34,472 字节，SHA-256：
  `A0DBE64B822E127300F247DD16B09E3172DE3E72A62B545D08B75AC4C175B42D`。
- Go 格式、vet、单元测试和 CLI 构建通过；完整 Android 双 ABI 构建通过，
  Gradle 报 BUILD SUCCESSFUL（22 秒）。lint 为 0 错误、3 警告；现有警告为
  DataExtractionRules、StaticFieldLeak 和 SetTextI18n。
- 对实际项目解析器源码重新运行主机检查：旧 ET_DYN 26 项、静态程序 28 项
  拒绝用例通过，三份最终 ELF 在 4 KiB／16 KiB 参数下均解析通过。
- 最终 APK 的三份内嵌 Shell、musl-smoke、Lua 字节与生成 ELF 完全相同；
  两个 APK 的 v2 签名正确且证书匹配，16 KiB ZIP 对齐通过，四个打包 SO 的
  LOAD 对齐均为 16 KiB。双 ABI catalog/JNI 及实际版本核对通过。

另运行原生 workspace broker 功能检查，输出
`workspace broker boundaries, descriptors, exec commit, rename and completion passed`，
退出码 0。该二进制由 **adb shell，UID 2000** 在 Android 15 ARM64 启动，
不是 App／隔离 worker 身份；只证明对应代理功能测试通过，不计入 48 项应用验收，
不建立 App 权限或隔离结论。目标 API 29 的 ARM64／x86_64 严格编译均通过；该检查
自己的设备临时目录和主机 scratch 已清理，精简证据保存于 exec-broker-check.json。

上述主机事实不建立 Android 10、16 KiB 真机或不可信代码隔离能力。

## 本版设备验收

设备为 Android 15/API 35、ARM64、4 KiB 页，应用使用不可调试 validation 构建。
没有使用 root 或更改系统设置；设备序列号不写入记录。

| 套件 | 预期条目 | 当前结果 |
| --- | --- | --- |
| exec | 11 | 11/11 通过 |
| tools | 10 | 10/10 通过 |
| program | 7 | 7/7 通过 |
| runtime | 10 | 10/10 通过 |
| runtime_recovery prepare | 1 | 1/1 通过 |
| runtime_recovery verify | 1 | 1/1 通过 |
| seccomp_sigsys_return | 4 | 4/4 通过 |
| arm64_elf | 4 | 4/4 通过 |

exec 套件包含 Shell/Lua 产物、失败与重定向、静态程序→Shell→静态程序链、
嵌套替换、PID/TID 与内存／描述符继承、错误参数、标准流 CLOEXEC、32 次链上限、
原期限、取消后复用和双项目并行。精确用例名与命令见 [设备验证](../device-validation.md)。

已核对八份最终套件结果的 passed/failed/expected_tests，全部 failed=0、
INSTRUMENTATION_CODE=-1，没有仅凭 adb 返回 0 判定成功。正常退出核对
host_context_restores=exec_count+1、
宿主 TLS、handler、备用栈和线程恢复；终态仍检查 worker death、双流 EOF、
broker completion 和 stdin feeder 完成。
独立审计确认 48 个成功用例事件、无隐藏失败／runner 异常或清理错误。

新增 exec 套件首次执行即 11/11，failed=0、INSTRUMENTATION_CODE=-1。
双项目原生执行区间实际重叠 **604 ms**，PID/UID 不同，产物各自保留；这是并发
事实，不是性能基准。3000 ms 原执行期限实测 **3050 ms**，覆盖替换前两秒 sleep
以及替换后 Lua CPU 循环，没有在 exec 时刷新为新三秒期限。

原生状态夹具还验证虚拟 SIGUSR1 掩码保持、自定义 argv[0] 与 AT_EXECFN 区分、
文件／标准流 CLOEXEC、旧镜像错误返回后的状态保持及成功后的 TLS/BSS/arena 重建。
其他并行回归原生区间重叠为 Lua 591 ms、musl 1,986 ms、Shell 2,000 ms；
均为不同 worker PID/UID，不推导为四项目性能或资源硬隔离。

## 最终 APK、UI 与清理

主 APK 与测试 APK 使用相同签名 install -r，均返回 Success；两包仍安装。
已核对设备上的 versionCode=5、versionName=0.5.0-exec-preview、minSdk 29、
targetSdk 37。最终主 APK 为 8,759,315 字节，SHA-256：
`B456AE1C6BAD41D8BE0BCEDAFAB5654546D5BB71ACA330F45C8521A8C7027649`。
测试 APK 为 130,836 字节，SHA-256：
`3F9D21714914C5850C40CA69959F317ACB25200E5C2F93081074E90B8E60C9AC`。

最终内嵌 ELF 摘要：

| 程序 | 字节数 | SHA-256 |
| --- | --- | --- |
| sucrune-sh | 34,472 | `A0DBE64B822E127300F247DD16B09E3172DE3E72A62B545D08B75AC4C175B42D` |
| musl-smoke | 55,728 | `CAFE8A092A12D1375C68F4660F27D673E8B52587F44050FA49C5809C61E943D4` |
| lua | 361,072 | `B875009D96A419F9CA3881FDB0464CBA11379944207F4E8FF15A0E8643B763D7` |

归档名称为 `.build/artifacts` 下的 exec-verification.json、exec-broker-check.json、
sucrune-exec-preview.apk、sucrune-exec-tests.apk、sucrune-exec-sh.elf、
sucrune-exec-musl-smoke.elf；Lua 复用字节未变的 sucrune-lua.elf。

主界面进入项目终端后显示 Shell、默认 pwd/help 和“请先新建项目”，本轮测试
项目未遗留。UI 代码未改，没有新建截图；唯一设备 UI XML 在检查结束时已删除。
该检查不替代完整交互、Activity 后台生存期或系统低内存回收验收。

按用户要求保留 `com.sucrune.probe`、`com.sucrune.probe.test`、匹配的签名密钥和
应用数据和持久执行历史；不卸载，不执行 pm clear。

测试 runner 清理自己的项目，恢复测试调用删除回执并报告清理成功；未独立断言
应用私有回执路径的最终不存在，不能把报告调用提升为额外的文件系统检查。

保存精简结果与最终产物后，删除本轮 `.build/device-results/exec-20261107`，
共九个文件（八份原始应用测试日志和一个中间套件 JSON）。本轮没有创建截图。
设备上的唯一 UI XML 与独立 broker 检查目录均已确认不存在。

主机检查自己的临时编译／提取目录已清理，包括 Shell 的 shell-exec 与
shell-host-tests；删除前验证绝对路径范围及非重解析目录，删除后确认不存在。
Shell 主机 44/44 与 ELF 摘要保留在文档和精简 shell-exec-check.json，最终 Shell
ELF 另已归档。未删除已有项目、持久执行历史、签名密钥或整个构建目录。

## 结论边界

execve 替换没有实现 fork、wait、动态链接、任意发行版 rootfs、PTY、网络或包管理。
Shell 无顺序启动多个外部命令或管道能力；Lua 没有新的 os.execute/io.popen 子进程
后端。固定可信镜像和项目路径代理不等于恶意脚本／字节码／ELF 的安全容器。

Android 10 基线、真实 16 KiB 页设备、更多厂商、低内存恢复、长期后台运行和
性能基准仍需单独验证；并行时间交叠不能推导为性能零开销。
