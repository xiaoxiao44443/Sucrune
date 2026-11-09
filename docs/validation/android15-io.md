# Android 15 ARM64 IO Preview 验证记录

日期：2026-11-07。版本：0.6.0-io-preview。

**同一不可调试 validation APK 的应用身份真机验收 60/60 通过，失败 0。**
新增 IO 十二组首次运行即 12/12，通过后重新执行此前 48 项；没有把历史版本的
通过结果直接计入本版。最终产物和原始日志独立审计通过，产物与精简证据已归档，
本轮原始日志、设备 XML 和检查 scratch 清理完成。

## 变更范围

客体采用固定 64 槽 FD 表，编号 0–63，与不透明代理句柄、宿主 FD 分离。
dup(23)、dup3(24) 和 fcntl(25) 的 F_DUPFD/F_DUPFD_CLOEXEC 创建共享打开对象的
别名，文件偏移和 O_APPEND 共享，FD_CLOEXEC 则按每个描述符独立保存。
F_GETFL 查询共享状态；F_SETFL 目前只允许修改 O_APPEND，不开放客体非阻塞或异步 I/O 模式。
错误 dup3 不破坏原目标；满表 open 在创建／截断文件前返回 EMFILE。关闭最后
一个别名才释放对应资源，因此 close(0) 后仍存活的别名可保持原 stdin 读端。

Shell 每命令接受最多一个 `<` 和一个 `>`／`>>`。两条路径先展开，随后按出现
顺序打开并通过 dup3 映射到 fd 0/1。内建命令、嵌套 sh/source、失败 exec 或部分
设置失败返回时恢复原标准流、FD 标志及原本关闭的状态；成功 exec 继承当前流，
关闭所有 F_DUPFD_CLOEXEC 备份，包括外层 frame 保存的别名。已完成的文件创建／
截断不回滚。cat 无参数或 `-` 读取 stdin，`./-` 读取名字为 `-` 的文件。
重复重定向、任意 FD 语法和 here-doc 在当前命令打开文件前返回语法错误。

固定程序目录、exec 32 次上限、同一执行绝对期限、取消和四项清理条件保持不变。
未新增管道、PTY、fork/wait、动态链接、网络、包管理或任意 ELF 导入。

## 已完成主机与独立原生检查

- Shell 实际 parser/builtin 主机回归 **72/72**：原 44 项中三项旧 exec 重定向
  拒绝预期改为支持，新增 28 项输入、别名、恢复和文件副作用检查。
- Shell mock 使用共享打开对象、偏移、引用计数和每 FD 标志；短读／短写保留。
  返回路径检查原标准流、标志、关闭状态及无 FD 备份泄漏。exec 用 longjmp 表示
  成功不返回，并应用 mock CLOEXEC，不加载目标 ELF 或执行主机解释器。
- 纯 FD 所有权测试 **10/10**，覆盖最后引用、标准流复用、共享描述对象、独立
  CLOEXEC、64 槽／64 资源、错误参数及关闭错误后的状态；不执行 Linux 客体。
- 严格 MSVC Shell 编译和 NDK ARM64 freestanding 编译／链接通过。Shell 为
  ET_DYN、RX/RW LOAD 均 16 KiB 对齐、无动态解释器，34,512 字节，SHA-256：
  `FB26669C31E8B5E21B7DE2AB3394931093222BFCAC3780D2BDBADF503E89E885`。
- 本版 Go 格式／vet／测试／CLI 检查与 Android 双 ABI 集成构建、lint 已通过；
  lint 为 0 错误、3 警告。
- 最终两份 APK 的 v2 签名验证通过，证书与既有保留签名匹配；16 KiB ZIP 对齐
  及四个打包 SO 的 16 KiB LOAD 对齐、W^X 检查通过。双 ABI JNI 符号匹配，
  三份内嵌 ELF 与实际生成文件逐字节一致，第三方 notices／源码摘要匹配。
- 独立重新编译六个关键原生对象，与实际构建对象逐字节一致，排除本轮复制
  源文件保留时间戳而导致 Ninja 复用旧对象的问题。独立结果保存为
  `io-artifact-audit.json`；该检查不替代 Android 10 或 16 KiB 真机验证。

原生 workspace broker 功能测试已在 Android 15 ARM64、**adb shell／UID 2000**
身份通过。它与上述 60 项应用身份验收分开，只证明对应代理功能测试通过，不能
证明普通 APK 或隔离服务权限。对应精简证据独立保存为 `io-broker-check.json`。

## 本版设备验收

设备为 Android 15/API 35、ARM64、4 KiB 页。validation 构建不可调试，
versionCode=6、versionName=0.6.0-io-preview、minSdk 29、targetSdk 37 已核对。
没有使用 root 或更改系统设置；设备序列号不写入记录。两份 APK 使用相同签名
install -r 覆盖均返回 Success，保留应用数据。

| 套件 | 预期条目 | 当前结果 |
| --- | --- | --- |
| io | 12 | 12/12 通过 |
| exec | 11 | 11/11 通过 |
| tools | 10 | 10/10 通过 |
| program | 7 | 7/7 通过 |
| runtime | 10 | 10/10 通过 |
| runtime_recovery prepare | 1 | 1/1 通过 |
| runtime_recovery verify | 1 | 1/1 通过 |
| seccomp_sigsys_return | 4 | 4/4 通过 |
| arm64_elf | 4 | 4/4 通过 |

独立日志审计核对九套最终 Bundle：passed/expected 合计 60、failed=0，全部
INSTRUMENTATION_CODE=-1；60 个唯一 PASS 与 60 个成功事件一致，无隐藏失败、
runner 异常或清理错误，不只依据 adb 的进程退出码。精简记录为
`io-device-audit.json`，包含各原始日志摘要和测试源码快照。

IO 用例名称、命令和核对范围见 [设备验证](../device-validation.md)。新增检查涵盖
Shell→Lua 文件输入／输出、返回恢复／追加、语法拒绝／打开顺序、嵌套 exec、
共享偏移／标志、64 槽耗尽／复用、exec 别名继承、标准流换号、最后 stdin 引用、
exec 关闭 Shell 保存的输入、反复重定向及双项目独立文件。

原 stdin 最后引用测试分别观测别名存活时 feeder 尚未完成、最后引用关闭后
feeder 完成且 worker 仍 running。Shell 保存输入的测试从带 1 MiB 输入的 libc
程序转入 Shell，再以文件重定向 exec 到 Lua CPU 循环，确认后继仍运行时 feeder
已完成，避免让 worker 死亡掩盖隐藏读端泄漏；随后取消，核对清理和保留产物。

**200 条重定向命令**在 64 槽表内完成，没有泄漏保存的描述符或资源。正常退出
核对 fd_limit=64、fd_peak 不超限、fds_live=0、resources_live=0；这些仅为客体
表计数。stdout/stderr 宿主 PFD 仍归 Kotlin 所有，必须另等 worker death、双输出
EOF、broker completion 以及 stdin feeder 关闭完成，不能用零计数代替四项屏障。
IO、Exec 和 Tools 的完成辅助函数逐项断言这四项；旧 Program／Runtime 辅助函数
逐项检查前三项，没有在每个用例独立断言 stdin_feeder_completed，不能把全部
60 项描述为每项都单独验证了四个字段。

双项目 IO 的原生执行区间实际重叠 **602 ms**，worker PID/UID 不同，同名输入／
输出文件各自独立。这是并发执行证据，不证明零开销、性能提升、四项目吞吐量或
CPU／内存硬隔离。旧 exec 套件已按本版支持直接／继承重定向更新预期后重跑通过。

管理进程恢复两阶段之间执行真实 adb force-stop，分别通过 prepare 和 verify；
没有用同一 JVM 重开对象代替管理进程重启。该检查不代表系统低内存回收验收。

## 最终产物与清理

最终主 APK 为 8,775,755 字节，SHA-256：
`E38D3F0E6E438859908ED8878C1AD7BE28DCF2FFA110477851B252A802EB2074`。
测试 APK 为 153,384 字节，SHA-256：
`C047AB9534443912C56549E77205FF584673A980C0C302ACDD1469B6DC6BFA28`。

| 程序 | 字节数 | SHA-256 |
| --- | --- | --- |
| sucrune-sh | 34,512 | `FB26669C31E8B5E21B7DE2AB3394931093222BFCAC3780D2BDBADF503E89E885` |
| musl-smoke | 63,560 | `A1A7B393801142A8BF093ED09C89539E8A21A5F93EC1E58E95A784E69E026DA8` |
| lua | 361,072 | `B875009D96A419F9CA3881FDB0464CBA11379944207F4E8FF15A0E8643B763D7` |

产物在 `.build/artifacts` 归档为 sucrune-io-preview.apk、sucrune-io-tests.apk、
sucrune-io-sh.elf、sucrune-io-musl-smoke.elf；Lua 继续使用字节未变的 sucrune-lua.elf。
五份精简检查 JSON 同目录归档：io-artifact-audit.json、io-device-audit.json、
io-broker-check.json、fd-native-check.json 和 shell-io-check.json。

项目终端已打开核对，项目列表为空并显示“请先新建项目”。本轮未创建截图，
唯一设备 UI XML 已删除，并以设备 test 确认不存在。两 App 仍保留。该界面检查
不能替代完整交互、Activity 后台生存期或系统低内存回收验收。

独立 native broker、FD 主机／严格编译及 APK 审计自己的 scratch 已清理。
Shell 的 `.build/shell-io-check` 四个文件也已清理：删除前核对绝对目标及无
重解析点，删除后确认目录不存在；精简证据保存在 `.build/shell-io-check.json`，
最终 Shell ELF 已归档，没有删除整个构建目录。

保存精简结果后，安全删除本轮 `.build/device-results/io-20261107` 中的九份
原始日志，并确认该目录不存在。测试 runner 在 finally 清理本次项目，日志未
出现清理错误，项目终端也未显示遗留项目；恢复验证调用了回执 AtomicFile.delete，
但没有独立检查应用私有回执路径最终不存在，不把删除调用提升为额外的文件系统
验收。

按用户要求保留 `com.sucrune.probe`、`com.sucrune.probe.test`、匹配签名密钥和
应用内持久执行历史；不卸载、不执行 pm clear、不删除整个构建目录或用户项目。

## 结论边界

共享 FD 和真实标准流重定向可用于当前固定 Shell／libc／Lua 工作流，不能推导为
完整 Linux 发行版兼容。固定可信机器码和项目路径代理仍不是经过审计的恶意
脚本／字节码／ELF 安全容器。

Android 10 基线、16 KiB 真机、更多厂商、长期后台运行、系统低内存恢复、完整
资源配额和性能基准仍需单独验证。主机解析和 16 KiB 对齐通过不替代相应设备执行。
