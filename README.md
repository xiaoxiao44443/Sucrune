# Sucrune

Sucrune 让普通 Android 应用在无 root 的 ARM64 设备上运行项目内的 Linux 程序。应用通过 Kotlin `RuntimeClient` 创建工作区、导入程序、读写文件并管理子进程。工作文件可跨执行保存。

当前开发版为 **0.8.0-agent-dev**，最低支持 Android 10（API 29）。[快速开始](#快速开始) · [Kotlin API](docs/runtime.md) · [真机验证](docs/device-validation.md) · [MIT 许可证](LICENSE)

上层应用可以为项目提供发行版 rootfs。Alpine 的原始文件、符号链接、动态加载器和脚本可以直接在项目内使用。导入方法和 Android 真机验证见[运行 Alpine minirootfs](docs/linux-rootfs-import.md)。

Go 管理多个持久化项目，Kotlin 管理执行生命周期，独立原生 runner 加载项目内的 ARM64 Linux ELF、动态链接器和库。Android 15 真机上，原版 Linux Node 24.22.2 已用 `child_process.spawn` 启动 Debian 程序。原版 node-pty 也启动了交互式 GNU Bash，连续执行两条命令，保留变量和进程 PID，并向父进程返回退出码 7。[进程与终端验证](docs/linux-process-design.md)

**原版 DSH Agent 已在 Android 15 无 root 真机跑通，最终验收 63/63。** 手机上的 Linux Node 24.22.2 运行原版 DSH 0.2.2-rc.1 的 `sdk-minimal` 配置，并通过原版文件工具与 Bash 工作。真实 DeepSeek 调用 `write → read → bash` 后，管理器独立核对了两个文件。第二个进程恢复同一会话，模型在没有工具、没有再次得到答案的情况下复述了第一轮的随机标记；JSONL 原有字节完整保留。第三个进程在活动轮次中被取消，同一项目随后成功执行了新程序。[真机收据](docs/validation/android15-dsh-agent-acceptance.json) · [运行步骤](docs/run-dsh-on-device.md)

本次验证使用非调试应用、隔离 UID 和前台测试入口。Windows 负责启动测试并临时传递本机 DSH 的 DeepSeek 凭据。Agent、文件、终端及会话均在手机上运行，推理由远端模型服务提供。尚未验证 DSH Web 界面、后台常驻或 Android 10 至 14 各版本。

`executeProgram` 提供固定的 Shell、`musl-smoke` 和 Lua。Lua 使用上游源码，静态链接 Zig 的 musl-based Linux libc。`executePath` 接受显式导入项目的 ARM64 Linux 文件，支持运行时已实现的 Linux 系统调用和库加载行为。[Linux 开发配置](docs/linux-profile.md)

## 当前可用

- 创建、查询和删除项目环境；工作文件跨执行保存。
- 流式校验导入单个最大 256 MiB 的文件；通过 `executePath` 运行 Linux 动态程序。默认 W^X，V8 普通模式需显式选择 `linux-jit` 内存策略。
- `executePathInteractive` 支持逐次输入、接收输出和显式 EOF；每次执行累计最多接受 1 MiB 输入，区分已接受、已写入和客体实际消费。
- 通过字节 API 读写、导入和导出文件，创建目录、列举文件；支持中文和 emoji。
- 执行内嵌 Shell 支持的命令、脚本文件、变量、引号、条件连接和 `<`、`>`、`>>` 文件重定向；`cat` 无参数或 `-` 读取 stdin。每条命令最多一个输入和一个输出重定向。具体范围见 [Shell 说明](native/shell/README.md)。
- 使用 `listPrograms` 查询内嵌程序，通过 `executeProgram` 传递 argv/env 和最多 1 MiB 的二进制 stdin；运行 Lua 脚本、纯 Lua 模块和文件转换，或用 `musl-smoke` 检查 libc/TLS/内存通路。具体契约见 [程序说明](native/programs/README.md)。
- 内嵌 Shell 可在三个固定程序之间执行 `exec`。Linux 项目程序可通过支持的 `clone` 标志创建真实子进程，通过 `execve` 加载另一个项目 ELF，再由父进程 `wait4` 收取退出状态。父子进程各有工作目录，继承的文件描述符共享同一个内核打开文件描述及偏移。
- Linux 执行的网络策略默认为 `none`。调用方可显式通过 `SUCRUNE_NETWORK_POLICY` 选择 `loopback` 或 `outbound`。在真机测试中，客体 Node 验证了公开服务的 TLS 证书和主机名，未携带凭据时收到 HTTP 401。另一项用例中，Bash 继承了已连接的 TCP 描述符，子进程退出后父 Node 继续写同一连接。[网络验证](docs/validation/android15-agent-execution-progress.json)
- Linux 路径执行有 1,024 个客体 FD 槽位，内嵌工具有 64 个。复制出的描述符共享文件偏移和追加状态，CLOEXEC 标志各自独立。
- 普通命令默认可运行 30 分钟。Agent 可在启动 Linux 服务时传入 `resident = true` 让它持续提供服务，同项目仍可运行普通命令。Android 管理器合计最多四次活动执行。[项目生命周期](docs/project-lifecycle.md)
- 保留原 seccomp 与受控 ELF 探针，用于分别验证底层机制。

管理核心只在主应用进程加载 Go；客体 worker 不加载 Go。取消后必须确认 worker 已停止、输出管道到达 EOF、文件代理完成清理、stdin 写入任务已关闭，才将执行置为终态并释放项目。主应用仍可能被 Android 杀死；重新打开管理核心会把遗留 running 记录标为 lost，不恢复进程。

## 快速开始

在 Windows PowerShell 7 中克隆仓库并进入项目目录。

```powershell
git clone https://github.com/xiaoxiao44443/Sucrune.git
cd Sucrune
```

需要 Go 1.24+、JDK 17+、Android SDK、NDK、CMake 和 Zig 0.17.1。Zig 工具链在 Windows 上交叉编译内嵌 Linux 程序；运行时管理与 syscall 后端仍为 Go/Kotlin/C/汇编。具体 Android 配置见 `android/probeapp/build.gradle`，当前 minSdk 29、targetSdk 37。

```powershell
.\scripts\test-core.ps1 -Go 'C:\Tools\Go\bin\go.exe'
.\scripts\build-android.ps1 -Zig 'C:\Tools\Zig\zig.exe' -Go 'C:\Tools\Go\bin\go.exe' -JdkHome 'C:\Tools\JDK' -SdkRoot 'C:\Android\Sdk' -Variant validation
```

Go/Zig 已在 PATH 中时可以省略对应参数。Android 构建脚本先核对 vendored Lua 源码摘要、生成并检查 Linux 验证程序，再生成两个 ABI 的 Go 共享库、构建 APK 并运行 lint。validation 不可调试，使用本地开发签名。Zig/Lua 来源、摘要与第三方许可证见 [程序构建说明](native/programs/README.md)。

使用 Android Studio 或直接调用 Gradle 前，先生成内嵌 Linux 程序和 Go 共享库。

```powershell
.\scripts\build-linux-programs.ps1 -Zig 'C:\Tools\Zig\zig.exe'
.\scripts\build-go-android.ps1 -Go 'C:\Tools\Go\bin\go.exe' -SdkRoot 'C:\Android\Sdk'
.\gradlew.bat :probeapp:assembleDebug
```

主 APK 在 `android/probeapp/build/outputs/apk/<variant>/`。安装到 Android 10+ ARM64 手机后，在 Sucrune Probe 中进入项目终端，新建项目并运行：

```sh
mkdir -p output
echo 'Hello from Sucrune' > output/result.txt
cat output/result.txt
```

再次运行 `cat output/result.txt` 可读取上次生成的文件。切换到“Linux 程序 · Lua 5.4.9”，argv 输入 `-`，stdin 输入 `print("Hello from Lua")`，运行后会输出问候语。UI 的 stdin 为 UTF-8 文本，应用内 API 另可传二进制。

选择“Linux 程序 · Linux libc validation 1”可运行标识为 `musl-smoke` 的 libc 检查；参数每行一个，例如 `selftest`、`参数中文🙂`，成功退出码为 42。应用内调用示例见 [运行时使用说明](docs/runtime.md)。x86_64 可构建管理层和探针，客体执行明确 unsupported。

也可在 Shell 中准备 Lua 文件并交接执行：

```sh
printf '%s\n' '10' '20' '12' > input.txt
printf '%s\n' 'local n=0;for v in io.lines() do n=n+tonumber(v) end;print(n)' > task.lua
exec /bin/lua task.lua < input.txt > result.txt
```

本例使用内嵌的最小 Shell。stdout 为空，result.txt 保存 `42` 和换行。`exec` 导出 Shell 变量，保留工作目录与重定向后的标准流，成功后由目标程序接管。需要 PATH 搜索、命令替换或管道时，可以用 `executePath` 启动项目内的 ash 或 Bash。

Windows 开发 CLI 可操作管理协议：

```powershell
'{"op":"env.list"}' | .\.build\bin\sucrune.exe --data-dir .runtime-data rpc
```

`rpc` 是逐行 JSON 管理接口，不会在 Windows 上执行 Linux。`exec.create` 仅分配执行记录；实际执行由 Android `RuntimeClient.execute` 监督。不要让多个进程同时管理同一数据目录。

## 验证状态

0.8 的最终 Agent 验收由 59 项运行时与原版工具前置检查和 4 项 Agent 用例组成。[最终验收](docs/validation/android15-dsh-agent-acceptance.json) 与[排错记录](docs/validation/android15-dsh-agent-iterations.json) 分开保存，各轮用例数不累加。

**0.8 的进程与终端回归在 Android 15 ARM64、4 KiB 页、非调试应用身份下通过 11/11。** 用例覆盖真实子进程的写时复制、已删除文件的共享偏移、glibc 动态程序替换、Node 子进程管道、TCP 继承、跨会话取消回收，以及原版 node-pty 与 GNU Bash 交互。独立 ADB shell UID 2000 检查和专用隔离服务的能力探针另行记录。此前各轮针对不同功能，重复用例按轮保留。[0.8 逐轮应用证据](docs/validation/android15-agent-execution-progress.json) · [PTY 能力测量](docs/validation/android15-pty-capability.json)

0.7 的最终构建通过 Linux/Node/DSH **36/36**、文件 I/O **12/12**、exec **11/11**、Lua/工具 **10/10**，四组共 **69/69**。这组历史验收覆盖 Node 常用工作流、DSH 原生扩展、依赖安装和交互式 SDK 初始化及关闭。[0.7 开发证据](docs/validation/android15-linux-progress.json)

长流程测试显式保持测试 Activity 在前台。本机曾出现退后台后管理者和客体一起停止推进、切回前台后恢复的现象，具体系统原因尚未确认；后台持续执行与后台期限保障仍待验证。

已归档的 0.6 版本 Shell 主机回归 **72/72**、纯 FD 所有权测试 **10/10**、Android 15 应用身份验收 **60/60**，含 200 条重定向和双项目 IO。该版 APK 签名、对齐、内嵌 ELF 和日志已经独立审计，详见 [0.6 验证记录](docs/validation/android15-io.md)。主机与 UID 2000 的独立检查不计入应用身份验收；并发重叠也不代表性能基准。

历史结果保留：[0.5.0 exec 48/48](docs/validation/android15-exec.md)、[0.4.0 Lua/stdin 37/37](docs/validation/android15-tools.md)、[0.3.0 libc 27/27 与来源更正](docs/validation/android15-libc.md)、[0.2.0 运行时](docs/validation/android15-runtime.md)、[seccomp](docs/validation/android15-arm64.md)和[受控 ELF](docs/validation/android15-arm64-elf.md)。这些记录各自限定当时版本，不替代新版本回归；仍无 Android 10 或 16 KB 真机证据。

复验时可用相同签名和 `adb install -r` 覆盖安装，保留设备上的项目数据和执行历史。[设备验证步骤](docs/device-validation.md)

## 项目结构与边界

| 路径 | 职责 |
| --- | --- |
| `cmd/sucrune`、`cmd/sucrunecore` | 开发 CLI、Android c-shared 桥 |
| `internal/runtimecore` | 环境、文件、执行记录及恢复语义 |
| `internal/environment`、`internal/capability` | Catalog 与主机能力模型 |
| `android/probeapp` | Kotlin 客户端、管理者、隔离 worker 和测试 UI |
| `native` | 实验执行后端、ELF 加载器、文件代理和架构桩 |
| `native/shell` | 内嵌无 libc Shell 及其主机测试 |
| `native/programs`、`third_party/musl`、`third_party/lua` | 固定 Linux 程序、Lua 源码、构建契约及第三方许可 |
| `scripts`、`docs` | 构建、验证与接口说明 |

项目数据由可信管理进程和文件代理维护。Android 上二者通过管理目录的文件锁协调路径操作。本版尚待针对恶意机器码和同 UID 代码的隔离审计。多个项目共享 CPU、内存、存储和温控预算。

Agent 保持在运行时之外。现有入口是同一 Android 应用内的 Kotlin API，尚未提供跨应用 IPC SDK、通用包管理器或任意工具链安装。

进一步阅读：[架构](docs/architecture.md)、[接口](docs/api.md)、[阶段目标](docs/roadmap.md)、[设备验证](docs/device-validation.md)、[ELF 加载](docs/elf-loader.md)。

## 开源许可

Sucrune 的原创代码和文档采用 [MIT 许可证](LICENSE)。

Lua、musl 和 Zig 运行库各自沿用上游许可，Gradle Wrapper 使用 Apache-2.0。设备测试使用的 Linux 软件包由准备脚本按固定版本和摘要获取，各包适用其原有许可。[Lua 声明](third_party/lua/NOTICE.md) · [musl 与 Zig 声明](third_party/musl/NOTICE.md) · [Gradle Wrapper 许可](https://www.apache.org/licenses/LICENSE-2.0)
