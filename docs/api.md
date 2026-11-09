# Sucrune 接口

Android 应用内的 `RuntimeClient` 负责执行客体程序，Go JSON 协议负责持久管理。尚未提供跨应用授权或公开 IPC SDK。

## Android 应用内 API

使用 `RuntimeClient.get(context)`，只能在主应用进程使用。文件传输以 ByteArray 为边界，调用方自行接入文件选择器、Agent 或其他来源。

| 方法 | 返回与约定 |
| --- | --- |
| `createEnvironment(name)` | 环境 JSONObject，使用其中的 id |
| `listEnvironments() / getEnvironment(id)` | 环境列表／单个环境 |
| `deleteEnvironment(id)` | 永久删除项目文件；活动执行存在时 conflict |
| `deleteProject(id)` | App 删除项目时在后台线程调用。立即请求取消该项目的全部执行，等清理完成再删除项目文件 |
| `writeFile(id,path,bytes) / readFile(id,path)` | 写入字节／返回 ByteArray，即当前导入导出边界 |
| `makeDirectory(id,path) / listFiles(id,path="/")` | 递归建目录／目录条目 |
| `execute(envId,script,cwd="/",timeoutMs=1800000)` | 取得占用并返回 execution ID，后续启动异步进行 |
| `listPrograms()` | 原生程序目录的 JSONArray；以 program_id 选择已打包程序 |
| `executeProgram(envId,programId,argv=emptyList(),env=emptyList(),cwd="/",timeoutMs=1800000,stdin=byteArrayOf())` | 按固定程序标识运行内嵌 ELF，返回 execution ID |
| `importFile(envId,path,input,expectedSize,sha256,executable=false)` | 在后台线程流式校验并导入最多 256 MiB 的普通文件；返回文件信息 |
| `executePath(envId,path,…,timeoutMs=null,resident=false)` | 加载项目内 ARM64 Linux ELF，有限输入发送后 EOF，返回 execution ID |
| `executePathInteractive(envId,path,…,timeoutMs=null,resident=false)` | 加载同类 ELF，输入保持打开。流式变体也接受相同的生命周期参数 |
| `writeInput(id,bytes) / closeInput(id)` | 交互输入：整块复制入队／排空后 EOF；累计最多 1 MiB |
| `getExecution(id) / listExecutions(envId?)` | 查询实时或持久记录 |
| `waitFor(id,timeoutMs=1805000)` | 在后台线程等待终态。调用方可提早结束等待，客体继续执行 |
| `cancel(id)` | 是否找到活动会话并请求取消，不表示已经停止 |
| `poll(id,afterCursor=0)` | 当前执行、增量事件和下个游标 |

execute 输入是本版 Shell 脚本，最多 65,536 UTF-8 字节，不允许 NUL。executeProgram 的 programId 当前为 `musl-smoke` 或 `lua`，以 listPrograms 返回的原生目录为准，不接受文件路径；目录另有 path 字段，分别为 `/bin/musl-smoke`、`/bin/lua`。`/bin/sucrune-sh` 是 exec 专用固定路径，不新增公开 programId。argv 不含 argv[0]，不做 Shell 分词，空参数和空格原样保留。env 是 `NAME=value` 列表，变量名须匹配 `[A-Za-z_][A-Za-z0-9_]*` 且不重复；只传递给这次程序执行。

argv/env 各最多 64 项，每项最多 4,096 UTF-8 字节，两者合计含每项 NUL 终止符最多 65,536 字节，不接受内嵌 NUL。未知程序抛出 unsupported_program，参数错误在取得项目占用前拒绝。cwd 必须是绝对客体路径、少于 1,024 UTF-8 字节。

| 执行配置 | 每个客体进程的 FD 槽位 | 翻译系统调用累计上限 | 命令执行期限 |
| --- | ---: | ---: | ---: |
| 内嵌 Shell 与固定程序 | 64 | 无 | 默认 30 分钟，可指定 1 秒至 30 分钟 |
| Linux 路径执行，含 `SUCRUNE_FD_PROFILE=build` | 1,024 | 无 | 默认 30 分钟，可指定 1 秒至 30 分钟 |
| Linux 路径执行，声明 `resident=true` | 1,024 | 无 | 无固定期限，须省略 `timeoutMs` |

期限从该命令提交起算，覆盖启动、执行及进程在其中等待 I/O 的时间。Agent 在沙箱外思考、尚未提交命令的时间不计入。常驻程序可长时间等待请求，依然可以取消。Linux 的 `fork` 和 `exec` 继承 FD 上限，`RLIMIT_NOFILE` 返回对应的软硬限额。Linux 路径执行可由宿主在初始环境设置 `SUCRUNE_WRITE_SCOPE=read-only` 或 `workspace-write`。前者拒绝文件系统写入，后者允许在项目内的 `/workspace` 和 `/tmp` 写入。子进程继承相同限制。省略该选项时使用原有项目级权限。特殊构建 I/O 和网络策略仍由 `SUCRUNE_FD_PROFILE=build` 与网络策略选择。网络 socket 资源限 64 个，PTY 有独立配额。

完整 Linux runner 对项目普通文件的单次 `write` / `pwrite64` 默认最多提交 1 MiB，构建配置最多 16 MiB。代理收齐请求后使用一次内核写入，返回实际字节数。超过对应上限时调用方需处理短写。两个项目内普通文件之间可用 `sendfile`，支持显式源偏移和共享文件偏移。

Linux 网络默认关闭。构建工具若只需回环网络，调用方可传 `SUCRUNE_NETWORK_POLICY=loopback`。只有同时选择 `build` 和 `loopback`，代理才把 UDP 对 `0.0.0.0:0` 或 `[::]:0` 的绑定转换为设备上相应回环地址的临时端口。`outbound` 是独立的显式网络策略。JIT 内存权限由 `SUCRUNE_MEMORY_POLICY` 单独选择。

在上述构建配置中，父进程持有已绑定、未连接的回环 UDP socket 时可以启动工具子进程。子进程在 `exec` 前可复制或关闭这个 FD，父进程仍可收发。子进程直接通过继承的 UDP FD 收发，或将它作为非 `CLOEXEC` 描述符带入新 ELF，均返回 `EOPNOTSUPP`。

排查 Linux 路径执行时可传 `SUCRUNE_TRACE_SYSCALLS=1`，在前 4,096 次调用范围内向 stderr 写入系统调用号及 errno。传入 `SUCRUNE_TRACE_FAULTS=1` 可让主 runner 在致命信号退出前写入信号编号、`si_code` 及 PC 和故障地址的归属。报告使用客体区域及相对偏移，另行标识近零、区域外或不可用的地址。两个开关默认关闭。

stdin 是 executeProgram 的可选 ByteArray，最多 1,048,576 字节，支持 NUL；入口复制调用方数据。管理者以独立非阻塞 socket 写入任务发送，发送完或停止后关闭写端，客体读到有限字节流后得到 EOF；空输入直接 EOF。它不是交互会话，不支持后续追加或 PTY。execute 仍没有 ByteArray stdin 参数，初始 stdin 为空，但 Shell 可用 `< path` 从项目文件读取；程序 exec 到 Shell 时也可继承尚未消费的输入。大于 socket 容量的输入会受背压，写入任务会检查取消、期限和 worker 状态。stdin 内容不进入 Binder Bundle 或持久请求；请求只保存 stdin_bytes 与 stdin_sha256。argv/env 和脚本仍按原契约保存。

`lua` 为官方 Lua 5.4.9，静态链接 Zig 的 musl-based Linux libc，支持项目脚本与纯 Lua 模块。此固定程序入口没有本地 C 扩展动态加载、外部进程、网络或发行版包管理。项目内 ELF 走独立的 `executePath` 接口，仍不接受宿主可执行文件路径。

Linux 文件导入、PT_INTERP、动态库、JIT 策略和交互输入的完整契约见
[Linux 配置](linux-profile.md)。交互式请求保存 `stdin_mode=interactive` 与累计预算，
不把后续输入内容存入历史；结果区分接受和实际写入计数。超限整块返回
`input_limit`，关闭后写入返回 `input_closed`，有限输入会话返回 `input_mode`，
已回收会话返回 `not_found`。取消会请求关闭输入，客体在退出前可能观察到 EOF；
取消成功和资源回收以终态及清理证据判断，不由最后一条输出判断。

同一项目可同时运行一个普通执行和多个显式常驻的 Linux 程序。Android 管理者提供四个并发槽。默认每次执行占一槽。宿主启动同一常驻服务的不同权限实例时，可在每个实例的初始环境显式设置 `SUCRUNE_RESIDENT_COMPANION=1`。同项目、程序路径、参数、工作目录及其余非密环境均相同的实例，每槽最多容纳三种写策略各一份。常驻状态随执行结束解除。宿主启动和删除服务的示例见[项目生命周期](project-lifecycle.md)。exited 表示收到客体退出结果，退出码可以非零。cancelled、timed_out 和 lost 不提供正常退出码。

固定程序的镜像替换接口保持原范围：脚本中的 `exec /bin/lua ...` 或内嵌程序的 Linux
`execve` 在当前 worker 内替换镜像。只解析 `/bin/lua`、`/bin/musl-smoke`、
`/bin/sucrune-sh` 三个虚拟程序路径，不读取任意项目 ELF、宿主程序或 shebang。
这三个名称精确匹配，不规范化路径或跟随符号链接；不创建真实 `/bin` rootfs，
同名 open/stat 仍访问项目文件代理，exec 不使用那些文件的字节。
同一 execution ID、项目占用、PID/TID、绝对期限和取消链保持不变；成功不返回，
最多成功替换 32 次，再请求返回 ELOOP。原始 request 和 native.kind 保留初始入口
类型；native.last_program 表示最终程序标识，exec_count 表示成功替换次数，
exec_limit 为 32，host_context_restores 表示回到宿主上下文的次数，不能把最终
程序反写为原始请求。客体 execve 允许最多 65 项 argv（含 argv[0]）、64 项 envp，
字符串连同 NUL 合计最多 65,536 字节；这与客户端 argv 不含程序名的接口有所区别。

exec 在旧镜像仍有效时复制并检查路径与 argv/envp；无效指针、大小超限和未知路径
返回 errno，原程序可继续运行。开始不可逆替换后如加载、内存或代理提交失败，
native 报 failed，管理层记录 lost，不伪造原程序可恢复或正常退出码。成功替换
保留 cwd、剩余 stdin、虚拟信号掩码及未标记 CLOEXEC 的 FD/文件偏移；标记
CLOEXEC 的客体描述符关闭。新的镜像、初始栈、TLS 和数据 arena 重新建立。

客体 FD、代理句柄及宿主 FD 各自独立编号。客体 FD 的范围见上表。
dup(23)、dup3(24)、fcntl(25) 的 F_DUPFD/F_DUPFD_CLOEXEC 创建共享文件偏移及
状态的别名，F_GETFD/F_SETFD 操作每个描述符独立的 CLOEXEC。F_GETFL 查询共享
状态。代理普通文件与目录支持共享 O_APPEND/O_NONBLOCK；代理内部始终保留宿主
O_NONBLOCK，查询时返回客体选择的状态。异步通知 O_ASYNC 未实现。满表返回 EMFILE，open 在产生
创建／截断副作用前检查容量。stdin 的最后一个别名关闭后才释放原读端。

Shell 每条命令接受最多一个 `<` 和一个 `>`／`>>`，两条路径先展开，再按出现顺序
打开。实际映射 fd 0/1，所以内建命令、嵌套 Shell 和成功 exec 使用同一标准流；
返回时恢复原映射及标志，成功 exec 关闭用于恢复的 CLOEXEC 备份。重复重定向、
FD 语法和 here-doc 返回 2；文件打开或重映射失败返回 1。已完成的创建／截断不会
因后续打开或 exec 失败而撤销。没有 Shell 管道、任意 FD 重定向或子进程。

poll 返回 execution、events、next_cursor、event_history_available；活动会话另有 event_history_truncated 和 output_truncated。事件为 `{cursor,type,data}`，输出事件 data 含 content_base64。每个活动会话最多保留 256 个事件；客户端必须处理游标缺口。结束后聚合输出保留在执行记录中，实时事件历史不再可用。

## Go 管理协议

`runtimecore.Open(dataDir)` 返回持久 Service，`CallJSON([]byte) []byte` 接收一个 JSON 对象。C 桥 `SucruneCoreCall(dataDir,request)` 返回需要以 `SucruneCoreFree` 释放的 UTF-8 字符串，并缓存同目录 Service。真正 Open 是恢复边界，不能对同一活跃目录反复打开新 Service。

请求为 `{"op":"操作",...}`；响应统一为：

```json
{"ok":true,"result":{}}
{"ok":false,"error":{"code":"conflict","message":"..."}}
```

### 环境与文件

| 操作 | 请求字段 | result |
| --- | --- | --- |
| env.create | name | 环境对象 |
| env.list | 无 | 环境数组 |
| env.get | env_id | 环境对象 |
| env.delete | env_id | `{env_id,deleted:true}` |
| env.paths | env_id | `{environment,workspace,dependencies}`，仅可信管理层使用的宿主路径 |
| file.write | env_id,path,content_base64 | `{path,size}` |
| file.read | env_id,path | `{path,size,content_base64}` |
| file.mkdir | env_id,path | `{path}` |
| file.list | env_id,path | `{path,entries:[{name,kind,size}]}` |

环境包含 schema_version=1、id、name、created_at、state；ID 为 env_ 加 32 位小写十六进制。名称不是唯一标识或权限凭据。Catalog 元数据保持 stopped；Service 的 get/list 根据活动执行返回 running。

文件路径相对 workspace，开头的 / 仍是 workspace 根。Go API 拒绝 ..、反斜杠、控制字符、符号链接、特殊文件和跨平台歧义名称。写文件前须先建父目录；写入采用临时文件加替换发布。单次文件读写最多 1 MiB，base64 可传二进制。list 最多 4,096 项，按名称排序，kind 为 file 或 directory。文件 API 上限不是项目磁盘配额。

### 执行记录

| 操作 | 请求字段 | result |
| --- | --- | --- |
| exec.create | env_id，可选 request 对象 | 新的 running 记录 |
| exec.finish | execution_id,state，以及结果字段 | 已提交的终态记录 |
| exec.get | execution_id | 执行记录 |
| exec.list | 可选 env_id | 按创建时间排序的记录数组 |

exec.create **不会启动进程**，只持久化记录并保留项目占用。Android 监督器负责启动客体、等待清理和提交 finish。不能用 CLI 人工 finish 一个仍在运行的 Android 执行。

执行对象含 schema_version=1、execution_id、env_id、state、created_at、stdout、stderr、truncated。执行 ID 为 exec_ 加 32 位小写十六进制，时间为 UTC RFC3339。终态增加 finished_at，并可有 exit_code、result。可选 request 和 result 对象各不超过 256 KiB，Go 只持久化、不解释其中命令。

finish 的 state 必须为 exited、cancelled、timed_out 或 lost；exited 必须传整数 exit_code。可传 stdout、stderr、truncated 和 result。每流最多保存 64 KiB，超出时保留有效 UTF-8 前缀并设置 truncated。重复 finish 返回 conflict，不覆盖原终态。项目删除后，终态历史仍可查询。

Android result 记录 worker 身份、native 结果、Binder death、双流排空、文件代理完成、stdin_feeder_completed、stdin_bytes_written 和各流截断等证据。stdin_bytes_written 只表示已写入 socket 的字节，不表示客体已消费；客体可忽略输入或提前关闭，所以小于请求长度不自动构成执行失败。原生结果 stdin_bytes_read 单独记录原输入流经其任意别名读取的字节，不含重定向项目文件的读取量。只有写端关闭且写入任务完成，才满足 stdin 清理条件。program 的原生结果另记录 guest_tls_seen、host_tls_restored、signal_gate_entries、heap_peak_bytes 和 program_parser_checks。正常原生清理后的结果含实际配置的 `fd_limit`（64 或 512）、`fd_peak`、`fds_live` 和 `resources_live`，后两项应为 0。这些是受控路径的诊断证据，不是恶意代码证明。清理未确认时不提前终结。管理进程恢复的 lost 记录含恢复原因，不代表观测到了客体正常退出。

Go 请求上限 4 MiB；当前 JNI 文本入口另限 2 MiB。错误代码包括 invalid_request、invalid_arguments、not_found、unsafe_path、too_large、conflict、corrupt_metadata、storage_error 和 unsupported_operation。

## 开发 CLI

```text
sucrune info
sucrune --data-dir PATH rpc
sucrune --data-dir PATH env create --name NAME [--base REFERENCE]
sucrune --data-dir PATH env list|get|paths|delete ...
```

rpc 从 stdin 接收 NDJSON，每行对应一个 stdout 响应，进程内复用 Service。它没有 Android worker，不会在 Windows 上执行 Linux；传统 exec 命令明确 not_implemented。禁止多个进程同时管理同一目录。

传统 env 命令是 Catalog 开发工具：成功 stdout 为直接结果，失败 stderr 为 `{"error":...}` 并返回非零状态；没有 RuntimeClient 的监督层。--base 只保存描述，不安装发行版。

info schema 为 1，状态分 supported／unsupported／unknown，只报告开发 CLI 的本机能力。其 linux_execution=unsupported 不否认 Android Shell/program 后端，也不能代替 Android 设备断言支持。

## 原生探针与后续范围

seccomp 和受控 ELF 探针仍由一次性服务使用。报告包含 schema、probe、status、stage、host、evidence；status 为 passed、failed 或 unsupported，Android 外壳补充身份与构建信息。它们是机制诊断，不等于 exec 协议，也不能在管理进程直接接管 SIGSYS。

交互 stdin 通过应用内 API 提供。Linux 路径入口另有受限的 PTY 与网络支持。上层应用负责提供和安装客体工具，跨应用授权与公开 SDK 待开发。
