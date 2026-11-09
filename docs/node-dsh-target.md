# Node.js / DSH 运行目标与验收

调查日期：2026-11-07。本文件保留开发目标与依赖证据；下文记录有限真机进展，
完整历史、失败分类与日志摘要见[Android 15 验证记录](validation/android15-linux-progress.json)。
最终目标是 Sucrune 的 Android 无 root Linux 客体内运行真实 Node.js 与官方
DeepSeek Harness。桌面 Harness 的 MCP 连通性、桌面 Electron 壳、已有 DSHA
中的 PRoot 执行结果均不能替代这一验收。

## 固定目标

- 官方 npm 包：`@deepseek-ai/dsh@0.2.2-rc.1`。查询时 npm `latest` 为该版本。
  CLI 入口是包内 `lib/bin.js`，`bin.dsh` 指向它，包为 ESM。
- 官方源码提交：`fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159`，CLI manifest
  与 npm 同为 `0.2.2-rc.1`。
- DSH 要求 **Node.js >=24.9.0**。主项目固定原版 GNU/Linux ARM64 Node
  **24.22.2**；经流式摘要校验导入后，已在 Android 15 非调试 isolated worker
  的 native runner 中通过版本、JavaScript、JIT 与多项实际工作流测试。
- npm 发布元数据记录 CLI tarball 为
  `https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-0.2.2-rc.1.tgz`，完整性为
  `sha512-ijR9UEVYkG15Q/Q79JzvzLBzQOQfc63VLr9n6flpwHPhr5IKn2UxthnSoto/P9l7qGd7pPvI1Ra6TW7LH3oKpg==`。
  仅固定顶层包不足以复现全部依赖，正式安装必须保留完整 lockfile 和实际解析
  版本、原生平台包、tarball 完整性记录。

证据：[npm 发布元数据](https://registry.npmjs.org/@deepseek-ai/dsh/0.2.2-rc.1)、
[CLI package.json](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/apps/cli/package.json)、
[官方启动说明](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/README.md)。

官方 Node v24.22.1 的构建文档将 Linux ARM64 列为 Tier 1，发布二进制要求
glibc >=2.28、libstdc++ >=6.0.25（`GLIBCXX_3.4.25`），构建主机为 RHEL 8
加 gcc-toolset-12。实际分发依赖应以所选 Node 24.22.2 ELF 的 PT_INTERP、
DT_NEEDED 和版本符号检查为准，不能只由相邻版本文档推断。
[Node 官方构建文档](https://github.com/nodejs/node/blob/v24.22.1/BUILDING.md)。

## 不能省略的运行能力

| 能力 | 需求与证据 |
| --- | --- |
| glibc 与动态加载 | Node Linux ARM64 及 DSH `.node` 扩展需要完整的用户态动态链接路径、TLS、依赖搜索和文件映射；仅解释 JavaScript 不足以证明兼容。 |
| 线程与事件循环 | Node/libuv 的真实线程、同步、异步文件 I/O、定时器、套接字和事件等待须实际工作；`node --version` 不覆盖这些。 |
| 可执行内存 | V8 正常模式和原生模块必须按所选 Node 实测；`--jitless` 可以定位问题，但不能直接把该诊断模式算成默认 Node 兼容。 |
| 文件与进程语义 | HOME、cwd、PATH、临时目录、chmod、符号链接、rename、文件监视、锁、子进程、管道及进程回收须按实际测试补齐。 |
| 网络与证书 | npm/pnpm 下载需要 DNS、TCP/TLS 和 CA；DSH Web 需要 loopback HTTP/WebSocket；模型 API 的连通性是另一个验收项。 |
| 原生扩展 | CLI 直接依赖 `node-addon-require-builtin:^0.1.9`；不得用隐藏失败或跳过原生加载的替身代替官方依赖。 |
| 会话锁 | `@deepseek-ai/node-addon-system` 的 `./flock` 使用异步非阻塞 POSIX flock；Linux ARM64 提供 glibc/musl `system.node`。须验证真实跨进程冲突及最后引用关闭后的释放。 |
| SQLite | 常规 base-backed profile 使用内存 SQLite 会话索引，相关存储采用 `node:sqlite`；只启动不含 SQLite 的 sdk-minimal 不能代表常规 profile。 |
| 命令与终端 | `dsh-subprocess-local` 依赖 `node-pty:1.2.0-beta.15` 和 `koffi:3.1.1`，带 spawn-helper 安装脚本；需要真正的子进程与 PTY 验收。 |

资料：[系统原生模块](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/native/system/README.md)、
[原生支持矩阵](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/native/system/docs/support-matrix.md)、
[子进程依赖](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/packages/subprocess/subprocess-local/package.json)、
[子进程行为](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/packages/subprocess/subprocess-local/README.md)、
[SQLite 存储](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/packages/storage/storage-sqlite/README.md)。

Linux 子进程 provider 优先尝试 user-systemd scope，在无可用用户 manager 时有
明确警告的 PGID fallback；Android 无 systemd 不必然让所有命令都无法运行。
但 `/proc` 观测、进程组、信号和退出等待仍需真实语义，不能伪造 scope 成功。
该 provider 支持额外控制 fd 7，fd0/1/2 与控制通道在 exec 后的继承也应覆盖。

DSH 内部 sandbox provider 在 Linux 依次探测 bwrap、Landlock；无可用后端时
`workspace-write` 命令明确报 `SANDBOX_UNAVAILABLE`。Sucrune 项目文件隔离
本身不能冒充通过 DSH 的 Landlock 功能探针。若最终采用另一个 DSH 执行适配器，
应作为显式配置与额外开发记录；不能静默降低权限模式或谎报强隔离。
[sandbox-local 契约](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/packages/sandbox/sandbox-local/README.md)。

## 安装和启动路径

先安装独立 guest 项目的 Linux ARM64 Node、npm，以及完整 DSH 依赖闭包。
不把宿主 Windows `node_modules` 当成 Linux ARM64 安装结果。包的安装脚本、
平台包选择和加载扩展都属于验收范围；离线预置可以作为分发方式，但须说明
安装发生在哪里，不能称之为手机内 `npm install` 已通过。

```sh
node --version
npm --version
npm install --prefix /opt/sucrune-dsh @deepseek-ai/dsh@0.2.2-rc.1
node /opt/sucrune-dsh/node_modules/@deepseek-ai/dsh/lib/bin.js --version
node /opt/sucrune-dsh/node_modules/@deepseek-ai/dsh/lib/bin.js --help
DSH_HOME=/workspace/dsh-home node /opt/sucrune-dsh/node_modules/@deepseek-ai/dsh/lib/bin.js web --no-open --host 127.0.0.1 --port 3080
```

这里的安装与 Web 行仍是后续验收命令；本轮通过下述离线部署路径验证了 CLI
版本与帮助，不声称手机内 `npm install` 或 Web 服务已通过。直接调用 `lib/bin.js` 可先
排除 `/usr/bin/env` shebang 入口问题，但后续仍应验证普通 `dsh` 命令的 PATH
和 shebang。官方 CLI 会初始化所选 profile，并使用调用目录作为默认文件系统
位置。Web 启动行在完整 Loader tree 就绪后输出；验收应随后验证带认证的 HTTP
页面及实际前端加载，不能只匹配一行 stdout 或硬编码 `/health` 存在。

插件包管理走 `dsh plugin --profile <name> <pnpm args>`，要求 pnpm 在 PATH。
安装源码插件可能运行 prepare/build；npm、pnpm、git、Bash 和工具链应分层
测试，不能由 DSH Web 页面出现推导包安装或创造模式已可用。
[CLI 行为参考](https://github.com/deepseek-ai/deepseek-harness/blob/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/apps/cli/reference/README.md)。

## 离线 SDK fixture 与有限真机验证

2026-11-07 已准备官方 `0.2.2-rc.1` 的 `sdk-minimal` 依赖素材，并完成下述
有限真机启动验收。固定 npm lock、官方 tarball SHA512、
Linux ARM64 glibc 平台包及安装脚本审查见
[完整来源记录](dsh-rootfs-provenance.json)；CLI 与原生扩展的独立验收说明见
[离线验证记录](dsh-offline-validation.json)。准备阶段没有执行 DSH、包生命周期
脚本、模型请求或手机内 npm 安装。

[离线准备脚本](../scripts/prepare-dsh-rootfs.ps1) 的 `SdkMinimal` 模式保留原版
CLI 和该 profile 的递归依赖，共 **212 个完整包、24,424 个文件、367,519,382
字节**。每个选中包的全部 regular-file payload 均保留，包括原生扩展、类型与
开发资源；没有按扩展名裁剪。该闭包从 CLI 启动依赖、官方 sdk-minimal 以及
profile-boot 额外导入的 http-proxy/cmdline 展开，没有展开其它 Web/ACP/profile
根依赖，不能据此声称完整 DSH 安装已验证。完整 654 包的来源与恢复索引另存。

为避免逐文件跨进程导入，已生成单个 gzip 自描述安装包
`.build/dsh-rootfs-sdk-minimal/rootfs.bundle.gz`，大小 **94,883,559 字节**，
SHA256 为 `95c99e5cfd9af26f33b8851eac3fece35de0a98b8cb1114593db9d624f24e0f0`。
独立宿主字节校验已检查全部文件的路径、mode、长度、SHA256、gzip CRC 与
解压 EOF。随后，真机上的原版 Linux Node 实际执行了辅助安装器
[guest-install-bundle.cjs](../scripts/guest-install-bundle.cjs)，再次流式校验全部
24,424 个文件后原子发布新目录；没有修改 DSH 代码，也没有执行 npm 安装脚本。

本轮有限验收入口是 `/usr/bin/node
/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js sdk-minimal`，显式采用
`linux-jit`，使用新建项目中的空 HOME、DSH_HOME、工作目录和有限空 stdin。
此前 `linux-dsh-directory.txt` **31/31 通过**：官方 EOF 路径等待 launcher 的
appReady，再正常退出；严格检查没有启动失败或未激活插件，并核对生成的
profile package/bundles、223 字节 `cordis.yml`、217 字节 `cordis.patch.yml`
与 61 字节 `pnpm-workspace.yaml`。同轮还通过原版 CLI 版本/帮助、真实 N-API
扩展调用，以及 Node 的 181 项目录扫描/流式读取回归。

两处实际兼容性问题已依次修复：原生扩展用 `msync(page, 1, MS_ASYNC)` 检查
映射，运行时现按逻辑 VMA 验证匿名/私有映射，拒绝保留区中的空洞；之后
glibc `opendir` 的 `O_NONBLOCK` 曾被文件代理拒绝，现将客体状态与代理内部
非阻塞保护分别保存，支持共享描述符的查询、设置和清除。实际固定 libc 的
ARM64 `opendir` 反汇编也确认 flags 为 `0x84800`，不是仅依据上游猜测。
[扩展检查源码](https://github.com/deepseek-ai/dsh-node-addon-require-builtin/blob/master/packages/native/src/runtime_probe/posix.cc)、
[glibc opendir](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/unix/sysv/linux/opendir.c)。
扩展 master 源码与发布二进制的符号、错误信息相互印证，但尚未建立该 npm
二进制到 master 精确提交的构建对应关系。`msync` 尚不支持共享文件写回，
长度页取整溢出保守返回 ENOMEM；此前失败、中断及修复后的日志均保留在验证记录。

有限 EOF 启动本身不证明 SDK 双向 JSON-RPC、Web、常规 Agent 会话或手机内
包安装已可用。有限预排 stdin 加 EOF 会与异步协议请求产生退出竞争；下述
新增握手采用受控双向输入。精确环境、产物断言、安装包协议和方案见
[SDK fixture 验证说明](dsh-sdk-minimal-validation.json)。本阶段不替代下述
Web、子进程、包安装与 Agent 工作流验收门槛。

后续加入交互输入的 `linux-dsh-interactive.txt` 完成 **30/36**：新增 Node
往返/空输入测试暴露 fd0 套接字类型识别缺口（syscall 204），另有一次前序
执行尚未终止导致的环境忙冲突；客体主动关闭 stdin 的检查通过。该轮 SDK
安装等待超过期限，应用重新进入前台后 watchdog 与套件立即恢复推进，随后
报告 wait_timeout；SDK EOF 和握手两项因安装前置条件未确认而没有执行。
标准 dumpsys 当时没有显示 frozen/cached，设备处于 Awake，因此这仅是
前台恢复与进展恢复的关联证据，不能归为安装器内部错误或确定某个 OEM
冻结机制。后续验收显式保持应用前台，后台运行可靠性仍未验证。

补齐现有本地 FD 的套接字名称/类型查询后，显式前台的
`linux-dsh-interactive-queries.txt` 完成 **34/36**。原版 SDK 的有限 EOF
启动与双向握手均通过：保持 stdin 打开，先核对 initialize 响应中的
`deepseek-harness-sdk-runtime/0.0.1`，再发送 shutdown，确认 `{}` 响应、
退出码 0 和四项清理条件；总输入 206 字节、通知 0 条。没有发起模型或工具
请求，也没有运行 Web、外网或手机内 npm 安装工作流。
[协议与证据](linux-sdk-protocol-validation.md)。
该轮两项空输入取消/超时用例仍计为失败：终态 cancelled/timed_out、零输入及
清理条件正确，但旧断言不接受终止过程中出现 EOF。该历史记录仍保持
34/36；测试终止边界与取消发布顺序修订后，结果另记在下面的最终轮次中。
套接字元数据查询不代表 Linux 客体已有完整网络支持。

最终固定构建在显式保持前台的条件下完成 `linux-dsh-interactive-final.txt`
**36/36**。原版 Node 的四项交互输入检查、官方 DSH CLI/原生扩展、完整
SDK-minimal fixture 的真实客体内安装、EOF 启动及严格 initialize→响应→shutdown
握手均通过；握手仍是 206 字节输入、0 条通知、退出 0 和四项清理条件。
最终日志 SHA256 为
`D1C42DBD7EE93F658FE07AD3B34510066347F1E6C68916A29E7FAA35554C398A`。

同一对 APK 随后通过旧 bundled backend 的 I/O **12/12**、exec **11/11**
和 tools/Lua **10/10** 回归，合计本次最终应用验收 **69/69**。I/O 中旧
O_NONBLOCK 拒绝断言导致的 11/12 失败仍保留；最终用例验证共享描述符的
真实 set/clear 及不支持 O_ASYNC 的拒绝。更早七组 **58/58** 是历史基线，
没有冒称全部在最终构建重跑。最终设备诊断确认项目和导入临时文件列表为空，
两个测试 App 保留；诊断不计为第 70 个功能用例。

这些结果验证了具体 Linux/Node 与 SDK-minimal 工作流；常规 GNU/Linux
fork/exec、Node child_process、PTY、完整网络、Web/Agent profile、手机内
npm 安装及后台可靠性仍需独立验收。本轮未发送模型或工具请求，也未读取
用户凭据。最终 APK、各组日志摘要、历史失败与清理证据见
[Android 15 验证记录](validation/android15-linux-progress.json)。

## 验收门槛

1. **原生 Linux 程序**：glibc 动态程序在 Android 非调试 isolated worker 执行，
   argv/env/cwd、文件读写、退出码、异常、取消、期限和原有清理条件正确。
2. **真实 Node**：不只版本号；执行 JS/ESM、读写 Unicode 文件、异步 fs、
   worker_threads、计时器、crypto、网络、HTTP 服务、动态 `.node` 加载和
   child_process。两个项目并发执行，文件/结果独立。
3. **常规环境**：真实 Bash/基础工具、npm 安装并运行一个小包、PATH/shebang、
   子进程及 pipe、实际终止回收。包安装网络错误与 syscall 不兼容分别记录。
4. **DSH 启动**：固定版本完整依赖安装、CLI `--version`/`--help`，正常 Web
   profile 就绪、认证后页面和 WebSocket 可用，无 required-plugin 启动失败。
5. **DSH 工作流**：创建项目/会话、读写文件、执行 shell、保存并恢复会话、
   插件安装/加载及取消。模型调用可先用明确标注的本地 mock 验证协议，真实
   API 请求另记；缺少凭据不能伪造模型成功，也不能把未测项改成已完成。
6. **清理与证据**：保留 APK、依赖锁与摘要、精简诊断和持久产物；删除本轮
   scratch、截图/原始日志，继续保留两个测试 App 及签名。

`--version`、`sdk-minimal`、Web 静态文件、宿主 Node 和桌面 Harness 分别只证明
其实际检查范围。任何不支持能力都必须在最终兼容性表中写明真实失败与原因。

## 本地 DSHA 参考边界

检查本地 DSHA 项目的 `tools/dsh-runtime/package.json` 和 lockfile，发现其
冻结 DSH `0.1.7-alpha.2`；这是相邻 Android App 的旧兼容基线，不是本轮固定
的官方新版本。该 lockfile含 `node-pty:1.2.0-beta.15`、系统原生模块、Koffi、
Sharp 与 node-addon-require-builtin 平台包，说明既有 App 已处理大量 Linux
运行依赖。未读取凭据、未修改该项目、未运行其 Harness、未复用其运行结果。

DFY DSH Desktop 是另一个桌面载体；用户最早引用的官方仓库及本轮目标默认
对应上述官方 CLI/Web profile，不要求把 Electron 桌面壳运行在 Android。
