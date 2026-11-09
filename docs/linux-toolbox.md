# Android Linux 命令验证范围

Go 编译、OpenJDK 与两类 Android Activity 的构建流程见[真机编译工具链](linux-compilers.md)。

首轮 Android 15 工具验收通过 29/29，并复现了 Bash、ash 嵌套管道和 tar 压缩三个进程限制。[首轮记录](validation/android15-linux-toolbox.json)

补齐嵌套进程后，同一台无 root 手机的工具工作流通过 32/32，包含上述三个原先失败的用例。原版 DSH 持久 Bash 组通过 3/3。Git 的 HTTPS 取远端 HEAD 在早期尝试中出现过超时，最终通过了默认 HTTP/2 和强制 HTTP/1.1 两条路径。[本轮验收](validation/android15-distro-rootfs.json)

## 复现测试

在已有 Node/glibc、Bash 和 DSH 验证资产的 Sucrune 项目中，从项目根目录执行以下命令。前三个准备器从锁定的 Debian 包生成工具层，已缓存软件包时可传 `--offline`。聚合步骤只生成 instrumentation 资产 `.build/linux-test-assets/linux-toolbox/profile.bin`。正常运行时构建不依赖这些准备器。

```powershell
python scripts/prepare-linux-base-tools.py
python scripts/prepare-git-curl.py
python scripts/prepare-linux-python.py
python scripts/prepare-toolbox-fixture.py
```

按 [设备验证说明](device-validation.md) 构建 validation 并用 `adb install -r` 覆盖安装两个 APK。第一条命令在新项目中验证工具工作流；第二条让已注册的 DSH Bash 工具在自己的 PTY 中按名称执行程序。仅 Git 和 curl 的公网用例申请出站访问，两条测试都可在没有模型密钥的情况下运行。

```sh
adb shell am instrument -w -r -e probe linux -e focus toolbox -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
adb shell am instrument -w -r -e probe linux -e focus dsh_tool -e dsh_tool true -e sdk true -e node true -e toolbox true -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

## 运行时与用户空间

`RuntimeClient` 目前是应用内接口。上层 App 可以将文件清单、工具版本、许可证与 rootfs 更新策略维护在自己的项目里，安装后经项目文件 API 导入，再用 `executePath` 启动指定的 Linux ELF。两个独立安装的 Android APK 如需直接通信，还需要另行设计跨 App IPC。通用发行版 tar 的解包、包管理器和安装脚本也有各自的兼容性要求。

上层 App 为项目提供 rootfs 和依赖，Sucrune 负责加载 ARM64 Linux ELF、处理其系统调用并限定文件及进程的可见范围。本次命令、库和验收脚本由测试 APK 提供，测试只向临时项目导入这些文件。运行时 APK 的程序目录不包含这批工具。

PRoot 接受一个包含 shell、库和工具的 Linux 根文件系统，其官方示例从根文件系统执行 `/bin/sh` 和 `cat`。能否运行某条命令取决于所选发行版以及运行时对其系统调用的支持。Sucrune 用固定版本的 Debian ARM64 程序测试这两个条件。[PRoot 官方示例](https://proot-me.github.io/)

| 上游项目 | 可复现的对照点 | Sucrune 对应验收 |
| --- | --- | --- |
| bxroot | 用发行版的 Bash、Node 启动程序，用 find 遍历、stat 查询元数据。[项目说明](https://github.com/qiannianhuanxiang/bxroot) | 现有 Bash 和 Node 用例，加上递归查找、文件模式、硬链接和脚本。 |
| proroot | Ubuntu 环境的 CLI 清单包括 Git、curl、Python 和 Node/npm，也列出 Chromium 等图形应用。[项目说明](https://github.com/coderredlab/proroot) | Git 仓库、curl 传输、Python 脚本各自使用独立 ARM64 工作流。 |
| DeepSeek Harness | 文件搜索插件使用随包分发的 ripgrep，终端插件提供 Bash。[搜索插件](https://github.com/deepseek-ai/deepseek-harness/tree/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159/packages/fs/tool-fs-search) | 给用户 shell 独立提供 Debian 的 `rg`，测试递归 glob、忽略规则、匹配行号；用已有 DSH 测试单独验收插件。 |

## 测试项目中的命令

`scripts/prepare-linux-base-tools.py` 校验锁定包的长度、SHA-256、ARM64 ELF 头和动态库依赖，并从锁定 BusyBox 的 applet 表逐一核对 96 个入口。`/bin/sh` 与常用工具按启动名称选择 applet，`rg` 和 `jq` 是独立 ELF。清单和文件写入 `.build/toolbox-inputs/linux-base-tools`，供测试项目导入。[Debian BusyBox](https://packages.debian.org/bookworm/busybox-static) · [BusyBox 命令说明](https://busybox.net/downloads/BusyBox.html) · [Debian ripgrep](https://packages.debian.org/bookworm/ripgrep) · [Debian jq](https://packages.debian.org/bookworm/jq)

| 工作流 | 测试断言 |
| --- | --- |
| shell、文本与参数 | 按 DSH 的用法启动 `/bin/bash run.sh`。检查 grep/sed/awk/sort/uniq 管道、重定向、命令替换、环境变量和退出状态。另用独立的 `/bin/ash` 脚本访问文件、执行管道和读取 `/proc/self/stat`。 |
| 文件与权限 | 从 mkdir、cp、mv、ls、find、xargs 到 rm/rmdir。检查 chmod 后的模式，从硬链接写入并从原始名称读回，删除别名后再次访问原文件。 |
| 归档、校验与补丁 | 用 `tar -cf`、`gzip -c`、`gunzip -c` 和 `tar -xf` 校验带空格文件的往返。bzip2 往返、解 xz/zip、读 ar，比较 MD5/SHA 校验和，并将 diff 生成的补丁应用到原始文件。 |
| 程序与数据 | 在非 root UID 上验证日期、架构和项目可见的 `/proc/self/stat`。执行 `rg` 检查文件过滤及行号，`jq` 检查排序、正则筛选及逐行输出。 |

| 在脚本中调用的 BusyBox 命令 | 命令名 |
| --- | --- |
| Shell、参数与状态 | `sh ash env which getopt printf echo test [ true false expr` |
| 文件、目录和路径 | `basename cat chmod cmp cp dd dirname du find ln ls mkdir mktemp mv pwd readlink realpath rm rmdir stat touch truncate unlink xargs` |
| 文本、筛选与字节 | `awk base64 cut diff dos2unix expand fold grep head hexdump less nl od paste patch rev sed seq sort strings tac tail tee tr uniq wc xxd yes` |
| 归档与校验 | `ar bunzip2 bzcat bzip2 gunzip gzip md5sum sha1sum sha256sum sha512sum tar unxz unzip xz xzcat zcat` |
| 时钟、身份与终端 | `clear date id kill ps sleep tty uname` |
| 只核对 applet 表和入口 | `chgrp chown df mkfifo nproc time timeout whoami` |

部分名称也是 shell 内建命令。脚本中的 `kill` 和 `[` 走 shell 的正常名称解析，显式路径用例包括 `/usr/bin/test`、`/usr/bin/printf` 和 `/bin/pwd`。

`base_pipeline_sibling_group` 用两个实际 fork 出的子进程验证作业控制。第一个进程建立组并等待管道消息，第二个进程自行调用 `setpgid` 加入该组，并检查无关 PGID 会被拒绝。DSH 的交互式 Bash 用例还检查真实 PTY 管道没有打印 `child setpgid` 错误。

96 是安装清单中的命令入口数。工作流验收以 `LinuxBaseToolChecks.kt` 的逐项结果为准。例如 `ps -o pid,comm` 要求列出的唯一 PID 与该次执行的 PID 相符，`ln` 检验硬链接，`readlink -f` 检验规范化路径。符号链接创建、交互式分页、命名管道、变更文件属主和定时终止进程均需要单独用例。

Android 15 已跑通 Bash、ash 命令替换内的多级管道，以及 BusyBox tar 通过 gzip 子进程压缩、解压并复原文件。三个正向用例已加入工具包回归。

## 版本控制、HTTPS 和 Python

| 程序 | Android 15 ARM64 真机已验证 | 还需要单独验收 |
| --- | --- | --- |
| Git 2.39.5 | 在项目中初始化仓库、暂存、提交、切换分支、检查差异并恢复文件。用 `git clone --local` 得到第二份工作树，核对 HEAD 和文件内容。用 `git ls-remote https://github.com/proot-me/proot.git HEAD` 检查 HTTPS 助手能取得远端引用。 | 网络克隆和 fetch 的 pack 传输、向远端 push、SSH、凭据助手、子模块与 Git LFS。 |
| curl 7.88.1 | 授予该次执行出站权限后，使用发行版 CA 访问 `https://example.com/`。同时核对 HTTP 200、TLS 证书校验结果 0，以及写入项目的响应正文。 | 带代理或客户端证书的连接、上传、长时间下载和断点续传。 |
| CPython 3.11 和 pip | 执行脚本，读写 JSON，压缩和解压 gzip、bzip2、xz，查询 SQLite，并加载 CA。子进程用例独立检查 stdin、stdout、stderr 和退出码。用 `python3 -m pip` 离线安装本地纯 Python wheel，另起解释器导入并调用模块。 | 从 PyPI 联网解析依赖、构建带 C/Rust 扩展的 wheel、创建 venv 以及执行 pip 生成的 CLI。 |

工具包锁定 Debian 包版本、下载长度和 SHA-256。Git 的 HTTP 助手使用 Debian 的 GnuTLS 版 libcurl，独立的 curl 命令使用 OpenSSL。两个 HTTPS 用例使用公开资源和项目内的 CA 合集，无需账户配置。[Debian Git](https://packages.debian.org/bookworm/git) · [Debian curl](https://packages.debian.org/bookworm/curl)

## 发行版链接和脚本入口

已有工具夹具把一些上游链接安装为普通文件或硬链接。导入新 rootfs 时可以保留原始的绝对、相对和目录符号链接，由项目 broker 解析。

带 `#!` 的可执行脚本可作为启动入口，解释器和 `/usr/bin/env` 搜索的命令均来自项目。参见[Alpine rootfs 导入与验收](linux-rootfs-import.md)。

TCP 客户端可直接使用阻塞 `connect`，或通过 `fcntl`、`FIONBIO` 切换非阻塞连接。两种模式均由 broker 校验目的地址。阻塞连接及常用读写在 worker 等待就绪，已连接流支持无目标地址和辅助数据的 `sendmsg`、`recvmsg`。监听和跨 `fork` 继承 TCP 仍要求非阻塞模式。Linux 主线程的 ELF 原地替换限于没有其他未汇合的 guest 线程。固定地址保留区可以在空闲地址范围扩展；单次执行链限 32 次替换。
