# 在 Android 项目沙箱中导入发行版

上层 App 可以为每个项目提供自己的 ARM64 Linux 用户空间。验证用的镜像是官方 Alpine 3.22.2 aarch64 minirootfs，源归档有 520 个条目，包含 87 个普通文件、98 个目录和 335 条符号链接。[Alpine 官方归档](https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.2-aarch64.tar.gz)

1. 在空项目中创建 `/.sucrune-bootstrap`，用 `RuntimeClient.importFile` 导入一个可信的静态 Linux ARM64 BusyBox 到 `/.sucrune-bootstrap/busybox`，设置可执行位。
2. 准备夹具时校验下载的 gzip 归档 SHA-256。测试 App 将 gzip 流解压，通过同一 API 把原始 tar 数据导入 `/.sucrune-rootfs.tar`，并独立校验解压后流的长度和 SHA-256。
3. 用 `executePath` 在项目的 `/` 执行这个 BusyBox，参数为 `tar -xof /.sucrune-rootfs.tar`。归档目录、链接文本和可执行文件由客体 tar 创建。普通 Android App 的 UID 承担存储所有权。
4. 上层 App 可直接启动项目里的 `/bin/sh` 或可执行脚本。项目路径解析会沿发行版自己的链接定位程序、ELF 动态加载器和脚本解释器。正式部署可在验收成功后移除解包工具和 tar 文件。

测试归档的 SHA-256 为 `6bf491907b705caa5fc65773fbbc1d0954530b6c455d4446f670a4c1fdcea489`。运行时 APK 的内容与用户选择的发行版独立。

## 路径和进程语义

- 绝对符号链接从项目根解析，相对目标从链接所在目录解析。目录链接可用于 `chdir` 和 dirfd 操作。失效链接可读取、重命名和删除；逐次查找最多展开 40 条链接，超过返回 `ELOOP`。路径字节上限为 1024，含结尾 NUL。
- Linux 可执行脚本支持 `#!` 和一个可选解释器参数。首行读取窗口为 256 字节，解释器链最多经过五个脚本。`#!/usr/bin/env …` 从项目启动 env，由它按客体的 PATH 查找程序。首次启动、进程内替换程序和 fork 子进程中的 exec 均有测试。
- 普通嵌套 fork 继承写时复制的地址空间，客体描述符表各自独立，继承的描述符引用同一内核打开文件描述。支持的 vfork 组合共享实际内存。发起调用的线程等待子进程成功 exec 或退出，其他客体线程继续执行。ARM64 探针覆盖共享写、另一个线程在等待期间执行系统调用、失败后重试 exec、退出与 exec 时清除 TID，以及通过 wait4 取得退出状态和内核资源统计。
- 在 fork 返回后、exec 新 ELF 之前，子进程使用有限的系统调用实现。它可以继续执行 fork，也可以执行 vfork。若这个子进程还有已登记的子进程，须先 wait 回收，exec 才能接管进程。已处于共享 VM 的 vfork 子进程再次调用 vfork 会得到 `EOPNOTSUPP`。
- vfork 子进程在此阶段按 clone 时的内存映射检查指针。父进程的其他线程新增的映射超出这一范围。如果其他线程同时撤销缓冲区的映射或写权限，正在回写结果的子进程可能收到 `SIGSEGV`。
- 在这个阶段，管道和本地套接字支持一次内核调用完成向量 I/O。项目文件的 `readv/writev` 按段经由文件代理传输，单次代理请求最多 4 KiB。并发访问同一打开文件时，各段之间可能穿插其他进程的操作。

## 复现

先按[工具包](linux-toolbox.md)和[编译器](linux-compilers.md)说明准备所选测试夹具。执行 `python scripts/prepare-linux-distro.py`，再构建 validation APK 与 androidTest APK。已有包缓存时可以加 `--offline`。

```powershell
adb shell am instrument -w -r -e probe linux -e focus distro -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
adb shell am instrument -w -r -e probe linux -e linux_processes true -e vfork_probe true -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
adb shell am instrument -w -r -e probe linux -e focus compiler -e compiler_profiles go -e compiler_cases linux_go_build_and_run,linux_go_build_android -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

逐项结果和设备信息见[Android 15 验证记录](validation/android15-distro-rootfs.json)。
