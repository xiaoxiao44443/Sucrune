# Android 真机内的 Linux 编译工具链

Sucrune 的测试 App 通过 `RuntimeClient.importFile` 把锁定并校验过的工具链导入一次性项目。测试用 `executePath` 在隔离 worker 中启动 Linux ARM64 程序。运行时 APK 的使用方可以独立选择工具链与 rootfs。首轮结果见[编译验证](validation/android15-linux-compilers.json)，进程改动后的结果见[发行版与 Go 构建验收](validation/android15-distro-rootfs.json)。

Android 15 真机上的最小 Kotlin 工程已通过原版 Gradle 离线冷构建、打包、系统安装、启动和随机界面文字核验。详细结果见[Gradle 构建与安装验收](validation/android15-gradle-build.json)。

## 覆盖范围

| 路径 | 验证内容 |
| --- | --- |
| Go 编译和链接 | 原版 Go 1.26.10 的 `compile` 把新源码编译为包，`link` 链接出 Linux ARM64 ELF，随后在同一项目执行。34 个传递依赖的标准库归档用同版 Go 在主机交叉编译，应用源码、主包和最终 ELF 在手机上构建。 |
| 标准 Go 驱动 | 普通 `go build` 在手机上编译主程序与标准库依赖（CGO 关闭，包级并行度为 1）。Linux/arm64 产物在同一项目运行并写出预期文件。Android/arm64 PIE 通过 ELF、动态解释器及构建设置检查。此路径无需预编译标准库层。 |
| Java | 用 OpenJDK 17 的 `javac` 编译 Java 17 类，用另一个 JVM 执行并检查输出。测试使用 `-Xint`、单活动 CPU 和 Serial GC。 |
| Kotlin/JVM | Gradle 9.3.1 分发中的 Kotlin 2.2.21 编译器在手机上编译新写入的 `.kt`。第二个客体 JVM 运行生成的 JVM 17 类，输出该次测试的随机标记。 |
| Android Java Activity | 在项目中写入 Activity 源码、XML 与 manifest，依次执行 javac、D8、AAPT2、zip、zipalign、keytool 和 apksigner。验收要求 DEX 含目标类，APK 包含原始 DEX、二进制 manifest、资源表，并通过对齐、签名和证书身份检查。 |
| Android Kotlin Activity 直接打包 | 客体 Kotlin 2.2.21 编译 Activity，随后运行 D8、AAPT2、zipalign 和 apksigner。真机已核对目标类、APK 中的原始 DEX、对齐与 V2 签名。首次安装命令等待超时，系统随后完成安装。验收从已安装的 base.apk 中读出此次构建的随机标记，启动 Activity，核对前台 TextView 含同一标记，最后卸载测试 App。 |
| Android Gradle Plugin | 客体 Gradle 9.3.1 调用 AGP 9.1.1 内置 Kotlin，执行 `:app:compileDebugKotlin`、`:app:packageDebug` 和 `:app:assembleDebug`。最终解释模式冷构建导出 2,433,332 字节的 debug APK，通过 Android 15 安装及前台 Activity 核验。 |
| Android NativeActivity | ARM64 TinyCC 把新 C 源码编译成对象文件，用 NDK API 29 的 libandroid.so 链接桩生成共享库，组装未签名 APK。验收检查 ARM64 ELF、NativeActivity 入口、动态依赖和归档内容。 |

直接调用 SDK 工具生成的 Java Activity APK 已通过同一台 Android 15 手机的安装、启动和界面验收。测试机收到的字节与客体导出的 APK 有相同的 SHA-256，系统将 Activity 切到前台后，UI 自动化读取了预期 TextView。验收结束后卸载生成的示例 App，临时签名密钥随测试项目删除。

## 复现

先按[工具包文档](linux-toolbox.md)准备基础 rootfs、Bash 和命令工具包。同版本主机 Go 用于准备标准库，已安装的 Android SDK 提供锁文件列出的平台、Build Tools 和 NDK。Python 脚本的 `--offline` 可使用已校验的包缓存。

```powershell
python scripts/prepare-go-compiler.py
python scripts/prepare-go-stdlib.py --go go
python scripts/prepare-linux-jdk.py
python scripts/prepare-linux-android-build.py --sdk "$env:ANDROID_HOME"
python scripts/prepare-linux-native-activity.py --sdk "$env:ANDROID_HOME"
foreach ($layer in 'linux-go','linux-go-stdlib','linux-jdk','linux-android-build','linux-native-activity') {
    python scripts/prepare-toolbox-fixture.py --compiler-layer $layer
}
```

使用项目的 `scripts/build-android.ps1 -Variant validation` 构建并覆盖安装 probe APK 与 androidTest APK。在当前设备运行全部工作流。

```powershell
adb shell am instrument -w -r -e probe linux -e focus compiler -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

`compiler_profiles` 接受逗号分隔的层名，例如 `go,go-stdlib` 或 `jdk,android`。`compiler_cases` 可选择记录中的单个工作流，例如 `linux_android_java_signed_apk`。默认 JVM 使用 Server VM。要独立测试 Zero VM，另运行 `prepare-linux-jdk.py --vm zero`，用 `--compiler-layer linux-jdk-zero` 打包后选择 `jdk,jdk-zero`。

## Gradle、Kotlin 和安装启动

Gradle 工作流在上述 JDK、Android 和基础层之外，向 androidTest APK 加载三个可选层。所有项目源码在新的手机沙箱写入。Gradle 使用本地 Maven 仓库和 `--offline`。

| 层 | 夹具内容 |
| --- | --- |
| `linux-gradle` | 原版 Gradle 9.3.1 分发、Debian ARM64 OpenJDK 的 jlink、jmod、jar 与 JVM 辅助文件。测试用客体 `java -jar` 调用 Gradle 启动脚本使用的同一个 CLI JAR。 |
| `linux-gradle-maven` | AGP 9.1.1、内置 Kotlin 对应的 2.2.10 依赖及传递依赖，按文件摘要从宿主 Maven 缓存还原至客体 `/opt/maven`。[Maven 夹具锁](../scripts/linux-gradle-maven.lock) |
| `linux-gradle-sdk` | 正式 SDK 平台 `platforms/android-37.0`（revision 2）的 `android.jar` 与平台元数据，Build Tools 36.0.0 元数据和可移植文件。六个 Linux ARM64 静态程序 aapt、aapt2、aidl、dexdump、split-select、zipalign 来自 `zhuwanhong/android-sdk-linux-arm64` 的 v1.0.0 发行归档，来源记录的 AOSP 标签为 `platform-tools-35.0.2`。准备时检查 SHA-256 和 AArch64 ELF，AGP 的 AAPT2 显式指向该层。[ARM64 工具来源](https://github.com/zhuwanhong/android-sdk-linux-arm64/releases/tag/v1.0.0) · [SDK 夹具锁](../scripts/linux-gradle-sdk-lock.json) |

示例工程使用 `compileSdk 37`、`minSdk 29` 和 `targetSdk 35`。本次物理设备为 Android 15（API 35）ARM64，安装测试使用该设备的包管理器。

本轮成品含 14 个 ZIP 条目和 3 个 DEX；全部条目的 CRC 校验通过。`apksigner` 针对 API 35 验证了 APK v2 签名，`zipalign -c 4` 与 `aapt2 dump badging` 均通过。系统安装后读到 `MainActivity` 的 TextView 文字 `Sucrune Kotlin 00fffbb9`，对应随机字符串也在该包的 `classes3.dex` 中。验收随后卸载样例并保留两枚测试 APK。

默认执行配置提供 64 个文件描述符和 100 万次系统调用预算，执行时限最长 5 分钟。Linux `executePath` 显式设置 `SUCRUNE_FD_PROFILE=build` 后可用 512 个文件描述符、6400 万次系统调用和最长 30 分钟。真机验证了高位文件与管道跨 fork/exec 的继承、CLOEXEC、共享偏移以及 select/poll。

真机已用解释模式和 HotSpot C1 启动 Gradle CLI、编译并运行 Kotlin/JVM 程序。客体 JDK 启动 AAPT2 daemon 编译并链接二进制资源。父 JVM 持有 280 个文件、阻塞 UDP 描述符为 285 时也能启动 AAPT2，并在子进程退出后继续收发。完整 Linux runner 对普通项目文件的一次 `write` / `pwrite64` 上限为 1 MiB，构建配置为 16 MiB。超过上限仍可能短写。

```powershell
python scripts/prepare-linux-gradle.py --gradle <解压的Gradle目录> --gradle-cache <含modules-2的缓存目录>
python scripts/prepare-linux-gradle-sdk.py --sdk "$env:ANDROID_HOME"
python scripts/prepare-toolbox-fixture.py --compiler-layer linux-gradle-sdk
```

构建、覆盖安装 validation 和 androidTest APK 后，用下列命令分别检查 Gradle、Kotlin/JVM 和 Android 工程。单机复现使用前台测试入口。安装工具把 instrumentation 导出的 APK 分块还原并核对长度与 SHA-256，检查系统安装结果、Activity 启动和前台文字，然后移除本次生成的示例 App。同名 App 已安装时会在构建前停止，部分手机首次安装需要在系统安装器中点击确认。

```powershell
adb shell am instrument -w -r -e probe linux -e focus compiler -e compiler_profiles jdk,gradle -e compiler_cases linux_gradle_version,linux_kotlin_compile_run,linux_gradle_build_fd_profile,linux_gradle_plain_datagram_close -e gradle_vm c1 -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
python scripts/test-guest-apk.py --serial <设备序列号> --workflow sdk
python scripts/test-guest-apk.py --serial <设备序列号> --workflow kotlin
python scripts/test-guest-apk.py --serial <设备序列号> --workflow gradle
```

需要保留成品时可加 `--apk-out <新文件.apk>`。以后用 `--verify-export <文件.apk>` 替代 `--apk-out`，可从同目录的 `.apk.json` 校验回执重试安装。脚本通过 `adb push` 传输，在手机端再次核对字节数与 SHA-256，然后交给系统安装会话。测试会清理手机上的传输文件和临时界面 XML。

直接运行 instrumentation 时，`gradle_vm` 默认 `interpreter`（`-Xint`，最大堆 384 MiB），`gradle_timeout_ms` 默认 300000。安装脚本也默认使用解释模式，将整包构建时限设为 1800000 毫秒。`--gradle-vm c1` 使用 HotSpot C1 和 512 MiB 堆。冷构建中曾出现间歇性 `SIGSEGV`，采样确认访问地址在 guest arena 内，具体触发原因尚未确定。两种模式均使用单活动 CPU、Serial GC、一个 Gradle worker 和进程内 Kotlin 编译。`--trace-gradle` 可采样 JVM 线程。

首轮整包构建在 `:app:processDebugResources` 遇到 AAPT2 daemon 启动失败。运行时补齐了持有阻塞回环 UDP socket 时的 fork 和子进程的 `RLIMIT_NOFILE` 查询。随后对 `:app:packageDebug` 补齐普通项目文件之间的 `sendfile`，以及大块 `write` 和 `pwrite64`。原版 AGP Zipflinger 已在真机写入并复制 1 MiB + 13 字节的条目，源、目标 ZIP 的校验和及内容一致。要单独定位资源处理，可在同一工程先执行资源任务再继续 `assembleDebug`。失败时测试会取回 Gradle 的异常原因链和失败任务。

```powershell
adb shell am instrument -w -r -e probe linux -e focus compiler -e compiler_profiles jdk,android,gradle,gradle-maven,gradle-sdk -e compiler_cases linux_gradle_kotlin_apk -e gradle_resources_first true -e gradle_vm c1 -e gradle_timeout_ms 1800000 -e keep_foreground true com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation
```

Gradle 启动参数包含 JDK 17 的 `-Djdk.net.usePlainDatagramSocketImpl=true`。严格回归验证了这个实现的回环收发、阻塞接收和跨线程关闭。默认 NIO 实现的接收线程也会醒来，但关闭方在 `NativeThread.signal` 中抛出异常。安装脚本的 `--trace-faults` 只对 `--workflow gradle` 生效。
