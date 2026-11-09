# Android 15 ARM64 真机验证

2026-11-07，Sucrune 在 OnePlus PKR110 的普通应用服务与隔离服务中，通过了受控 syscall 陷阱、信号处理和恢复执行实验。debug 与不可调试 validation 两种构建各 4/4 通过，合计 8/8。

本次没有使用 root，也没有修改系统设置。ADB 用于安装、启动 instrumentation、读取结果及卸载；原生探针实际运行在 APK 创建的服务进程内。

## 设备与构建条件

| 项目 | 实测条件 |
| --- | --- |
| 设备 | OnePlus PKR110 |
| Android | Android 15，API 35 |
| ABI | ARM64 |
| 页大小 | 4096 字节 |
| 内核 | `6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k` |
| 系统构建 | user，ro.debuggable=0 |
| SELinux | Enforcing |
| 应用版本范围 | minSdk 29，targetSdk 37 |
| 普通服务身份 | UID 10418 |
| 隔离服务身份 | 本次观察到 UID 99242 至 99245 |
| validation 配置 | 所有用例 debuggable=false；本地开发签名，不是正式 release 包 |

实际设备序列号、完整 fingerprint 和原始报告均不保存在本记录中。

## 用例结果

| 构建 | 普通服务 | 隔离服务 | 总结果 |
| --- | --- | --- | --- |
| debug | 2/2 通过 | 2/2 通过 | 4/4 通过 |
| validation | 2/2 通过 | 2/2 通过 | 4/4 通过 |

同一服务的第二次测试在第一次工作进程的 Binder death 已确认后开始。用例之间顺序执行，本次没有测试多项目并行。

## 已核对的机制证据

- 服务进程继承的 seccomp 已是 FILTER 模式 2，专用工作线程仍能叠加本次过滤器。
- 初始 no_new_privs 为 0；工作线程设置后为 1。
- ARM64 getpid 调用号为 172。过滤器同时匹配调用号与受控汇编桩 syscall 后的精确返回 PC，单次调用触发一次 SIGSYS。
- 信号处理器运行在备用信号栈上，写回合成返回值 424242；调用方恢复执行后收到该值。
- 不经过该受控位置的 getpid 返回真实 PID，gettid 在陷阱前后保持一致。
- 原 SIGSYS 处理器恢复成功，工作线程 join 成功。
- 服务返回后，监督方确认对应 Binder death，满足一次性工作进程退出要求。

这些结果说明，在本机 Android 15 的两种应用身份和两种构建配置下，指定 getpid 的陷阱、处理与恢复链路可以成立。它们不说明应用可以移除系统原有的 seccomp 过滤器。

## 解释范围

本次没有验证：

- 任意指令位置或全部系统调用的拦截与仿真。
- ARM64 ELF 加载、可运行 Linux rootfs 或通用 Linux 软件兼容性。
- 并行多沙箱、跨项目恶意代码隔离及安全边界。
- 手机性能、资源隔离、能耗和长期稳定性。
- Android 10、x86_64 AVD、16 KB 页大小。
- 异常注入、界面退出或退后台、超时与原生崩溃恢复。
- 正式发布签名及最终发布配置。

## 复验入口

按 [设备验证流程](../device-validation.md) 构建、安装并运行同一 instrumentation。不可调试构建可通过：

```powershell
.\scripts\build-android.ps1 -Variant validation
```

对应 Gradle 任务：

```powershell
.\gradlew.bat -Psucrune.testBuildType=validation :probeapp:assembleValidation :probeapp:assembleValidationAndroidTest :probeapp:lintValidation
```

复验时必须重新确认 Android API、targetSdk、ABI、页大小、进程身份及 debuggable 标志，不将本次结果自动推广到其他设备或配置。

## 清理与保留范围

测试 APK `com.sucrune.probe.test` 与主 APK `com.sucrune.probe` 已卸载，并通过包列表查询确认无残留。本次原始临时日志已清理，仅保留此处经过核对的配置和结论。

本记录不附原始 JSON 或 logcat。后续需要更多证据时应重新运行探针，不能将已删除的原始日志作为可重新审查的附件。
