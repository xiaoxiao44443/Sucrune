# 项目、命令和常驻服务

项目文件和已安装依赖从创建保留到显式删除。运行时按执行分配 Android worker。某条命令退出后即可回收它的 worker，即使同一项目的对话或服务仍在继续。两次工具调用之间，Agent 可以只等模型回复，下一次调用使用同一个项目 ID 和工作区。

| Agent 或用户的操作 | 运行时行为 |
| --- | --- |
| 执行普通命令 | 默认从提交起计时 30 分钟，调用方可设更短的期限。单条命令超时只终止该次执行。 |
| 启动 Web 服务、文件监视器或队列消费者 | 在启动该 Linux 进程时传一次 `resident = true`，省略 `timeoutMs`。监督器持续持有它，直至退出、显式取消、项目删除或宿主终止。 |
| 聊天结束、服务长时间无请求、端口暂时没打开 | 已声明的服务继续运行。调用方无需上报端口、CPU 或心跳。关闭网络时也可运行常驻进程。 |
| 停止其中一个服务 | 对启动时返回的 execution ID 调用 `cancel(id)`。同项目的其他执行保有自己的 worker。 |
| 用户删除项目 | App 在后台线程调用 `deleteProject(id)`。运行时立即阻止该项目新执行、取消它的所有执行，等 worker、输出、代理和标准输入都已收尾，再删除工作区和依赖。App 可在成功返回后移除自己的项目记录。 |

```kotlin
val server = runtime.executePath(
    envId = projectId,
    path = "/usr/bin/python3",
    argv = listOf("-m", "http.server", "8080", "--bind", "127.0.0.1"),
    env = listOf("SUCRUNE_NETWORK_POLICY=loopback"),
    resident = true,
)
// 该项目仍可运行普通命令。需要停止服务时使用它自己的 execution ID。
runtime.cancel(server)
```

示例假设该项目的 rootfs 已包含 Python。服务主进程须持续在前台运行；在单独的默认 executePath 调用中从 shell 启动 `daemon &` 再让 shell 退出，仍按原执行的进程树清理。每个项目可以有一个普通执行及多个常驻执行，Android 管理器共提供四个并发槽，默认每次执行占一槽。宿主可为同一常驻服务显式声明不同写策略的配套进程，详见[执行 API](api.md)。端口仍受网络策略和绑定冲突约束。

这版没有单独维持的空闲 VM，也不保存进程内存快照。普通执行的 30 分钟是命令期限，常驻声明绑定到这一条执行。若上层以后增加“整项目连续空闲后释放预热资源”，可以按项目同时检查进行中的 Agent 轮次、执行和清理状态；等模型返回的轮次也算活动。当前无需为了等下一次工具调用而保留空 worker。

宿主进程死亡后管理核心会把未完成记录标为 `lost`。运行时的常驻声明不改变 Android 对宿主的调度，也不自动重启服务。项目删除保留既有执行历史。删除未能确认清理时向 App 返回错误，App 应保留项目并重试。接口和资源上限见[应用内 API](api.md)。

## 项目工作进程中的 Shell 后台任务

Sugar 为每个工作区启动独立的常驻项目 worker。宿主在顶层 executePath 中传入 `SUCRUNE_PROCESS_SCOPE=project`，同一个 worker 派生的 Bash 和终端通过私有通道继承作用域。独立调用 executePath 会建立自己的执行边界，即使使用相同的工作区目录，也不会加入已有 worker。子程序修改环境变量不会变更作用域。

在一次 Bash 调用中运行 `nohup python3 -m http.server 8000 >server.log 2>&1 </dev/null & echo $!`，后续同工作区的命令可使用返回的 PID 检查 `/proc/<pid>/stat` 或发送信号。重定向使服务的标准流脱离本次调用。工作进程结束或项目删除后，内核撤销作用域并终止剩余成员。后台任务不会在 Android 杀死宿主后自动重启。

项目内可对指定 PID 使用信号 0、HUP、INT、TERM 和 KILL。跨命令发送 STOP 或 CONT 会返回 EOPNOTSUPP，以免冻结用于回收进程的监视线程。负进程组号仅作用于本作用域内属于该组的成员。宿主控制进程和其他工作区不在普通命令的成员视图中。每个 worker 同时最多登记 128 个成员。目录和统计信息使用固定到登记进程的内核描述符，信号通过注册进程独占的租约套接字分发，避免 PID 复用影响其他项目。
