# Sucrune 运行时使用说明

0.7.0-linux-dev 在 Android 10+ ARM64 应用中提供固定程序和项目内 Linux ELF 两类入口。本文说明已有的无 libc Shell、libc 检查程序和 Lua 5.4.9，包括真实文件描述符复制、文件重定向和固定镜像 exec。原版 Linux Node、动态链接与交互输入见 [Linux 配置](linux-profile.md)；项目终端 UI 仍使用固定程序入口。安装和验证状态见 [设备验证](device-validation.md)。

## 在项目终端使用

打开 Sucrune Probe 的项目终端，新建项目，工作目录填 /、超时填 30 秒：

```sh
mkdir -p scripts output
printf '%s\n' 'echo "hello from script" > output/result.txt' 'cat output/result.txt' > scripts/build.sh
sh scripts/build.sh
```

预期 stdout 为 hello from script 加换行；产物保存在该项目的 output/result.txt。新一次执行中运行 `cat output/result.txt` 可读取同一内容。/ 代表项目根，不能用它访问宿主系统的 /proc 或其他项目。

变量与工作目录只属于一次执行，文件持久化。sh FILE 在当前客体内部创建变量／cwd 作用域，返回后恢复调用者作用域；文件修改保留，没有 fork 第二个 Linux 进程。

## 在同一 Android 应用内调用

以下片段在后台线程执行，使用现有 API，不需要 Agent 或模型：

```kotlin
val client = RuntimeClient.get(context)
val envId = client.createEnvironment("demo").getString("id")
client.makeDirectory(envId, "/scripts")
client.makeDirectory(envId, "/output")
client.writeFile(
    envId, "/scripts/build.sh",
    "echo 'hello from script' > output/result.txt\ncat output/result.txt\n"
        .toByteArray(Charsets.UTF_8)
)
val id = client.execute(envId, "sh /scripts/build.sh", timeoutMs = 30_000)
val result = client.waitFor(id, 35_000) // 不在主线程调用
check(result.getString("state") == "exited" && result.getInt("exit_code") == 0)
val artifact: ByteArray = client.readFile(envId, "/output/result.txt")
```

writeFile/readFile 是当前的导入导出边界：接收、返回字节，不附带文档选择器或分享 UI。项目终端也不是完整文件管理器。

创建另一个环境可并行执行，各自相同路径指向不同 workspace。同项目可有一个普通执行及多个常驻 Linux 服务，全局共享四个并发槽。每次执行默认占一槽；宿主显式声明的同一常驻服务可按写策略共槽，详见[执行 API](api.md)。

## 用 Lua 处理输入并生成产物

项目终端选择“Linux 程序 · Lua 5.4.9”，argv 输入一行 `-`，stdin 输入
`print("Hello from Lua")` 后运行即可。UI 将 stdin 文本编码为 UTF-8；二进制
输入通过下述应用内 ByteArray API 传入。

`client.listPrograms()` 返回原生程序目录。本版的 `lua` 接受上游 Lua 命令行参数，
例如 `listOf("-e", "print(1 + 2)")`，或以项目内脚本路径为第一个参数。
参数仍逐项传递，不经过 Shell 分词。下例在后台线程运行，把有限 stdin 中的数值累加后写入项目文件：

```kotlin
client.makeDirectory(envId, "/scripts")
client.makeDirectory(envId, "/output")
client.writeFile(envId, "/scripts/sum.lua", """
    local sum = 0
    for line in io.lines() do
        sum = sum + assert(tonumber(line))
    end
    local out = assert(io.open("/output/result.txt", "w"))
    assert(out:write(tostring(sum), "\n"))
    assert(out:close())
    print("sum=" .. sum)
""".trimIndent().toByteArray(Charsets.UTF_8))
val id = client.executeProgram(
    envId, "lua", argv = listOf("/scripts/sum.lua"),
    stdin = "10\n20\n12\n".toByteArray(Charsets.UTF_8)
)
val result = client.waitFor(id, 35_000)
check(result.getString("state") == "exited" && result.getInt("exit_code") == 0)
val artifact = client.readFile(envId, "/output/result.txt") // 42 加换行
```

Lua 支持循环、函数、table、字符串、纯 Lua 模块和语言级 coroutine；coroutine
不等于客体 OS 线程。模块可写入项目，再传 `env = listOf("LUA_PATH=/scripts/?.lua")`
供 `require` 使用。`os.clock()` 使用 worker 的进程 CPU 时钟，不是独立客体 CPU
计费器；Lua 的 SIGINT handler 安装仍不受支持，取消由 Android 监督器终止 worker。

stdin 最多 1 MiB，支持二进制和 NUL，入口复制数据后异步写入；发完关闭即 EOF。
未传输入也是 EOF。客体可提前关闭或不读取；结果中的 `stdin_bytes_written`
仅表示已排入 socket 的字节。没有交互终端、后续追加或 PTY。

Lua 从项目内的 `/tmp` 创建临时文件；使用 `io.tmpfile()` 前需通过 makeDirectory
创建该目录。`os.rename`、`os.remove` 同样受项目文件边界约束。没有可用的
`os.execute`／`io.popen` 子进程通路，不支持 C 扩展动态加载、网络、readline 或包管理。
这不是把完整 Linux rootfs 装进项目；可直接调用 executeProgram，或按下节通过
Shell exec 转入固定 Lua 解释器。Lua 本身没有新增 exec API，os.execute 仍依赖
未实现的子进程机制。

## 从 Shell 交接给 Lua

```sh
mkdir -p scripts output
printf '%s\n' 'local f=assert(io.open("result.txt","w"));f:write(os.getenv("VALUE"));f:close();print("done")' > scripts/work.lua
VALUE='项目产物🙂'
cd output
exec /bin/lua /scripts/work.lua
```

成功输出 done 后执行结束，output/result.txt 保留。exec 后面的 Shell 命令不会
执行，嵌套 sh/source 中成功 exec 也不会返回外层脚本。需要后续处理时，在同一
项目完成本次执行后再调用 execute，或让 Lua 在自己的脚本内完成文件操作。

`/bin/lua`、`/bin/musl-smoke`、`/bin/sucrune-sh` 是运行时的固定可执行路径；
没有 PATH 搜索、shebang 或用户 ELF 加载。Shell 全部当前变量传为环境，cwd
保持不变。找不到程序时 exec 返回 127，其他 syscall 失败返回 126，可使用
`exec /missing || echo recovered`；缺少参数或非绝对路径返回 2。
这些路径精确匹配，不跟随链接或规范化路径，也没有在项目中安装 `/bin` 文件。
即使项目写入同名文件，exec 也只选择构建时内嵌的程序；open/stat 仍访问项目文件。

也可以把 Lua 当作文件转换程序，无需在 Lua 中显式打开输入和输出文件：

```sh
printf '%s\n' '10' '20' '12' > input.txt
printf '%s\n' 'local n=0;for v in io.lines() do n=n+tonumber(v) end;print(n)' > sum.lua
exec /bin/lua sum.lua < input.txt > result.txt
```

本次 stdout 为空，result.txt 为 `42` 加换行。`>>` 追加到已有文件；重定向也适用于
嵌套 `sh`、`source` 和内建命令，例如 `cat < input.txt > copy.txt`。这些命令返回后
恢复调用者的标准流，成功 exec 则继承新映射，不返回旧 Shell。`cat` 无参数或参数
`-` 读取当前 stdin；`cat ./-` 读取名字为 `-` 的文件。

每条命令最多一个输入和一个输出重定向，两条路径在任何打开操作前展开，随后按
出现顺序执行。`cat > out < missing` 可能先截断 out 再失败；`cat < missing > out`
不会打开 out。未知程序的 `exec /missing > out` 也会先创建／截断 out，然后返回
127 并恢复原 stdout。重复重定向、`2>`、`<&`、here-doc 等语法在当前命令产生
文件副作用前返回 2；打开重定向文件失败返回 1。

一次执行最多成功替换 32 次；替换不会刷新超时或取得新项目槽位。所有镜像共用
执行 ID、取消、输出排空和最终清理条件。新镜像保留 PID/TID、cwd、剩余 stdin
及非 CLOEXEC 文件偏移，但重新建立栈、TLS 和客体内存。参数等检查失败时保留
旧镜像；不可逆替换开始后遇到资源错误会结束为 lost，不返回已被卸载的旧程序。

## 运行 libc 检查程序

项目终端选择“Linux 程序 · Linux libc validation 1”（程序标识 `musl-smoke`），
参数每行一个，不填写程序名：

```text
selftest
参数中文🙂
```

环境变量输入 `SUCRUNE_TEST=环境中文🙂`。成功时 stdout 出现 argv/env、TLS、内存和文件检查标记，stderr 为 `musl:stderr=ok`，**退出码 42 是此 fixture 的成功约定**。文件 `libc-result.txt` 留在选择的工作目录，内容为 `Sucrune musl: 中文🙂` 加换行。切回 Shell 可用 cat 读取同一项目产物。

应用内等价调用：

```kotlin
val id = client.executeProgram(
    envId, "musl-smoke",
    argv = listOf("selftest", "参数中文🙂"),
    env = listOf("SUCRUNE_TEST=环境中文🙂"),
    cwd = "/", timeoutMs = 30_000
)
val result = client.waitFor(id, 35_000)
check(result.getString("state") == "exited" && result.getInt("exit_code") == 42)
val artifact = client.readFile(envId, "/libc-result.txt")
```

argv 不含 argv[0]，不经过 Shell 分词；空格、引号和空参数是参数本身。
可用 `listOf("echo", "a b", "中文🙂")` 检查边界，用
`listOf("sleep", "10")` 检查取消和超时。sleep 先刷新 start 标记，再睡眠，正常结束输出 done 标记。

这个固定程序链接 Zig 0.17.1 的 musl-based Linux libc，使用 musl 的启动/TLS 等
实现与 Zig 提供的 libc 实现；实测 malloc/free 来自 Zig 的 SmpAllocator，不能称为
musl 分配器测试。Sucrune 未修改工具链 libc，也未将客体库替换为 Android Bionic。
它验证 libc 兼容基础，不提供 BusyBox、Python、Node.js 或发行版包管理。

## Shell 支持范围

语法支持换行、分号、注释、单双引号、反斜杠、独立变量赋值、`$NAME`／`${NAME}`／`$?`、`&&`／`||`，每条命令最多一次 stdin 的 `<` 和一次 stdout 的 `>` 或 `>>`。

内建命令包括 echo、受限 printf、pwd、cd、cat、ls、mkdir、touch、rm、cp、mv、true、false、exit、sleep、source／点命令、嵌套 sh、固定路径 exec 和 help。完整选项以 [Shell 说明](../native/shell/README.md)为准。例如 touch 不更新时间戳，rm 不递归删除目录，cp 不保留元数据。

不支持管道、后台任务、命令替换、子 Shell 进程、循环、函数、通配符展开、任意 FD 重定向、here-doc、位置参数、外部命令搜索或包管理器。不会回退到宿主命令。变量展开不做 field splitting：一次输入 word 保持一个参数，空展开也如此。

脚本最多 64 KiB；展开后单条命令小于 8 KiB，最多 64 参数、64 变量；客体路径使用 1,024 字节缓冲区，嵌套受四个 frame slot 限制。Go 文件 API 每次限 1 MiB。通过文件代理传输内容时每条消息最多携带 4 KiB。Linux 路径执行时，runner 可使用代理在原打开应答中授予的只读 FD，在本进程读取普通文件。以上大小均指单次操作。

内嵌 Shell 与固定程序最多有 64 个客体 FD，包含标准流、程序打开的文件以及 Shell 的临时备份。Linux 路径执行有 1,024 个。
`dup`／`dup3` 和 fcntl 复制别名共享文件位置与 O_APPEND，CLOEXEC 按描述符独立。
Shell 备份都带 CLOEXEC，成功 exec 不会留下隐藏的原 stdin 读端；普通返回时则
恢复原映射、原标志和原本关闭的状态。代理普通文件与目录的 O_NONBLOCK 状态
可通过 F_SETFL 修改并由别名共享；这不增加 Shell 管道语法或 O_ASYNC 通知支持。

语法或不支持功能返回 2，未知命令／exec ENOENT 返回 127，其他 exec 失败为 126，文件操作失败通常为 1。脚本逐条执行：后续语法错误不会回滚前面已完成的文件操作。

## 输出、取消和持久化

管理者持续排空双输出流，不依赖界面轮询；每流最多保留 64 KiB 并报告截断。聚合输出按 UTF-8 文本呈现；无损二进制产物应写文件，再用 readFile 导出。

cancel 只是发起取消，须用 waitFor 或 poll 等待终态。等待超时不等于执行超时。只有 worker 停止、输出 EOF、文件代理清理、stdin 写入任务关闭并完成都确认后，才允许项目再次执行或删除。

Activity 重建可重新查询记录；这不承诺 Android 长期后台保活。主应用被杀后，未完成执行在重开时标为 lost，已完成文件保留，未提交实时输出可能丢失。deleteEnvironment 永久删除项目文件；普通退出、取消或超时不删除文件。

## 当前隔离假设

隔离 worker 使用不同 Android UID，通过指定项目的文件代理操作 workspace；宿主文件 FD 不直接传给客体，Go 不加载在 worker 中。

当前可信范围包含内嵌 Shell、解析器和固定 Linux 程序。Lua 允许项目脚本，但未经恶意脚本或字节码安全审计。受控路径检查不等于恶意机器码隔离；不能据此开放任意 ELF、共享可由其他同 UID 代码改写的管理目录，或宣称已实现完整 Linux 容器。

程序的 brk/mmap 只使用 64 MiB 数据 arena（8 MiB brk、56 MiB mmap），拒绝可执行页和越界保护修改；它不是整个 worker 的内存配额。动态链接、fork、客体线程、用户信号 handler 和 POSIX 信号交付仍未实现；未实现 syscall 返回 ENOSYS。更多边界见 [架构](architecture.md)。
