# 在真机上验证原版 DSH Agent

这个入口运行的是项目里的 GNU/Linux ARM64 Node 和原版 DSH。Windows 负责启动 Android 仪器测试、限时传递凭据并读取状态。模型收到的文件操作或 Bash 工具调用在手机上执行。当前入口用于开发验收，依赖包含客体软件的测试 APK；它不是普通用户界面。

首次克隆后，在构建测试 APK 前从项目根目录生成 Linux/Node 基座和终端用例的测试文件。以下命令需要 PowerShell 7、Node.js、Python 3 和 Android NDK。将 `ANDROID_NDK_HOME` 指向已安装的 NDK。

```powershell
$readelf = Join-Path $env:ANDROID_NDK_HOME 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
.\scripts\prepare-linux-rootfs.ps1 -IncludeNode
.\scripts\prepare-linux-bash.ps1 -ReadElf $readelf
node scripts/prepare-linux-node-pty.cjs
python scripts/prepare-linux-stty.py --readelf $readelf
```

DSH 本身的固定依赖、离线安装包和来源摘要见 [DSH 准备说明](node-dsh-target.md#离线-sdk-fixture-与有限真机验证)。

1. 使用同一签名的 validation APK 和 androidTest APK。构建方法见仓库 README。测试 APK 应含 Linux/Node 基座、Bash、GNU stty、node-pty 和 DSH 的 `SdkMinimal` 安装包；普通 APK 不包含模型凭据。用 `adb devices` 选定一台已授权的 ARM64 设备。
2. 在项目根目录运行下列 PowerShell 命令。首次安装可能需要手机确认。后续用 `-r` 保留应用数据和执行历史；厂商安装确认行为以手机设置为准。

   ```powershell
   $device = '<adb devices 中的序列号>'
   $adb = (Get-Command adb -CommandType Application).Source
   & $adb -s $device install -r android/probeapp/build/outputs/apk/validation/probeapp-validation.apk
   & $adb -s $device install -r android/probeapp/build/outputs/apk/androidTest/validation/probeapp-validation-androidTest.apk
   node scripts/run-dsh-agent-device.cjs --synthetic --adb $adb --serial $device
   ```

3. 准备本机 DSH 的 DeepSeek 凭据以及控制器所需的固定 YAML 解析器：`.build/dsh-prep-study/node_modules/yaml` 须与原版依赖树中的 `yaml@2.9.1` 校验值一致。真实模式固定选用 `deepseek-official` / `deepseek-flash` 和官方 HTTPS 地址。控制器检查设备、已通过的前置用例和手机握手证明后才打开本机受管凭据文件。请勿把密钥写进命令、ADB 参数或测试日志。

   ```powershell
   node scripts/run-dsh-agent-device.cjs --real-deepseek --adb $adb --serial $device
   ```

4. 看最后的结构化结果。当前套件共 63 项：59 项前置检查，以及 Agent 准备、模型与工具、进程重启恢复、活动轮次取消这 4 项。只有 `status: passed`、`mode: real` 和所有用例都通过，才算完整验收。出现 `started`、`credential_received` 或 `turn_end` 都不等于成功。控制器只导出白名单状态；失败时先检查第一个失败的用例及其分类。前置用例失败时，控制器不会打开本机凭据。

验收会检查模型是否实际调用 write、read、bash，两个产物的字节是否一致，新进程能否恢复 JSONL 会话并复述先前的随机标记，以及活跃轮次取消后项目能否再次执行。测试会删除自己创建的项目，保留正式执行历史和两只 APK。详细证据条件见[验收设计](dsh-agent-validation-design.md)。

若要留存结果，可将控制器的 JSONL 保存为文件。[收据脚本](../scripts/summarize-dsh-agent.py) 校验每个用例的终态、凭据回执、ADB 转发移除和两份 APK 的摘要。它单独接收测试结束后实际查询的临时项目、导入文件和本次凭据转发数量；没有独立清理数据时只生成未完成的收据。
