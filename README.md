# CampusLink 校园连接

一个基于现有开源认证客户端开发的 Windows 校园网连接工具。当前版本针对广东天翼校园网络进行适配和本机验证，不是天翼官方软件，也不能保证适用于所有学校。

## 功能

- 简化的 Windows Forms 界面：账号、密码、连接状态和连接按钮。
- 自动选择校园网物理网卡；网卡、认证入口和日志收在高级设置中。
- 账号密码通过 Windows DPAPI 加密保存，并限制配置目录访问权限。
- 可安装 `CampusLinkAuto` Windows 服务，在用户登录前等待网卡就绪并自动认证。
- 后台保活与暂时断线重试；关闭界面不会停止已安装的后台服务。
- 本机已验证无需短信验证码的账号，因此此版本不展示验证码输入，也不执行短信验证码流程。

## 来源与致谢

本项目没有从零重新实现全部认证协议，明确使用和修改了以下项目：

| 来源 | 使用方式 | 授权 |
| --- | --- | --- |
| [xxmod/EsurfingGo](https://github.com/xxmod/EsurfingGo) | 认证核心基础；基于提交 `c25e908755ddd56acf51698eee2cb9e19b44029d` 修改 | MIT |
| [BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion) | 参考并改写 `src/cipher/algo/windows/win_zsm.c` 的 Windows ZSM 数据解析，移植到 Go | Apache-2.0 |
| [emmansun/gmsm](https://github.com/emmansun/gmsm) | 密码算法依赖 | MIT |
| [google/uuid](https://github.com/google/uuid) | UUID 依赖 | BSD-3-Clause |
| [ulikunitz/xz](https://github.com/ulikunitz/xz) | LZMA 解压依赖 | BSD-3-Clause |

本次新增和改动主要包括：物理网卡与出口绑定、Windows 原生算法兼容、票据协商、心跳响应兼容、敏感日志抑制、简化界面、DPAPI 设置存储，以及独立 Windows 服务。下载的 Windows 认证模块仅作为数据解析，不作为本地程序加载执行。

详细来源、保留的版权说明和变更说明见 [NOTICE.txt](NOTICE.txt)，第三方许可证全文见 [licenses](licenses)。新增代码尚未单独指定开源许可证；第三方代码仍受其原有许可证约束。

## 目录

```text
source/CampusLink.cs           界面、设置、服务及认证进程管理
source/EsurfingGo/             修改后的 Go 认证核心
source/Build.ps1               Windows 构建脚本
extras/CampusHotspotLogon.cs   可选的登录后自动热点工具
licenses/                     第三方许可证
NOTICE.txt                    来源与修改说明
```

## 构建

需要 Windows、Go 1.25 或更新版本，以及 Windows 自带的 .NET Framework C# 编译器。安装 Go 并添加到 PATH 后运行：

```powershell
./source/Build.ps1
```

脚本先运行认证主包、network 和 utils 的测试，再编译核心与界面。生成的 `CampusLink.exe` 内嵌认证模块，独立 `campus-core.exe` 主要用于开发。

完整 cipher 测试曾在开发机器上受到安全软件阻止，因此这里不声称完整测试套件全部通过。不需要关闭安全防护来使用本项目。

## 使用

打开 `CampusLink.exe`，输入自己的账号密码，选择是否记忆和自动连接。首次安装开机后台需确认 Windows 管理员提示。后台服务使用 `LocalService` 账户，程序位于 `%ProgramData%\CampusLink\bin`，加密设置位于 `%ProgramData%\CampusLink\data`。

安装后台会停止原天翼客户端并将其服务改为手动启动，避免两个客户端同时认证。高级设置可以移除 CampusLink 后台并恢复原服务此前的启动类型。关闭窗口只隐藏界面；要停止当前连接，点击“断开连接”。仍启用自动连接时，下次启动系统会重新连接。

## 热点和 Clash

可选热点工具独立于校园认证服务，见 [extras/README.md](extras/README.md)。它不会修改热点名称、密码、Clash 配置或防火墙。

Windows 热点共享和 TUN 可能存在转发/路由冲突，不能仅通过更换认证客户端解决全部情况。本机采用国内 IP 绕过 TUN、代理节点和校园认证地址排除等配置验证了电脑与手机同时联网。具体网段、节点、规则版本均因环境而异，仓库不包含本机订阅或私有配置，不能直接照抄固定地址作为通用方案。

## 隐私与限制

仓库不包含实际校园账号密码、DPAPI 配置、订阅链接、Clash 密钥或运行日志。请勿将 `%ProgramData%\CampusLink\data`、个人 `.env` 或本地日志上传到 GitHub。

DPAPI 加密不是对本机管理员的绝对隔离。请仅在自己的 Windows 账户和授权网络上使用。网络认证逻辑仍依赖校园服务器，账号失效、服务器变更或需要短信验证时，需要另行适配。
