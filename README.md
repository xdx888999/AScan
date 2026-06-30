# AScan

AScan 是一个本地运行的 iOS App Store 提审合规初筛工具。它面向用 AI / Vibe Coding 快速做 iOS App 的开发者，在提交审核前扫描源码、`Info.plist`、隐私清单和导出的 IPA，提前发现一些常见静态风险。

重要边界：**AScan 不能代替 Apple 官方审核，也不能保证过审。** 它只做本地静态初筛，不做在线真机测试、不访问 App Store Connect、不验证后端或运行时流程。

## 安装

推荐使用 Homebrew：

```bash
brew tap xdx888999/ascan
brew install ascan
```

一行安装：

```bash
brew install xdx888999/ascan/ascan
```

升级：

```bash
brew update
brew upgrade ascan
```

卸载：

```bash
brew uninstall ascan
```

如果你已经安装 Go，也可以从源码安装：

```bash
go install github.com/xdx888999/AScan/cmd/ascan@latest
```

从本仓库构建：

```bash
make build
./bin/ascan --version
```

## 使用

扫描当前 iOS 项目目录：

```bash
ascan .
```

只输出中文：

```bash
ascan ./MyApp --lang zh
```

输出 JSON 报告：

```bash
ascan . --format json --output report.json
```

只跑源码扫描：

```bash
ascan . --only codescan
```

附带扫描导出的 IPA：

```bash
ascan . --ipa build/MyApp.ipa
```

只扫描 IPA：

```bash
ascan build/MyApp.ipa --only ipa
```

如果你已经在导出 IPA 的目录里，并且该目录不像源码项目、只有一个 `.ipa` 文件，可以直接运行：

```bash
ascan
```

也可以显式指定只扫 IPA：

```bash
ascan . --only ipa
```

如果当前目录有多个 `.ipa` 文件，AScan 会要求你用 `--ipa` 指定具体文件，避免扫错包：

```bash
ascan . --only ipa --ipa "./MyApp.ipa"
```

退出码：

- `0`：没有发现 critical 级问题。
- `1`：发现 critical 级问题，适合 CI 门禁。
- `2`：命令参数、配置或读取过程出错。

## 当前能检查什么

源码扫描：

- 疑似私有 API 字符串调用。
- 硬编码密钥的典型模式，例如 Stripe live key、AWS access key。
- 动态执行代码或热更新痕迹，例如 `dlopen`、JSPatch。
- 疑似绕过 Apple IAP 的外部支付关键词。
- 已废弃的 `UIWebView`。
- 明文 HTTP URL。
- `lorem ipsum`、`coming soon` 等占位内容。

工程元数据扫描：

- `Info.plist` 是否缺少 `ITSAppUsesNonExemptEncryption`。
- 权限用途说明是否过短。
- 是否缺少 `PrivacyInfo.xcprivacy`。
- 是否使用了常见 Required Reason API 痕迹，例如 `UserDefaults`、文件时间戳、系统启动时间。

IPA 扫描：

- `Payload/*.app/Info.plist` 结构是否有效。
- Bundle ID、版本号、主可执行文件是否存在。
- ATS 是否全局放开明文网络或配置了明文域名例外。
- 图标声明和图标引用文件是否存在。
- 主可执行文件和内嵌 framework 是否包含 `UIWebView` 符号。
- 是否包含 JSPatch 这类热更新框架路径痕迹。
- IPA 体积是否明显偏大。

## AScan 检查不到什么

这些内容通常需要真机运行、后端联调、人工检查或 App Store Connect 环境，AScan 不能可靠判断：

- 用户账号是否真的能创建、登录、登出和删除。
- 删除账号是否同步删除了服务端数据。
- 恢复购买是否真实可用。
- IAP 购买、订阅续费、退款、权益发放是否完整。
- 是否存在通过后端配置、远程网页、客服消息引导外部支付。
- Sign in with Apple 是否在 Apple Developer 后台、后端 token 校验和 App 内流程中完整可用。
- ATT 弹窗是否在正确时机展示，追踪 SDK 是否实际运行。
- 推送通知、地理围栏、后台定位、Live Activity 等运行时能力是否可靠。
- 第三方 SDK 内部是否动态执行代码、收集隐私数据或触发审核风险。
- 运行时拼接出来的 URL、文案、支付入口或审核敏感内容。
- App Store 审核员看到的真实体验、内容质量、完成度和业务合规性。

因此，AScan 的定位是“提交前本地初筛”，不是“审核通过率验证工具”。

## 配置

在项目根目录放 `.ascan.yml`：

```yaml
rules:
  http-cleartext:
    severity: info
  placeholder-content:
    enabled: false
ignore:
  - Pods
  - Carthage
  - "*.generated.swift"
```

说明：当前配置主要作用于源码规则。metadata、privacy 和 IPA 规则的统一配置会在后续版本继续完善。

## 开发

```bash
make check
make build
```

## 灵感来源

AScan 的灵感来自 [RevylAI/greenlight](https://github.com/RevylAI/greenlight)。

greenlight 包含本地静态预检和在线真机验证能力；AScan 是独立重写的本地工具，只实现本地初步诊断，不包含云真机运行时测试。

## License

MIT
