package ipa

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"

	"github.com/xdx888999/AScan/internal/codescan"
)

const (
	infoPlistName = "Info.plist"
	payloadPrefix = "Payload/"
	appSuffix     = ".app"

	uiWebViewSymbol = "UIWebView"
	jsPatchKeyword  = "jspatch"

	// maxRecommendedIPASizeBytes 是面向新手的体积提醒阈值，不代表 App Store 的硬性限制。
	maxRecommendedIPASizeBytes int64 = 200 * 1024 * 1024

	bytesPreviewLimit = 32 * 1024
)

var (
	errNoPayloadApp       = errors.New("未在 IPA 中找到 Payload/*.app/Info.plist")
	errMultiplePayloadApp = errors.New("IPA 的 Payload 目录下存在多个 .app 主包")
	errBadInfoPlist       = errors.New("无法解析 IPA 中的 Info.plist")
)

type appBundle struct {
	root      string
	infoPath  string
	execPath  string
	infoPlist map[string]interface{}
}

// Scan 扫描已构建的 .ipa 文件，返回发现项与检查过的 IPA 内部条目数量。
func Scan(ipaPath string) ([]codescan.Finding, int, error) {
	reader, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, 0, fmt.Errorf("打开 IPA 失败：%w", err)
	}
	defer reader.Close()

	filesByName := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		filesByName[file.Name] = file
	}

	app, err := readAppBundle(reader.File)
	if err != nil {
		return nil, 0, err
	}

	findings := checkInfoPlist(app)
	inspected := 1
	findings = append(findings, checkIconFiles(filesByName, app)...)

	executableFindings, executableInspected := checkExecutable(filesByName, app)
	findings = append(findings, executableFindings...)
	inspected += executableInspected

	frameworkFindings, frameworkInspected := checkFrameworkExecutables(reader.File)
	findings = append(findings, frameworkFindings...)
	inspected += frameworkInspected

	findings = append(findings, checkArchiveNames(reader.File)...)
	if sizeFinding, ok := checkIPASize(ipaPath); ok {
		findings = append(findings, sizeFinding)
	}

	return findings, inspected, nil
}

func readAppBundle(files []*zip.File) (appBundle, error) {
	var appInfoFiles []*zip.File
	for _, file := range files {
		if isAppInfoPlist(file.Name) {
			appInfoFiles = append(appInfoFiles, file)
		}
	}
	switch len(appInfoFiles) {
	case 0:
		return appBundle{}, errNoPayloadApp
	case 1:
	default:
		return appBundle{}, errMultiplePayloadApp
	}

	for _, file := range appInfoFiles {
		name := file.Name
		if !isAppInfoPlist(name) {
			continue
		}
		data, err := readZipFile(file)
		if err != nil {
			return appBundle{}, fmt.Errorf("读取 IPA 中的 Info.plist 失败：%w", err)
		}
		var info map[string]interface{}
		if _, err := plist.Unmarshal(data, &info); err != nil {
			return appBundle{}, fmt.Errorf("%w：%s", errBadInfoPlist, name)
		}
		root := strings.TrimSuffix(name, "/"+infoPlistName)
		return appBundle{
			root:      root,
			infoPath:  name,
			execPath:  executablePath(root, info),
			infoPlist: info,
		}, nil
	}
	return appBundle{}, errNoPayloadApp
}

func isAppInfoPlist(name string) bool {
	if !strings.HasPrefix(name, payloadPrefix) || !strings.HasSuffix(name, "/"+infoPlistName) {
		return false
	}
	root := strings.TrimSuffix(name, "/"+infoPlistName)
	return strings.HasSuffix(root, appSuffix) && strings.Count(root, "/") == 1
}

func executablePath(root string, info map[string]interface{}) string {
	executableName, _ := info["CFBundleExecutable"].(string)
	if strings.TrimSpace(executableName) == "" {
		return ""
	}
	return root + "/" + executableName
}

func checkInfoPlist(app appBundle) []codescan.Finding {
	var findings []codescan.Finding
	if strings.TrimSpace(stringValue(app.infoPlist["CFBundleIdentifier"])) == "" {
		findings = append(findings, codescan.Finding{
			RuleID:   "ipa-missing-bundle-id",
			Severity: codescan.SeverityCritical,
			TitleZH:  "IPA 缺少 Bundle ID",
			TitleEN:  "IPA bundle identifier is missing",
			DetailZH: "最终包的 Info.plist 缺少 CFBundleIdentifier，App Store 和系统都无法可靠识别这个 App。",
			DetailEN: "The final bundle Info.plist lacks CFBundleIdentifier, so App Store and iOS cannot reliably identify the app.",
			FixZH:    "检查 Xcode target 的 Bundle Identifier，并重新归档导出 IPA。",
			FixEN:    "Check the Xcode target Bundle Identifier, then archive and export the IPA again.",
			File:     app.infoPath,
		})
	}

	if strings.TrimSpace(stringValue(app.infoPlist["CFBundleShortVersionString"])) == "" ||
		strings.TrimSpace(stringValue(app.infoPlist["CFBundleVersion"])) == "" {
		findings = append(findings, codescan.Finding{
			RuleID:   "ipa-missing-version",
			Severity: codescan.SeverityHigh,
			TitleZH:  "IPA 缺少版本号信息",
			TitleEN:  "IPA version fields are missing",
			DetailZH: "最终包缺少 CFBundleShortVersionString 或 CFBundleVersion。上传和审核都依赖这两个版本字段。",
			DetailEN: "The final bundle lacks CFBundleShortVersionString or CFBundleVersion. Upload and review rely on these version fields.",
			FixZH:    "在 target 的 Version 和 Build 中填入有效值，然后重新导出 IPA。",
			FixEN:    "Set valid Version and Build values on the target, then export the IPA again.",
			File:     app.infoPath,
		})
	}

	if _, ok := app.infoPlist["ITSAppUsesNonExemptEncryption"]; !ok {
		findings = append(findings, codescan.Finding{
			RuleID:   "ipa-encryption-not-declared",
			Severity: codescan.SeverityInfo,
			TitleZH:  "IPA 未声明加密合规",
			TitleEN:  "IPA encryption compliance not declared",
			DetailZH: "最终 IPA 的 Info.plist 缺少 ITSAppUsesNonExemptEncryption。上传时 App Store Connect 可能会要求你回答加密问题。",
			DetailEN: "The final IPA Info.plist lacks ITSAppUsesNonExemptEncryption. App Store Connect may ask the encryption compliance question during upload.",
			FixZH:    "在工程构建设置或 Info.plist 中声明 ITSAppUsesNonExemptEncryption；只使用 HTTPS 等标准加密通常填 false。",
			FixEN:    "Declare ITSAppUsesNonExemptEncryption in build settings or Info.plist; set false if you only use standard encryption such as HTTPS.",
			File:     app.infoPath,
		})
	}

	if allowsArbitraryLoads(app.infoPlist) {
		findings = append(findings, codescan.Finding{
			RuleID:    "ipa-ats-arbitrary-loads",
			Severity:  codescan.SeverityWarn,
			Guideline: "2.5.1",
			TitleZH:   "IPA 开启了 ATS 任意明文放行",
			TitleEN:   "IPA allows arbitrary ATS loads",
			DetailZH:  "最终包里的 NSAppTransportSecurity.NSAllowsArbitraryLoads 为 true，审核时可能被要求解释为什么需要明文网络访问。",
			DetailEN:  "The final bundle has NSAppTransportSecurity.NSAllowsArbitraryLoads set to true, which may require review justification.",
			FixZH:     "优先改用 HTTPS；确需明文访问时，只给必要域名配置最小范围的 ATS 例外。",
			FixEN:     "Prefer HTTPS; if cleartext is required, scope ATS exceptions to the smallest necessary domains.",
			File:      app.infoPath,
		})
	}

	findings = append(findings, checkATSExceptions(app)...)

	if app.execPath == "" {
		findings = append(findings, codescan.Finding{
			RuleID:   "ipa-missing-executable-name",
			Severity: codescan.SeverityCritical,
			TitleZH:  "IPA 缺少主可执行文件名",
			TitleEN:  "IPA main executable name is missing",
			DetailZH: "最终包的 Info.plist 缺少 CFBundleExecutable，系统无法可靠定位 App 主程序。",
			DetailEN: "The final bundle Info.plist lacks CFBundleExecutable, so the system cannot reliably locate the app executable.",
			FixZH:    "检查 target 的 Product Name 和 Info.plist 构建设置，确保 CFBundleExecutable 会写入最终包。",
			FixEN:    "Check the target Product Name and Info.plist build settings so CFBundleExecutable is written into the final bundle.",
			File:     app.infoPath,
		})
	}
	return findings
}

func stringValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func allowsArbitraryLoads(info map[string]interface{}) bool {
	ats, ok := info["NSAppTransportSecurity"].(map[string]interface{})
	if !ok {
		return false
	}
	return boolValue(ats["NSAllowsArbitraryLoads"])
}

func checkATSExceptions(app appBundle) []codescan.Finding {
	ats, ok := app.infoPlist["NSAppTransportSecurity"].(map[string]interface{})
	if !ok {
		return nil
	}
	exceptions, ok := ats["NSExceptionDomains"].(map[string]interface{})
	if !ok {
		return nil
	}
	var findings []codescan.Finding
	for domain, rawConfig := range exceptions {
		config, ok := rawConfig.(map[string]interface{})
		if !ok || !boolValue(config["NSExceptionAllowsInsecureHTTPLoads"]) {
			continue
		}
		findings = append(findings, codescan.Finding{
			RuleID:    "ipa-ats-insecure-exception",
			Severity:  codescan.SeverityWarn,
			Guideline: "2.5.1",
			TitleZH:   "IPA 为域名开启了明文网络例外",
			TitleEN:   "IPA allows cleartext loads for a domain",
			DetailZH:  "最终包允许 " + domain + " 使用明文 HTTP。若不是必要能力，审核时可能被要求解释。",
			DetailEN:  "The final bundle allows cleartext HTTP for " + domain + ". Review may ask for justification if it is not necessary.",
			FixZH:     "优先把该域名改为 HTTPS；确需明文时保留最小范围例外并准备说明。",
			FixEN:     "Prefer HTTPS for this domain; if cleartext is required, keep the exception narrow and prepare a justification.",
			File:      app.infoPath,
		})
	}
	return findings
}

func boolValue(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case uint64:
		return v != 0
	case int64:
		return v != 0
	case string:
		return strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	default:
		return false
	}
}

func checkIconFiles(filesByName map[string]*zip.File, app appBundle) []codescan.Finding {
	iconNames := iconFileNames(app.infoPlist)
	if len(iconNames) == 0 {
		return []codescan.Finding{{
			RuleID:   "ipa-missing-icon-declaration",
			Severity: codescan.SeverityWarn,
			TitleZH:  "IPA 缺少图标声明",
			TitleEN:  "IPA icon declaration is missing",
			DetailZH: "最终包的 Info.plist 未发现可用的 CFBundleIcons 或 CFBundleIconFiles。缺少应用图标会影响安装展示，也可能导致提交检查失败。",
			DetailEN: "The final bundle Info.plist does not include usable CFBundleIcons or CFBundleIconFiles. Missing app icons can break install presentation or submission checks.",
			FixZH:    "在 Xcode 的 AppIcon 资源中补齐图标，并确认构建后的 Info.plist 写入图标声明。",
			FixEN:    "Add complete icons in the Xcode AppIcon asset and confirm the built Info.plist contains icon declarations.",
			File:     app.infoPath,
		}}
	}

	var findings []codescan.Finding
	for _, iconName := range iconNames {
		if iconExists(filesByName, app.root, iconName) {
			continue
		}
		findings = append(findings, codescan.Finding{
			RuleID:   "ipa-icon-reference-missing",
			Severity: codescan.SeverityHigh,
			TitleZH:  "IPA 图标引用文件不存在",
			TitleEN:  "IPA icon reference is missing",
			DetailZH: "Info.plist 引用了图标 " + iconName + "，但最终 .app 包内没有找到对应文件。",
			DetailEN: "Info.plist references icon " + iconName + ", but the final .app bundle does not contain the matching file.",
			FixZH:    "检查 AppIcon 资源是否完整，并确认导出的 IPA 内包含对应 PNG 文件。",
			FixEN:    "Check that the AppIcon asset is complete and the exported IPA contains the matching PNG file.",
			File:     app.infoPath,
		})
	}
	return findings
}

func iconFileNames(info map[string]interface{}) []string {
	if icons := primaryIconFiles(info["CFBundleIcons"]); len(icons) > 0 {
		return icons
	}
	return stringSliceValue(info["CFBundleIconFiles"])
}

func primaryIconFiles(value interface{}) []string {
	icons, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	primaryIcon, ok := icons["CFBundlePrimaryIcon"].(map[string]interface{})
	if !ok {
		return nil
	}
	return stringSliceValue(primaryIcon["CFBundleIconFiles"])
}

func stringSliceValue(value interface{}) []string {
	switch icons := value.(type) {
	case []interface{}:
		out := make([]string, 0, len(icons))
		for _, icon := range icons {
			if s := strings.TrimSpace(stringValue(icon)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(icons))
		for _, icon := range icons {
			if s := strings.TrimSpace(icon); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(icons) == "" {
			return nil
		}
		return []string{strings.TrimSpace(icons)}
	default:
		return nil
	}
}

func iconExists(filesByName map[string]*zip.File, appRoot, iconName string) bool {
	candidates := []string{appRoot + "/" + iconName}
	if !strings.HasSuffix(strings.ToLower(iconName), ".png") {
		candidates = append(candidates,
			appRoot+"/"+iconName+".png",
			appRoot+"/"+iconName+"@2x.png",
			appRoot+"/"+iconName+"@3x.png",
			appRoot+"/"+iconName+"@2x~ipad.png",
			appRoot+"/"+iconName+"@3x~ipad.png",
		)
	}
	for _, candidate := range candidates {
		if _, ok := filesByName[candidate]; ok {
			return true
		}
	}
	return false
}

func checkExecutable(filesByName map[string]*zip.File, app appBundle) ([]codescan.Finding, int) {
	if app.execPath == "" {
		return nil, 0
	}
	file, ok := filesByName[app.execPath]
	if !ok {
		return []codescan.Finding{{
			RuleID:   "ipa-missing-executable",
			Severity: codescan.SeverityCritical,
			TitleZH:  "IPA 缺少主可执行文件",
			TitleEN:  "IPA main executable is missing",
			DetailZH: "Info.plist 指向的 CFBundleExecutable 在最终包中不存在，App 将无法正常启动。",
			DetailEN: "The CFBundleExecutable referenced by Info.plist does not exist in the final bundle, so the app cannot launch correctly.",
			FixZH:    "重新归档导出 IPA，并检查 target 产物是否被正确打入 Payload/*.app。",
			FixEN:    "Archive and export the IPA again, then verify the target product is packaged into Payload/*.app.",
			File:     app.execPath,
		}}, 0
	}

	found, err := zipEntryContains(file, []byte(uiWebViewSymbol))
	if err != nil {
		return []codescan.Finding{{
			RuleID:   "ipa-executable-unreadable",
			Severity: codescan.SeverityWarn,
			TitleZH:  "无法读取 IPA 主可执行文件",
			TitleEN:  "Could not read IPA main executable",
			DetailZH: "扫描器无法读取最终包里的主可执行文件，因此无法确认是否包含 UIWebView 等二进制符号。",
			DetailEN: "The scanner could not read the final executable, so it could not verify binary symbols such as UIWebView.",
			FixZH:    "确认 IPA 文件未损坏后重新运行扫描。",
			FixEN:    "Confirm the IPA is not corrupted and run the scan again.",
			File:     app.execPath,
		}}, 1
	}
	if !found {
		return nil, 1
	}
	return []codescan.Finding{uiWebViewFinding(app.execPath)}, 1
}

func checkFrameworkExecutables(files []*zip.File) ([]codescan.Finding, int) {
	var findings []codescan.Finding
	inspected := 0
	for _, file := range files {
		if !isFrameworkExecutable(file) {
			continue
		}
		inspected++
		found, err := zipEntryContains(file, []byte(uiWebViewSymbol))
		if err != nil {
			findings = append(findings, codescan.Finding{
				RuleID:   "ipa-framework-unreadable",
				Severity: codescan.SeverityWarn,
				TitleZH:  "无法读取 IPA 内嵌 framework",
				TitleEN:  "Could not read embedded framework",
				DetailZH: "扫描器无法读取最终包里的 framework 可执行文件，因此无法确认是否包含 UIWebView 等二进制符号。",
				DetailEN: "The scanner could not read the embedded framework executable, so it could not verify binary symbols such as UIWebView.",
				FixZH:    "确认 IPA 文件未损坏后重新运行扫描。",
				FixEN:    "Confirm the IPA is not corrupted and run the scan again.",
				File:     file.Name,
			})
			continue
		}
		if found {
			findings = append(findings, uiWebViewFinding(file.Name))
		}
	}
	return findings, inspected
}

func isFrameworkExecutable(file *zip.File) bool {
	if file.FileInfo().IsDir() {
		return false
	}
	parts := strings.Split(file.Name, "/")
	for i, part := range parts {
		if !strings.HasSuffix(part, ".framework") {
			continue
		}
		if i+2 != len(parts) {
			return false
		}
		frameworkName := strings.TrimSuffix(part, ".framework")
		return parts[i+1] == frameworkName
	}
	return false
}

func uiWebViewFinding(filePath string) codescan.Finding {
	return codescan.Finding{
		RuleID:   "ipa-uiwebview-symbol",
		Severity: codescan.SeverityHigh,
		TitleZH:  "IPA 二进制中包含 UIWebView 符号",
		TitleEN:  "IPA binary contains UIWebView symbol",
		DetailZH: "最终包的可执行文件中出现 UIWebView 字符串。即使源码已移除，第三方库或旧二进制仍可能导致 App Store 拒绝上传或审核。",
		DetailEN: "An executable in the final bundle contains the UIWebView string. Even if source code was updated, an old binary or dependency may still cause App Store rejection.",
		FixZH:    "升级或移除仍引用 UIWebView 的依赖，重新归档后再次扫描 IPA。",
		FixEN:    "Upgrade or remove dependencies that still reference UIWebView, then archive and scan the IPA again.",
		File:     filePath,
	}
}

func checkArchiveNames(files []*zip.File) []codescan.Finding {
	seen := map[string]bool{}
	var findings []codescan.Finding
	for _, file := range files {
		lowerName := strings.ToLower(file.Name)
		if !strings.Contains(lowerName, jsPatchKeyword) {
			continue
		}
		dir := frameworkOrFileName(file.Name)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		findings = append(findings, codescan.Finding{
			RuleID:    "ipa-dynamic-code-framework",
			Severity:  codescan.SeverityCritical,
			Guideline: "2.5.2",
			TitleZH:   "IPA 中疑似包含热更新框架",
			TitleEN:   "IPA may contain a hot-update framework",
			DetailZH:  "最终包路径中出现 JSPatch 相关文件。动态下发并执行代码通常违反 App Store 审核规则。",
			DetailEN:  "The final bundle contains a JSPatch-related path. Dynamically delivering and executing code usually violates App Store review rules.",
			FixZH:     "移除 JSPatch 或类似热更新框架，所有可执行代码都应随审核包一起提交。",
			FixEN:     "Remove JSPatch or similar hot-update frameworks; all executable code should ship in the reviewed bundle.",
			File:      dir,
		})
	}
	return findings
}

func frameworkOrFileName(name string) string {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if strings.HasSuffix(part, ".framework") {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return name
}

func checkIPASize(ipaPath string) (codescan.Finding, bool) {
	info, err := os.Stat(ipaPath)
	if err != nil || info.Size() <= maxRecommendedIPASizeBytes {
		return codescan.Finding{}, false
	}
	return codescan.Finding{
		RuleID:   "ipa-large-file",
		Severity: codescan.SeverityInfo,
		TitleZH:  "IPA 体积偏大",
		TitleEN:  "IPA file is large",
		DetailZH: fmt.Sprintf("当前 IPA 大小约为 %.1f MB。体积偏大会影响下载转化和审核排查效率。", float64(info.Size())/(1024*1024)),
		DetailEN: fmt.Sprintf("The IPA is about %.1f MB. A large app can hurt download conversion and make review troubleshooting slower.", float64(info.Size())/(1024*1024)),
		FixZH:    "检查未使用资源、重复图片、调试符号和过大的内置媒体，必要时做资源压缩或按需下载。",
		FixEN:    "Check unused assets, duplicate images, debug symbols, and large bundled media; compress or download assets on demand where appropriate.",
		File:     ipaPath,
	}, true
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func zipEntryContains(file *zip.File, needle []byte) (bool, error) {
	reader, err := file.Open()
	if err != nil {
		return false, err
	}
	defer reader.Close()

	buffer := make([]byte, bytesPreviewLimit)
	var tail []byte
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			chunk := append(tail, buffer[:n]...)
			if bytes.Contains(chunk, needle) {
				return true, nil
			}
			if len(chunk) >= len(needle)-1 {
				tail = append([]byte(nil), chunk[len(chunk)-len(needle)+1:]...)
			} else {
				tail = append([]byte(nil), chunk...)
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		return false, readErr
	}
}

// LooksLikeIPA 判断路径是否指向 .ipa 文件。
func LooksLikeIPA(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".ipa")
}
