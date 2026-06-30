package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xdx888999/AScan/internal/codescan"
	"github.com/xdx888999/AScan/internal/config"
	"github.com/xdx888999/AScan/internal/ipa"
	"github.com/xdx888999/AScan/internal/metadata"
	"github.com/xdx888999/AScan/internal/privacy"
	"github.com/xdx888999/AScan/internal/report"
	"github.com/xdx888999/AScan/internal/version"
)

// Run 执行 CLI，返回进程退出码。
func Run(args []string) int {
	var (
		only       string
		format     string
		outputPath string
		langStr    string
		configPath string
		ipaPath    string
	)

	cmd := &cobra.Command{
		Use:     "ascan [path]",
		Short:   "iOS App Store 提审合规预检 / Pre-submission compliance scanner",
		Version: version.Version,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, a []string) error {
			root := "."
			if len(a) == 1 {
				root = a[0]
			}
			return runScan(root, only, format, outputPath, langStr, configPath, ipaPath, c)
		},
	}
	cmd.Flags().StringVar(&only, "only", "", "只跑指定扫描器，逗号分隔（codescan/metadata/privacy/ipa）")
	cmd.Flags().StringVar(&ipaPath, "ipa", "", "扫描指定 IPA 文件")
	cmd.Flags().StringVar(&format, "format", "terminal", "输出格式：terminal | json")
	cmd.Flags().StringVar(&outputPath, "output", "", "结果写入文件")
	cmd.Flags().StringVar(&langStr, "lang", "both", "输出语言：zh | en | both")
	cmd.Flags().StringVar(&configPath, "config", "", "配置文件路径（默认自动发现 .ascan.yml）")

	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		if ec, ok := err.(exitError); ok {
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "ascan:", err)
		return 2
	}
	if v, ok := cmd.Annotations["exit"]; ok && v == "1" {
		return 1
	}
	return 0
}

type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// onlySet 解析 --only；空字符串表示全部。
func onlySet(only string) map[string]bool {
	if strings.TrimSpace(only) == "" {
		return nil
	}
	m := map[string]bool{}
	for _, s := range strings.Split(only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}

var knownScanners = map[string]bool{
	"codescan": true,
	"metadata": true,
	"privacy":  true,
	"ipa":      true,
}

const ipaScannerName = "ipa"

var projectIndicatorNames = map[string]bool{
	".ascan.yml":            true,
	".git":                  true,
	"Assets.xcassets":       true,
	"Cartfile":              true,
	"Info.plist":            true,
	"Package.swift":         true,
	"Podfile":               true,
	"PrivacyInfo.xcprivacy": true,
	"Sources":               true,
	"Tests":                 true,
	"Tuist":                 true,
	"project.yml":           true,
}

var projectIndicatorExtensions = map[string]bool{
	".h":           true,
	".m":           true,
	".mm":          true,
	".swift":       true,
	".xcconfig":    true,
	".xcframework": true,
	".xcworkspace": true,
	".xcodeproj":   true,
}

func runScan(root, only, format, outputPath, langStr, configPath, ipaPath string, cmd *cobra.Command) error {
	if !validFormat(format) {
		return fmt.Errorf("未知输出格式 %q（可选：terminal、json）", format)
	}
	if !validLang(langStr) {
		return fmt.Errorf("未知输出语言 %q（可选：zh、en、both）", langStr)
	}
	scanners := onlySet(only)
	if scanners != nil {
		for name := range scanners {
			if !knownScanners[name] {
				return fmt.Errorf("未知扫描器 %q（可选：codescan、metadata、privacy、ipa）", name)
			}
		}
	}
	rootIsIPA := ipa.LooksLikeIPA(root)
	if rootIsIPA && scanners != nil && hasSourceScanner(scanners) {
		return fmt.Errorf("扫描路径是 IPA 文件时，--only 只能选择 ipa；源码扫描器需要传入项目目录")
	}
	sourceScannersAllowed := !rootIsIPA
	runCodescan := sourceScannersAllowed && (scanners == nil || scanners["codescan"])
	runMetadata := sourceScannersAllowed && (scanners == nil || scanners["metadata"])
	runPrivacy := sourceScannersAllowed && (scanners == nil || scanners["privacy"])

	scanIPAPath := strings.TrimSpace(ipaPath)
	if scanIPAPath == "" && rootIsIPA {
		scanIPAPath = root
	}
	autoDiscoveredIPAOnly := false
	if scanIPAPath == "" && scanners == nil && !rootIsIPA {
		discoveredIPAPath, found, derr := discoverSingleIPAForPlainRun(root)
		if derr != nil {
			return derr
		}
		if found {
			scanIPAPath = discoveredIPAPath
			autoDiscoveredIPAOnly = true
		}
	}
	if scanIPAPath == "" && isIPAAutoDiscoveryMode(scanners) {
		discoveredIPAPath, derr := discoverSingleIPA(root)
		if derr != nil {
			return derr
		}
		scanIPAPath = discoveredIPAPath
	}
	if autoDiscoveredIPAOnly {
		runCodescan = false
		runMetadata = false
		runPrivacy = false
	}
	runIPA := (scanners == nil || scanners["ipa"]) && scanIPAPath != ""
	if scanners != nil && scanners["ipa"] && scanIPAPath == "" {
		return fmt.Errorf("使用 --only ipa 时，请通过 --ipa 指定 IPA 文件，或把扫描路径直接设为 .ipa 文件")
	}

	cfgPath := configPath
	if cfgPath == "" {
		if rootIsIPA {
			cfgPath = filepath.Join(filepath.Dir(root), ".ascan.yml")
		} else {
			cfgPath = filepath.Join(root, ".ascan.yml")
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	should := codescan.ShouldScan(cfg.Ignored())

	var findings []codescan.Finding
	filesRead := 0

	if runCodescan {
		rules := codescan.ApplyConfig(codescan.AllRules(), cfg.Enabled, cfg.SeverityOverride)
		res, serr := codescan.Scan(root, should, rules)
		if serr != nil {
			return serr
		}
		findings = append(findings, res.Findings...)
		filesRead += res.FilesRead
	}

	if runMetadata {
		fs, n, merr := metadata.Scan(root, should)
		if merr != nil {
			return merr
		}
		findings = append(findings, fs...)
		filesRead += n
	}

	if runPrivacy {
		fs, n, perr := privacy.Scan(root, should)
		if perr != nil {
			return perr
		}
		findings = append(findings, fs...)
		filesRead += n
	}

	if runIPA {
		fs, n, ierr := ipa.Scan(scanIPAPath)
		if ierr != nil {
			return ierr
		}
		findings = append(findings, fs...)
		filesRead += n
	}

	sum := codescan.SummaryFrom(findings, filesRead)

	out := os.Stdout
	if outputPath != "" {
		f, cerr := os.Create(outputPath)
		if cerr != nil {
			return cerr
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "json":
		if jerr := report.JSON(out, findings, sum); jerr != nil {
			return jerr
		}
	default:
		report.Terminal(out, findings, sum, report.ParseLang(langStr))
	}

	if !sum.Passed {
		cmd.Annotations = map[string]string{"exit": "1"}
	}
	return nil
}

func validFormat(format string) bool {
	return format == "terminal" || format == "json"
}

func validLang(lang string) bool {
	return lang == "zh" || lang == "en" || lang == "both"
}

func hasSourceScanner(scanners map[string]bool) bool {
	return scanners["codescan"] || scanners["metadata"] || scanners["privacy"]
}

func isIPAAutoDiscoveryMode(scanners map[string]bool) bool {
	return scanners != nil && scanners[ipaScannerName] && !hasSourceScanner(scanners)
}

func discoverSingleIPAForPlainRun(dir string) (string, bool, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || hasProjectIndicators(dir) {
		return "", false, nil
	}

	matches, err := listIPAPaths(dir)
	if err != nil {
		return "", false, err
	}

	switch len(matches) {
	case 0:
		return "", false, nil
	case 1:
		return matches[0], true, nil
	default:
		return "", false, fmt.Errorf("当前目录不像源码项目，但发现多个 .ipa 文件：%s；请使用 --ipa 指定其中一个", strings.Join(matches, "、"))
	}
}

func discoverSingleIPA(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("读取 IPA 查找目录失败：%w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("使用 --only ipa 自动查找 IPA 时，扫描路径必须是目录或 .ipa 文件：%s", dir)
	}

	matches, err := listIPAPaths(dir)
	if err != nil {
		return "", err
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("未在目录 %q 下找到 .ipa 文件；请把 IPA 放在该目录，或使用 --ipa 指定文件", dir)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("目录 %q 下发现多个 .ipa 文件：%s；请使用 --ipa 指定其中一个", dir, strings.Join(matches, "、"))
	}
}

func hasProjectIndicators(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}

	for _, entry := range entries {
		name := entry.Name()
		if projectIndicatorNames[name] || projectIndicatorExtensions[strings.ToLower(filepath.Ext(name))] {
			return true
		}
	}
	return false
}

func listIPAPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取 IPA 查找目录失败：%w", err)
	}

	var matches []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		candidatePath := filepath.Join(dir, entry.Name())
		if ipa.LooksLikeIPA(candidatePath) {
			matches = append(matches, candidatePath)
		}
	}
	return matches, nil
}
