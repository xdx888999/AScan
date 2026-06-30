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
