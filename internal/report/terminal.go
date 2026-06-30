package report

import (
	"fmt"
	"io"

	"github.com/xdx888999/AScan/internal/codescan"
)

func sevIcon(s codescan.Severity) string {
	switch s {
	case codescan.SeverityCritical:
		return "⛔"
	case codescan.SeverityHigh:
		return "🔶"
	case codescan.SeverityWarn:
		return "⚠️"
	default:
		return "ℹ️"
	}
}

// 按语言选择文案：both 时中文在上、英文在下。
func bilingual(zh, en string, lang Lang) []string {
	switch lang {
	case LangZH:
		return []string{zh}
	case LangEN:
		return []string{en}
	default:
		return []string{zh, en}
	}
}

func Terminal(w io.Writer, findings []codescan.Finding, sum codescan.Summary, lang Lang) {
	for _, f := range findings {
		header := fmt.Sprintf("%s [%s]", sevIcon(f.Severity), f.Severity)
		loc := f.File
		if f.File != "" && f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if loc != "" {
			header += " " + loc
		}
		if f.Guideline != "" {
			header += fmt.Sprintf(" (指南 %s)", f.Guideline)
		}
		fmt.Fprintln(w, header)
		for _, line := range bilingual(f.TitleZH, f.TitleEN, lang) {
			fmt.Fprintf(w, "   %s\n", line)
		}
		for _, line := range bilingual(f.FixZH, f.FixEN, lang) {
			fmt.Fprintf(w, "   → %s\n", line)
		}
		fmt.Fprintln(w)
	}
	writeVerdict(w, sum, lang)
	writeDisclaimer(w, lang)
}

func writeVerdict(w io.Writer, sum codescan.Summary, lang Lang) {
	fmt.Fprintf(w, "扫描 %d 个文件，发现 %d 个问题（严重 %d / 高 %d / 提醒 %d / 信息 %d）\n",
		sum.FilesRead, sum.Total, sum.Critical, sum.High, sum.Warns, sum.Infos)
	switch {
	case sum.Critical > 0:
		for _, l := range bilingual(
			fmt.Sprintf("🔴 大概率被拒——先修这 %d 个严重问题", sum.Critical),
			fmt.Sprintf("🔴 Likely to be rejected — fix these %d critical issue(s) first", sum.Critical), lang) {
			fmt.Fprintln(w, l)
		}
	case sum.High > 0 || sum.Warns > 0:
		for _, l := range bilingual(
			"🟡 建议修复后再提交", "🟡 Fix recommended before submitting", lang) {
			fmt.Fprintln(w, l)
		}
	default:
		for _, l := range bilingual(
			"🟢 没发现明显问题", "🟢 No obvious issues found", lang) {
			fmt.Fprintln(w, l)
		}
	}
}

func writeDisclaimer(w io.Writer, lang Lang) {
	fmt.Fprintln(w, "──────────")
	for _, l := range bilingual(
		"提示：通过 AScan 不保证一定过审。它只检查能在代码层面发现的常见问题，无法发现运行时行为、SDK 内部或动态拼接造成的违规，也可能存在误报，请自行判断。",
		"Note: Passing AScan does NOT guarantee approval. It only catches common code-level issues; it cannot detect runtime behavior, in-SDK, or dynamically-constructed violations, and may produce false positives. Use your judgment.",
		lang) {
		fmt.Fprintln(w, l)
	}
}
