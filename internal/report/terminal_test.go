package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xdx888999/AScan/internal/codescan"
)

func sampleFindings() []codescan.Finding {
	return []codescan.Finding{
		{RuleID: "uiwebview", Severity: codescan.SeverityHigh, TitleZH: "使用了已废弃的 UIWebView", TitleEN: "Deprecated UIWebView in use", FixZH: "替换成 WKWebView", FixEN: "Replace with WKWebView", File: "A.swift", Line: 3},
	}
}

func TestTerminalShowsBilingualAndVerdict(t *testing.T) {
	var buf bytes.Buffer
	fs := sampleFindings()
	Terminal(&buf, fs, codescan.SummaryFrom(fs, 1), LangBoth)
	out := buf.String()
	if !strings.Contains(out, "使用了已废弃的 UIWebView") || !strings.Contains(out, "Deprecated UIWebView in use") {
		t.Error("both languages should appear")
	}
	if !strings.Contains(out, "A.swift:3") {
		t.Error("file:line should appear")
	}
	if !strings.Contains(out, "🟡") {
		t.Error("expected yellow verdict for high-only findings")
	}
	if !strings.Contains(out, "不保证") || !strings.Contains(out, "NOT guarantee") {
		t.Error("disclaimer must always appear in both languages")
	}
}

func TestTerminalGreenWhenClean(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, nil, codescan.SummaryFrom(nil, 5), LangBoth)
	if !strings.Contains(buf.String(), "🟢") {
		t.Error("expected green verdict when no findings")
	}
}

func TestTerminalRedWhenCritical(t *testing.T) {
	var buf bytes.Buffer
	fs := []codescan.Finding{{RuleID: "x", Severity: codescan.SeverityCritical, TitleZH: "严重", TitleEN: "Critical"}}
	Terminal(&buf, fs, codescan.SummaryFrom(fs, 1), LangBoth)
	if !strings.Contains(buf.String(), "🔴") {
		t.Error("expected red verdict when critical present")
	}
}
