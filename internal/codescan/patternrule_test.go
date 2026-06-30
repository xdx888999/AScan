package codescan

import "testing"

func ctx(path, lang, content string) FileContext {
	return FileContext{Path: path, Lang: lang, Content: content, Lines: splitLines(content)}
}

func TestPatternRuleMatches(t *testing.T) {
	r := &PatternRule{
		IDStr:    "demo",
		Severity: SeverityHigh,
		Langs:    []string{"swift"},
		Patterns: []string{`forbidden`},
	}
	fc := ctx("A.swift", "swift", "line one\nforbidden here\nlast")
	fs := r.Check(fc)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Line != 2 {
		t.Errorf("Line = %d, want 2", fs[0].Line)
	}
}

func TestPatternRuleAntiPatternSuppresses(t *testing.T) {
	r := &PatternRule{
		IDStr:        "demo",
		Severity:     SeverityHigh,
		Langs:        []string{"swift"},
		Patterns:     []string{`forbidden`},
		AntiPatterns: []string{`SAFE_WRAPPER`},
	}
	fc := ctx("A.swift", "swift", "forbidden\n// SAFE_WRAPPER present")
	if fs := r.Check(fc); len(fs) != 0 {
		t.Fatalf("anti-pattern should suppress, got %d findings", len(fs))
	}
}

func TestPatternRuleIgnoreLine(t *testing.T) {
	r := &PatternRule{
		IDStr:          "demo",
		Severity:       SeverityHigh,
		Langs:          []string{"swift"},
		Patterns:       []string{`forbidden`},
		IgnorePatterns: []string{`^\s*//`},
	}
	fc := ctx("A.swift", "swift", "// forbidden in comment")
	if fs := r.Check(fc); len(fs) != 0 {
		t.Fatalf("ignored line should not match, got %d", len(fs))
	}
}

func TestPatternRuleAppliesByLang(t *testing.T) {
	r := &PatternRule{IDStr: "demo", Langs: []string{"swift"}, Patterns: []string{`x`}}
	if r.Applies(ctx("A.ts", "ts", "x")) {
		t.Error("rule should not apply to ts when restricted to swift")
	}
	if !r.Applies(ctx("A.swift", "swift", "x")) {
		t.Error("rule should apply to swift")
	}
}
