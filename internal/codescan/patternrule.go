package codescan

import (
	"regexp"
	"strings"
	"sync"
)

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// PatternRule 是基于正则的规则主力实现。
type PatternRule struct {
	IDStr     string
	Guideline string
	Severity  Severity
	TitleZH   string
	TitleEN   string
	DetailZH  string
	DetailEN  string
	FixZH     string
	FixEN     string
	Langs     []string // 空 = 适用所有语言

	Patterns       []string
	AntiPatterns   []string
	IgnorePatterns []string

	once   sync.Once
	pat    []*regexp.Regexp
	anti   []*regexp.Regexp
	ignore []*regexp.Regexp
}

func (r *PatternRule) ID() string { return r.IDStr }

func (r *PatternRule) compile() {
	r.once.Do(func() {
		for _, p := range r.Patterns {
			r.pat = append(r.pat, regexp.MustCompile(p))
		}
		for _, p := range r.AntiPatterns {
			r.anti = append(r.anti, regexp.MustCompile(p))
		}
		for _, p := range r.IgnorePatterns {
			r.ignore = append(r.ignore, regexp.MustCompile(p))
		}
	})
}

func (r *PatternRule) Applies(fc FileContext) bool {
	if len(r.Langs) == 0 {
		return true
	}
	for _, l := range r.Langs {
		if l == fc.Lang {
			return true
		}
	}
	return false
}

func (r *PatternRule) Check(fc FileContext) []Finding {
	r.compile()
	// anti-pattern：整文件命中任一则抑制本规则
	for _, a := range r.anti {
		if a.MatchString(fc.Content) {
			return nil
		}
	}
	var out []Finding
	for i, line := range fc.Lines {
		if r.lineIgnored(line) {
			continue
		}
		for _, p := range r.pat {
			if p.MatchString(line) {
				out = append(out, Finding{
					RuleID:    r.IDStr,
					Severity:  r.Severity,
					Guideline: r.Guideline,
					TitleZH:   r.TitleZH,
					TitleEN:   r.TitleEN,
					DetailZH:  r.DetailZH,
					DetailEN:  r.DetailEN,
					FixZH:     r.FixZH,
					FixEN:     r.FixEN,
					File:      fc.Path,
					Line:      i + 1,
					Code:      strings.TrimSpace(line),
				})
				break // 同一行命中一次即可
			}
		}
	}
	return out
}

func (r *PatternRule) lineIgnored(line string) bool {
	for _, ig := range r.ignore {
		if ig.MatchString(line) {
			return true
		}
	}
	return false
}
