package codescan

import "testing"

func TestApplyConfigDisablesRule(t *testing.T) {
	rules := AllRules()
	enabled := func(id string) bool { return id != "uiwebview" }
	sevOf := func(id string) (string, bool) { return "", false }
	got := ApplyConfig(rules, enabled, sevOf)
	for _, r := range got {
		if r.ID() == "uiwebview" {
			t.Fatal("uiwebview should be filtered out")
		}
	}
	if len(got) != len(rules)-1 {
		t.Errorf("len = %d, want %d", len(got), len(rules)-1)
	}
}

func TestApplyConfigOverridesSeverity(t *testing.T) {
	rules := AllRules()
	enabled := func(id string) bool { return true }
	sevOf := func(id string) (string, bool) {
		if id == "http-cleartext" {
			return "info", true
		}
		return "", false
	}
	got := ApplyConfig(rules, enabled, sevOf)
	for _, r := range got {
		if r.ID() == "http-cleartext" {
			if pr := r.(*PatternRule); pr.Severity != SeverityInfo {
				t.Errorf("severity = %v, want info", pr.Severity)
			}
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{"info": SeverityInfo, "warn": SeverityWarn, "high": SeverityHigh, "critical": SeverityCritical}
	for s, want := range cases {
		if got, ok := ParseSeverity(s); !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %v,%v want %v", s, got, ok, want)
		}
	}
	if _, ok := ParseSeverity("bogus"); ok {
		t.Error("bogus severity should not parse")
	}
}
