package codescan

import (
	"encoding/json"
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityInfo:     "info",
		SeverityWarn:     "warn",
		SeverityHigh:     "high",
		SeverityCritical: "critical",
	}
	for sev, want := range cases {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}

func TestSummaryFromFindings(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityWarn},
		{Severity: SeverityInfo},
	}
	s := SummaryFrom(fs, 3)
	if s.Total != 4 || s.Critical != 1 || s.High != 1 || s.Warns != 1 || s.Infos != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if s.FilesRead != 3 {
		t.Errorf("FilesRead = %d, want 3", s.FilesRead)
	}
	if s.Passed {
		t.Error("Passed should be false when a critical finding exists")
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	b, err := json.Marshal(SeverityCritical)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"critical"` {
		t.Errorf("Severity JSON = %s, want \"critical\"", b)
	}
}
