package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/xdx888999/AScan/internal/codescan"
)

func TestJSONStructure(t *testing.T) {
	var buf bytes.Buffer
	fs := sampleFindings()
	if err := JSON(&buf, fs, codescan.SummaryFrom(fs, 1)); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := doc["summary"]; !ok {
		t.Error("json should have summary")
	}
	if _, ok := doc["findings"]; !ok {
		t.Error("json should have findings")
	}
	if _, ok := doc["disclaimer"]; !ok {
		t.Error("json should carry disclaimer field")
	}
}
