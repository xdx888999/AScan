package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndQuery(t *testing.T) {
	dir := t.TempDir()
	yml := `
rules:
  http-cleartext:
    severity: info
  placeholder-content:
    enabled: false
ignore:
  - Pods
  - Carthage
`
	p := filepath.Join(dir, ".ascan.yml")
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled("placeholder-content") {
		t.Error("placeholder-content should be disabled")
	}
	if !cfg.Enabled("http-cleartext") {
		t.Error("http-cleartext should remain enabled")
	}
	if sev, ok := cfg.SeverityOverride("http-cleartext"); !ok || sev != "info" {
		t.Errorf("severity override = %q,%v want info,true", sev, ok)
	}
	if got := cfg.Ignored(); len(got) != 2 || got[0] != "Pods" {
		t.Errorf("ignored = %v", got)
	}
}

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yml"))
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if !cfg.Enabled("anything") {
		t.Error("with no config every rule is enabled by default")
	}
}
