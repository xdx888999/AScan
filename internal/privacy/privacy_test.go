package privacy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xdx888999/AScan/internal/codescan"
)

func TestPrivacyInfoWhenMissingAndNoRRAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"), []byte("let x = 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "missing-privacy-manifest" {
		t.Fatalf("want 1 missing-privacy-manifest finding, got %+v", fs)
	}
	if fs[0].Severity != codescan.SeverityInfo {
		t.Errorf("severity = %v, want info (no Required Reason API detected)", fs[0].Severity)
	}
}

func TestPrivacyInfoWhenRRAPIUsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"),
		[]byte("let d = UserDefaults.standard\nd.set(1, forKey: \"k\")"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "missing-privacy-manifest" {
		t.Fatalf("want 1 missing-privacy-manifest finding, got %+v", fs)
	}
	if fs[0].Severity != codescan.SeverityInfo {
		t.Errorf("severity = %v, want info (Required Reason API detected)", fs[0].Severity)
	}
}

func TestPrivacyPassesWhenManifestPresent(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "App")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "PrivacyInfo.xcprivacy"), []byte("<plist></plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 即使用了 RR API，只要清单存在就算合规
	if err := os.WriteFile(filepath.Join(sub, "B.swift"), []byte("let d = UserDefaults.standard"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("manifest present should yield 0 findings, got %+v", fs)
	}
}

func TestPrivacyIgnoresManifestInIgnoredDir(t *testing.T) {
	dir := t.TempDir()
	pods := filepath.Join(dir, "Pods", "SomeLib")
	if err := os.MkdirAll(pods, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pods, "PrivacyInfo.xcprivacy"), []byte("<plist></plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _, err := Scan(dir, codescan.ShouldScan([]string{"Pods"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Errorf("manifest only in ignored Pods should still flag missing, got %+v", fs)
	}
}
