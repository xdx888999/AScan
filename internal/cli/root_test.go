package cli

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCodescanExitsNonZeroOnCritical(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"),
		[]byte(`let k = "`+fakeStripeLiveKey()+`"`), 0o644); err != nil {
		t.Fatal(err)
	}
	code := Run([]string{dir, "--format", "json"})
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (critical present)", code)
	}
}

func TestRunCleanExitsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"),
		[]byte(`let w = WKWebView()`), 0o644); err != nil {
		t.Fatal(err)
	}
	code := Run([]string{dir})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (clean)", code)
	}
}

func TestRunOnlyFilter(t *testing.T) {
	dir := t.TempDir()
	// codescan 会命中，但 --only metadata 时应跳过 codescan，从而退出 0
	if err := os.WriteFile(filepath.Join(dir, "A.swift"),
		[]byte(`let k = "`+fakeStripeLiveKey()+`"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{dir, "--only", "metadata"}); code != 0 {
		t.Errorf("with --only metadata, codescan skipped, want exit 0, got %d", code)
	}
}

func TestRunOnlyUnknownErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"),
		[]byte(`let w = UIWebView()`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{dir, "--only", "bogus"}); code == 0 {
		t.Errorf("unknown scanner name should not exit 0, got %d", code)
	}
}

func TestRunInvalidFormatErrors(t *testing.T) {
	dir := t.TempDir()
	if code := Run([]string{dir, "--format", "xml"}); code == 0 {
		t.Fatal("invalid --format should fail")
	}
}

func TestRunInvalidLangErrors(t *testing.T) {
	dir := t.TempDir()
	if code := Run([]string{dir, "--lang", "cn"}); code == 0 {
		t.Fatal("invalid --lang should fail")
	}
}

func TestRunPrivacyFlagsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"), []byte("let w = WKWebView()"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{dir, "--only", "privacy", "--format", "json", "--output", filepath.Join(dir, "r.json")}); code != 0 {
		t.Errorf("missing manifest is high (not critical), want exit 0, got %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "missing-privacy-manifest") {
		t.Error("json should contain missing-privacy-manifest finding")
	}
}

func TestRunWithIPAFlagIncludesIPAFinding(t *testing.T) {
	dir := t.TempDir()
	ipaPath := writeTestIPA(t, dir, map[string]string{
		"Payload/App.app/Info.plist": cliPlistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleExecutable</key><string>App</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/App":              "MachO binary placeholder",
		"Payload/App.app/AppIcon60x60.png": "png placeholder",
	})
	reportPath := filepath.Join(dir, "report.json")

	if code := Run([]string{dir, "--ipa", ipaPath, "--format", "json", "--output", reportPath}); code != 0 {
		t.Errorf("IPA high finding is not critical, want exit 0, got %d", code)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ipa-missing-version") {
		t.Fatalf("json should contain IPA finding, got %s", data)
	}
}

func TestRunOnlyIPASkipsCodescan(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.swift"),
		[]byte(`let k = "`+fakeStripeLiveKey()+`"`), 0o644); err != nil {
		t.Fatal(err)
	}
	ipaPath := writeCleanTestIPA(t, dir)
	reportPath := filepath.Join(dir, "ipa-only.json")

	if code := Run([]string{dir, "--only", "ipa", "--ipa", ipaPath, "--format", "json", "--output", reportPath}); code != 0 {
		t.Errorf("--only ipa should skip critical codescan finding, want exit 0, got %d", code)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hardcoded-secret") {
		t.Fatalf("--only ipa should skip codescan findings, got %s", data)
	}
}

func TestRunOnlyIPAWithoutIPAPathErrors(t *testing.T) {
	dir := t.TempDir()
	if code := Run([]string{dir, "--only", "ipa"}); code == 0 {
		t.Fatal("--only ipa without --ipa should fail")
	}
}

func TestRunDirectIPAPath(t *testing.T) {
	dir := t.TempDir()
	ipaPath := writeCleanTestIPA(t, dir)
	reportPath := filepath.Join(dir, "direct-ipa.json")

	if code := Run([]string{ipaPath, "--format", "json", "--output", reportPath}); code != 0 {
		t.Errorf("clean direct IPA scan should exit 0, got %d", code)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"files_read": 2`) {
		t.Fatalf("direct IPA scan should inspect plist and executable, got %s", data)
	}
}

func TestRunDirectIPAWithSourceOnlyErrors(t *testing.T) {
	dir := t.TempDir()
	ipaPath := writeCleanTestIPA(t, dir)
	if code := Run([]string{ipaPath, "--only", "codescan"}); code == 0 {
		t.Fatal("direct IPA path with source scanner should fail")
	}
}

func TestRunIPACriticalFindingExitsOne(t *testing.T) {
	dir := t.TempDir()
	ipaPath := writeTestIPA(t, dir, map[string]string{
		"Payload/App.app/Info.plist": cliPlistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/AppIcon60x60.png": "png placeholder",
	})

	if code := Run([]string{dir, "--only", "ipa", "--ipa", ipaPath, "--format", "json", "--output", filepath.Join(dir, "critical.json")}); code != 1 {
		t.Errorf("critical IPA finding should exit 1, got %d", code)
	}
}

func TestRunVersion(t *testing.T) {
	if code := Run([]string{"--version"}); code != 0 {
		t.Errorf("--version should exit 0, got %d", code)
	}
}

func writeCleanTestIPA(t *testing.T, dir string) string {
	t.Helper()
	return writeTestIPA(t, dir, map[string]string{
		"Payload/App.app/Info.plist": cliPlistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>App</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/App":              "MachO binary placeholder",
		"Payload/App.app/AppIcon60x60.png": "png placeholder",
	})
}

func writeTestIPA(t *testing.T, dir string, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "App.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	defer writer.Close()
	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func cliPlistBody(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
` + body + `
</dict>
</plist>
`
}

func fakeStripeLiveKey() string {
	return "sk_" + "live_" + "abcdefghij0123456789ABCD"
}
