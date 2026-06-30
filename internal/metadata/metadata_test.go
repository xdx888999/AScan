package metadata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xdx888999/AScan/internal/codescan"
)

const plistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">`

func writePlist(t *testing.T, dir, body string) {
	t.Helper()
	p := filepath.Join(dir, "Info.plist")
	content := plistHeader + "\n<dict>\n" + body + "\n</dict>\n</plist>\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ids(fs []codescan.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestMetadataFlagsMissingEncryptionAndVaguePurpose(t *testing.T) {
	dir := t.TempDir()
	writePlist(t, dir, `<key>CFBundleIdentifier</key><string>com.x.y</string>
<key>NSCameraUsageDescription</key><string>需要相机</string>`)
	fs, examined, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if examined != 1 {
		t.Errorf("examined = %d, want 1", examined)
	}
	got := ids(fs)
	if !got["encryption-not-declared"] {
		t.Error("should flag missing ITSAppUsesNonExemptEncryption")
	}
	if !got["vague-purpose-string"] {
		t.Error("should flag short usage description")
	}
}

func TestMetadataCleanPlistNoFindings(t *testing.T) {
	dir := t.TempDir()
	writePlist(t, dir, `<key>CFBundleIdentifier</key><string>com.x.y</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>NSCameraUsageDescription</key><string>需要使用相机来拍摄照片用于头像上传</string>`)
	fs, _, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("clean plist should have 0 findings, got %d: %+v", len(fs), fs)
	}
}

func TestMetadataIgnoresNonAppPlist(t *testing.T) {
	dir := t.TempDir()
	writePlist(t, dir, `<key>SomeOtherKey</key><string>value</string>`)
	fs, examined, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if examined != 0 {
		t.Errorf("examined = %d, want 0 (non-app plist skipped)", examined)
	}
	if len(fs) != 0 {
		t.Errorf("non-app plist should produce 0 findings, got %d", len(fs))
	}
}

// 现代 Xcode 工程的 Info.plist 常只含权限说明而无 CFBundleIdentifier，
// 也应被识别为 App 主清单并执行检查（回归：曾因判定过严而漏报）。
func TestMetadataTreatsUsageDescriptionOnlyPlistAsApp(t *testing.T) {
	dir := t.TempDir()
	writePlist(t, dir, `<key>NSCameraUsageDescription</key><string>需要使用相机来拍摄照片用于头像</string>`)
	fs, examined, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if examined != 1 {
		t.Errorf("examined = %d, want 1 (UsageDescription-only plist is an app manifest)", examined)
	}
	if !ids(fs)["encryption-not-declared"] {
		t.Error("should flag missing encryption on a usage-description-only app plist")
	}
}

func TestMetadataEncryptionDeclaredInBuildSettings(t *testing.T) {
	dir := t.TempDir()
	// App Info.plist 缺加密键，但 .pbxproj 在构建设置里声明了 → 不应再报 encryption-not-declared
	writePlist(t, dir, `<key>CFBundleIdentifier</key><string>com.x.y</string>`)
	proj := filepath.Join(dir, "App.xcodeproj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "project.pbxproj"),
		[]byte("INFOPLIST_KEY_ITSAppUsesNonExemptEncryption = NO;"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, examined, err := Scan(dir, codescan.ShouldScan(nil))
	if err != nil {
		t.Fatal(err)
	}
	if examined != 1 {
		t.Errorf("examined = %d, want 1", examined)
	}
	if ids(fs)["encryption-not-declared"] {
		t.Error("encryption declared in build settings should suppress the finding")
	}
}
