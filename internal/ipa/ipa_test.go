package ipa

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/xdx888999/AScan/internal/codescan"
)

const testPlistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">`

func writeIPA(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "App.ipa")
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

func plistBody(body string) string {
	return testPlistHeader + "\n<dict>\n" + body + "\n</dict>\n</plist>\n"
}

func findingIDs(findings []codescan.Finding) map[string]bool {
	ids := map[string]bool{}
	for _, finding := range findings {
		ids[finding.RuleID] = true
	}
	return ids
}

func TestScanCleanIPA(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/App.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>App</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/App":              "MachO binary placeholder",
		"Payload/App.app/AppIcon60x60.png": "png placeholder",
	})

	findings, inspected, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if inspected != 2 {
		t.Errorf("inspected = %d, want 2", inspected)
	}
	if len(findings) != 0 {
		t.Fatalf("clean IPA should have no findings, got %+v", findings)
	}
}

func TestScanFlagsInfoBinaryAndArchiveIssues(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/App.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleExecutable</key><string>App</string>
<key>NSAppTransportSecurity</key><dict>
<key>NSAllowsArbitraryLoads</key><true/>
<key>NSExceptionDomains</key><dict>
<key>example.com</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>
</dict>
</dict>`),
		"Payload/App.app/App":                                     "MachO binary placeholder",
		"Payload/App.app/Frameworks/Legacy.framework/Legacy":      "framework binary with UIWebView symbol",
		"Payload/App.app/Frameworks/JSPatch.framework/Info.plist": "framework metadata placeholder",
	})

	findings, inspected, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if inspected != 3 {
		t.Errorf("inspected = %d, want 3", inspected)
	}
	ids := findingIDs(findings)
	for _, ruleID := range []string{
		"ipa-encryption-not-declared",
		"ipa-missing-version",
		"ipa-ats-arbitrary-loads",
		"ipa-ats-insecure-exception",
		"ipa-missing-icon-declaration",
		"ipa-uiwebview-symbol",
		"ipa-dynamic-code-framework",
	} {
		if !ids[ruleID] {
			t.Errorf("missing finding %q in %+v", ruleID, findings)
		}
	}
}

func TestScanFlagsMissingExecutable(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/App.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>MissingApp</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/AppIcon60x60.png": "png placeholder",
	})

	findings, _, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := findingIDs(findings)
	if !ids["ipa-missing-executable"] {
		t.Fatalf("should flag missing executable, got %+v", findings)
	}
}

func TestScanFlagsMissingExecutableName(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/App.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/AppIcon60x60.png": "png placeholder",
	})

	findings, _, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := findingIDs(findings)
	if !ids["ipa-missing-executable-name"] {
		t.Fatalf("should flag missing executable name, got %+v", findings)
	}
}

func TestScanMissingPayloadAppErrors(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Other/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>`),
	})

	if _, _, err := Scan(path); err == nil {
		t.Fatal("missing Payload/*.app/Info.plist should return an error")
	}
}

func TestScanMultiplePayloadAppsErrors(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/AppA.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.a</string>`),
		"Payload/AppB.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.b</string>`),
	})

	if _, _, err := Scan(path); err == nil {
		t.Fatal("multiple Payload/*.app bundles should return an error")
	}
}

func TestScanFlagsMissingIconReference(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/App.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>App</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>MissingIcon</string></array></dict></dict>`),
		"Payload/App.app/App": "MachO binary placeholder",
	})

	findings, _, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if !findingIDs(findings)["ipa-icon-reference-missing"] {
		t.Fatalf("should flag missing icon reference, got %+v", findings)
	}
}

func TestScanAcceptsScaleQualifiedIconFile(t *testing.T) {
	path := writeIPA(t, map[string]string{
		"Payload/App.app/Info.plist": plistBody(`<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>App</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
<key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>`),
		"Payload/App.app/App":                 "MachO binary placeholder",
		"Payload/App.app/AppIcon60x60@2x.png": "png placeholder",
	})

	findings, _, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if findingIDs(findings)["ipa-icon-reference-missing"] {
		t.Fatalf("@2x icon file should satisfy base icon reference, got %+v", findings)
	}
}

func TestLooksLikeIPA(t *testing.T) {
	if !LooksLikeIPA("Build/App.IPA") {
		t.Fatal("uppercase .IPA extension should be accepted")
	}
	if LooksLikeIPA("Build/App.zip") {
		t.Fatal(".zip should not be treated as IPA")
	}
}
