package codescan

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLangForExt(t *testing.T) {
	cases := map[string]string{
		"a.swift": "swift", "a.m": "objc", "a.h": "objc",
		"a.ts": "ts", "a.tsx": "ts", "a.js": "js", "a.jsx": "js",
		"a.txt": "",
	}
	for name, want := range cases {
		if got := langForExt(name); got != want {
			t.Errorf("langForExt(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestScanWalksAndAppliesRules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Sources/A.swift", `let w = UIWebView()`)
	writeFile(t, dir, "Sources/B.swift", `let w = WKWebView()`)
	writeFile(t, dir, "README.txt", `UIWebView mentioned in docs`) // 非源码，跳过

	res, err := Scan(dir, ShouldScan(nil), AllRules())
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesRead != 2 {
		t.Errorf("FilesRead = %d, want 2 (only .swift)", res.FilesRead)
	}
	var hit bool
	for _, f := range res.Findings {
		if f.RuleID == "uiwebview" {
			hit = true
		}
	}
	if !hit {
		t.Error("expected uiwebview finding from A.swift")
	}
}

func TestScanRespectsIgnore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Pods/X.swift", `let w = UIWebView()`)
	res, err := Scan(dir, func(rel string) bool {
		// 忽略 Pods 目录
		return !hasDirPrefix(rel, "Pods")
	}, AllRules())
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesRead != 0 {
		t.Errorf("FilesRead = %d, want 0 (Pods ignored)", res.FilesRead)
	}
}

func TestScanGlobIgnore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Foo.generated.swift", `let w = UIWebView()`)
	writeFile(t, dir, "Bar.swift", `let w = WKWebView()`)
	res, err := Scan(dir, ShouldScan([]string{"*.generated.swift"}), AllRules())
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesRead != 1 {
		t.Errorf("FilesRead = %d, want 1 (generated file ignored via glob)", res.FilesRead)
	}
}

func TestScanIgnoresDefaultDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App/A.swift", `let w = UIWebView()`)
	writeFile(t, dir, ".kilo/node_modules/x.ts", `let u = "http://x"`)
	writeFile(t, dir, "node_modules/dep/y.js", `let u = "http://y"`)
	writeFile(t, dir, ".git/config.swift", `let w = UIWebView()`)
	writeFile(t, dir, "Pods/Lib/z.swift", `let w = UIWebView()`)
	res, err := Scan(dir, ShouldScan(nil), AllRules())
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesRead != 1 {
		t.Errorf("FilesRead = %d, want 1 (only App/A.swift; deps & hidden dirs ignored by default)", res.FilesRead)
	}
}
