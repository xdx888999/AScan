package codescan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Result struct {
	Findings  []Finding
	FilesRead int
}

func (r Result) Summary() Summary { return SummaryFrom(r.Findings, r.FilesRead) }

// ScanPredicate 接收相对 root 的路径（用 / 分隔），返回是否应扫描。
type ScanPredicate func(rel string) bool

// DefaultIgnoreDirs 是默认忽略的依赖/构建目录名（按路径段匹配，任意层级生效）。
var DefaultIgnoreDirs = map[string]bool{
	"node_modules": true,
	"Pods":         true,
	"Carthage":     true,
	"DerivedData":  true,
	"build":        true,
	"vendor":       true,
}

// ShouldScan 返回扫描谓词：默认忽略隐藏目录（段名以 . 开头）与常见依赖/构建目录
// （DefaultIgnoreDirs，任意层级），再叠加用户在 .ascan.yml 配置的忽略（前缀或 glob）。
// 传 nil 表示无额外用户忽略（但默认忽略始终生效）。
func ShouldScan(ignored []string) ScanPredicate {
	return func(rel string) bool {
		for _, seg := range strings.Split(rel, "/") {
			if seg == "" || seg == "." {
				continue
			}
			if strings.HasPrefix(seg, ".") {
				return false
			}
			if DefaultIgnoreDirs[seg] {
				return false
			}
		}
		base := filepath.Base(rel)
		for _, ig := range ignored {
			if hasDirPrefix(rel, ig) {
				return false
			}
			if ok, _ := filepath.Match(ig, rel); ok {
				return false
			}
			if ok, _ := filepath.Match(ig, base); ok {
				return false
			}
		}
		return true
	}
}

func hasDirPrefix(rel, dir string) bool {
	dir = strings.Trim(dir, "/")
	return rel == dir || strings.HasPrefix(rel, dir+"/")
}

func langForExt(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".swift":
		return "swift"
	case ".m", ".h", ".mm":
		return "objc"
	case ".ts", ".tsx":
		return "ts"
	case ".js", ".jsx":
		return "js"
	default:
		return ""
	}
}

func Scan(root string, should ScanPredicate, rules []Rule) (Result, error) {
	var res Result
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && should != nil && !should(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		lang := langForExt(d.Name())
		if lang == "" {
			return nil
		}
		if should != nil && !should(rel) {
			return nil
		}
		content, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		res.FilesRead++
		fc := FileContext{Path: rel, Lang: lang, Content: string(content), Lines: splitLines(string(content))}
		for _, r := range rules {
			if r.Applies(fc) {
				res.Findings = append(res.Findings, r.Check(fc)...)
			}
		}
		return nil
	})
	return res, err
}
