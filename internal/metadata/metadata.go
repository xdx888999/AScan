package metadata

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"howett.net/plist"

	"github.com/xdx888999/AScan/internal/codescan"
)

// minPurposeRunes 是权限用途说明的最小可接受长度（小于此视为过简）。
const minPurposeRunes = 6

type appManifest struct {
	rel string
	m   map[string]interface{}
}

// Scan 遍历 root，对"看起来是 App 主清单"（含 CFBundleIdentifier/CFBundleExecutable
// 或任意 *UsageDescription）的 Info.plist 执行元数据检查。
// 同时扫描 .pbxproj/.xcconfig，若加密合规声明写在构建设置里则不再报"未声明加密"。
// 返回 findings 与检查过的 App 主清单数。
func Scan(root string, should codescan.ScanPredicate) ([]codescan.Finding, int, error) {
	var manifests []appManifest
	encDeclared := false

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
		if should != nil && !should(rel) {
			return nil
		}

		name := d.Name()
		if name == "project.pbxproj" || strings.EqualFold(filepath.Ext(name), ".xcconfig") {
			if !encDeclared {
				if data, rerr := os.ReadFile(path); rerr == nil &&
					bytes.Contains(data, []byte("ITSAppUsesNonExemptEncryption")) {
					encDeclared = true
				}
			}
			return nil
		}
		if name != "Info.plist" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		var m map[string]interface{}
		if _, perr := plist.Unmarshal(data, &m); perr != nil {
			return nil // 解析失败的 plist 跳过
		}
		if !looksLikeAppManifest(m) {
			return nil
		}
		manifests = append(manifests, appManifest{rel: rel, m: m})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	var findings []codescan.Finding
	for _, am := range manifests {
		findings = append(findings, checkPlist(am.rel, am.m, encDeclared)...)
	}
	return findings, len(manifests), nil
}

// looksLikeAppManifest 判断一个 Info.plist 是否是 App 主清单。
// 现代 Xcode 工程的标准键常由构建设置注入而不写在 plist 里，
// 因此除标准标识键外，含任意权限用途说明（*UsageDescription）也视为 App 主清单。
func looksLikeAppManifest(m map[string]interface{}) bool {
	if _, ok := m["CFBundleIdentifier"]; ok {
		return true
	}
	if _, ok := m["CFBundleExecutable"]; ok {
		return true
	}
	for k := range m {
		if strings.HasSuffix(k, "UsageDescription") {
			return true
		}
	}
	return false
}

func checkPlist(rel string, m map[string]interface{}, encDeclaredElsewhere bool) []codescan.Finding {
	var out []codescan.Finding

	if _, ok := m["ITSAppUsesNonExemptEncryption"]; !ok && !encDeclaredElsewhere {
		out = append(out, codescan.Finding{
			RuleID:   "encryption-not-declared",
			Severity: codescan.SeverityInfo,
			TitleZH:  "未声明加密合规（提交时会被问到）", TitleEN: "Encryption compliance not declared (asked at submission)",
			DetailZH: "Info.plist 与构建设置都缺少 ITSAppUsesNonExemptEncryption。这不会导致拒审，只是上传时 App Store Connect 会让你回答一次是否使用加密。",
			DetailEN: "Neither Info.plist nor build settings declare ITSAppUsesNonExemptEncryption. This does NOT cause rejection; App Store Connect just asks the encryption question at upload.",
			FixZH:    "想省掉那一步可在 Info.plist 或构建设置加 ITSAppUsesNonExemptEncryption（只用标准加密如 HTTPS 填 false）。",
			FixEN:    "To skip that step, add ITSAppUsesNonExemptEncryption to Info.plist or build settings (set false if you only use standard encryption like HTTPS).",
			File:     rel,
		})
	}

	for k, v := range m {
		if !strings.HasSuffix(k, "UsageDescription") {
			continue
		}
		s, _ := v.(string)
		if utf8.RuneCountInString(strings.TrimSpace(s)) < minPurposeRunes {
			out = append(out, codescan.Finding{
				RuleID:    "vague-purpose-string",
				Severity:  codescan.SeverityWarn,
				Guideline: "5.1.1",
				TitleZH:   "权限用途说明过简或缺失", TitleEN: "Permission purpose string too short or missing",
				DetailZH: "权限说明 " + k + " 内容过短，审核要求清楚说明为什么需要该权限。",
				DetailEN: "Purpose string " + k + " is too short; review requires a clear explanation of why the permission is needed.",
				FixZH:    "把 " + k + " 写成一句明确说明用途的话，例如说明用相机做什么。",
				FixEN:    "Write " + k + " as a clear sentence explaining the actual use, e.g. what the camera is for.",
				File:     rel,
			})
		}
	}
	return out
}
