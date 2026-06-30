package privacy

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xdx888999/AScan/internal/codescan"
)

// requiredReasonAPIPattern 匹配常见的 Required Reason API 使用，用于判断是否更需要隐私清单。
var requiredReasonAPIPattern = regexp.MustCompile(`UserDefaults|NSUserDefaults|@AppStorage|\.systemUptime\b|mach_absolute_time|\bstatfs\b|volumeAvailableCapacity|\.creationDate\b|\.modificationDate\b|getattrlist`)

func isSourceFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".swift", ".m", ".mm", ".h":
		return true
	default:
		return false
	}
}

// Scan 检查是否存在 PrivacyInfo.xcprivacy；缺失时按是否使用 Required Reason API 调整严重度。
// 第二个返回值固定为 0：工程级检查，不计入“扫描文件数”。
func Scan(root string, should codescan.ScanPredicate) ([]codescan.Finding, int, error) {
	found := false
	usesRRAPI := false
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
		if d.Name() == "PrivacyInfo.xcprivacy" {
			found = true
			return filepath.SkipAll
		}
		if !usesRRAPI && isSourceFile(d.Name()) {
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil // 读取失败跳过该文件
			}
			if requiredReasonAPIPattern.Match(data) {
				usesRRAPI = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if found {
		return nil, 0, nil
	}
	if usesRRAPI {
		return []codescan.Finding{{
			RuleID:    "missing-privacy-manifest",
			Severity:  codescan.SeverityInfo,
			Guideline: "5.1.1",
			TitleZH:   "建议补充隐私清单 PrivacyInfo.xcprivacy", TitleEN: "Consider adding PrivacyInfo.xcprivacy",
			DetailZH: "检测到使用了 Required Reason API（如 UserDefaults）。按 Apple 要求应在隐私清单中声明使用原因；当前缺失通常不会直接拒审，但建议补充以更稳合规。",
			DetailEN: "Detected Required Reason API use (e.g. UserDefaults). Apple expects you to declare the reason in a privacy manifest. Missing it usually won't cause outright rejection, but adding it is recommended.",
			FixZH:    "在 Xcode 中 New File → App Privacy 添加 PrivacyInfo.xcprivacy，声明用到的 API（如 UserDefaults 选 CA92.1）与数据类型。",
			FixEN:    "In Xcode, New File → App Privacy to add PrivacyInfo.xcprivacy and declare the APIs used (e.g. UserDefaults → CA92.1) and data types.",
		}}, 0, nil
	}
	return []codescan.Finding{{
		RuleID:    "missing-privacy-manifest",
		Severity:  codescan.SeverityInfo,
		Guideline: "5.1.1",
		TitleZH:   "未发现隐私清单 PrivacyInfo.xcprivacy（可选）", TitleEN: "No PrivacyInfo.xcprivacy found (optional)",
		DetailZH: "未检测到明显的 Required Reason API 使用。若你的 App 使用第三方 SDK 或访问相册/文件时间戳等，建议补充隐私清单；否则可忽略。",
		DetailEN: "No obvious Required Reason API usage detected. If your app uses third-party SDKs or accesses photo library/file timestamps, consider adding a privacy manifest; otherwise you can ignore this.",
		FixZH:    "如需补充：Xcode → New File → App Privacy 添加 PrivacyInfo.xcprivacy。",
		FixEN:    "If needed: Xcode → New File → App Privacy to add PrivacyInfo.xcprivacy.",
	}}, 0, nil
}
