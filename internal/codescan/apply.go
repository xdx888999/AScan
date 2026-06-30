package codescan

func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "info":
		return SeverityInfo, true
	case "warn":
		return SeverityWarn, true
	case "high":
		return SeverityHigh, true
	case "critical":
		return SeverityCritical, true
	default:
		return SeverityInfo, false
	}
}

// ApplyConfig 根据 enabled / 严重度覆盖回调，过滤并调整规则集。
// 注意：只对 *PatternRule 生效严重度覆盖；被禁用的规则直接剔除。
// 严重度采用就地修改：AllRules() 每次返回全新实例，调用方在扫描前一次性应用配置，
// 因此就地改安全；且 PatternRule 含 sync.Once，按值拷贝会触发 go vet copylocks，故不拷贝。
func ApplyConfig(rules []Rule, enabled func(id string) bool, sevOf func(id string) (string, bool)) []Rule {
	var out []Rule
	for _, r := range rules {
		if !enabled(r.ID()) {
			continue
		}
		if pr, ok := r.(*PatternRule); ok {
			if s, has := sevOf(r.ID()); has {
				if sev, valid := ParseSeverity(s); valid {
					pr.Severity = sev
				}
			}
		}
		out = append(out, r)
	}
	return out
}
