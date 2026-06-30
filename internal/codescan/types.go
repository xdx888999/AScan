package codescan

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarn
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Finding 是单条检测结果，所有面向用户的文案均为中英双语。
type Finding struct {
	RuleID    string   `json:"rule_id"`
	Severity  Severity `json:"severity"`
	Guideline string   `json:"guideline"`
	TitleZH   string   `json:"title_zh"`
	TitleEN   string   `json:"title_en"`
	DetailZH  string   `json:"detail_zh"`
	DetailEN  string   `json:"detail_en"`
	FixZH     string   `json:"fix_zh"`
	FixEN     string   `json:"fix_en"`
	File      string   `json:"file"`
	Line      int      `json:"line"` // 1-indexed
	Code      string   `json:"code,omitempty"`
}

// FileContext 是规则检查的输入。
type FileContext struct {
	Path    string
	Lang    string // swift/objc/ts/js/plist/json
	Content string
	Lines   []string
}

// Rule 是可插拔的检查单元。
type Rule interface {
	ID() string
	Applies(fc FileContext) bool
	Check(fc FileContext) []Finding
}

type Summary struct {
	Total     int  `json:"total"`
	Critical  int  `json:"critical"`
	High      int  `json:"high"`
	Warns     int  `json:"warns"`
	Infos     int  `json:"infos"`
	FilesRead int  `json:"files_read"`
	Passed    bool `json:"passed"`
}

func SummaryFrom(findings []Finding, filesRead int) Summary {
	s := Summary{Total: len(findings), FilesRead: filesRead}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityWarn:
			s.Warns++
		case SeverityInfo:
			s.Infos++
		}
	}
	s.Passed = s.Critical == 0
	return s
}
