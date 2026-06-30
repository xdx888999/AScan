package report

import (
	"encoding/json"
	"io"

	"github.com/xdx888999/AScan/internal/codescan"
)

type jsonDoc struct {
	Summary    codescan.Summary   `json:"summary"`
	Findings   []codescan.Finding `json:"findings"`
	Disclaimer disclaimerText     `json:"disclaimer"`
}

type disclaimerText struct {
	ZH string `json:"zh"`
	EN string `json:"en"`
}

func JSON(w io.Writer, findings []codescan.Finding, sum codescan.Summary) error {
	if findings == nil {
		findings = []codescan.Finding{}
	}
	doc := jsonDoc{
		Summary:  sum,
		Findings: findings,
		Disclaimer: disclaimerText{
			ZH: "通过 AScan 不保证一定过审，仅检查能在代码层面发现的常见问题，可能存在漏报与误报。",
			EN: "Passing AScan does not guarantee approval; it only catches common code-level issues and may have false negatives/positives.",
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
