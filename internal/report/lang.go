package report

type Lang int

const (
	LangBoth Lang = iota
	LangZH
	LangEN
)

func ParseLang(s string) Lang {
	switch s {
	case "zh":
		return LangZH
	case "en":
		return LangEN
	default:
		return LangBoth
	}
}
