package codescan

import "testing"

// 每条规则给一个应命中样例与一个不应命中样例。
func TestRulesPositiveAndNegative(t *testing.T) {
	type tc struct {
		ruleID string
		lang   string
		hit    string // 应命中
		miss   string // 不应命中
	}
	cases := []tc{
		{"private-api", "swift", `let m = NSSelectorFromString("_privateThing")`, `let m = NSSelectorFromString("publicThing")`},
		{"hardcoded-secret", "swift", `let k = "` + fakeStripeLiveKey() + `"`, `let k = loadKey()`},
		{"dynamic-code-exec", "swift", `dlopen(path, 2)`, `open(path)`},
		{"external-payment", "ts", `stripe.paymentIntents.create({})`, `iap.purchase(product)`},
		{"uiwebview", "swift", `let w = UIWebView(frame: f)`, `let w = WKWebView(frame: f)`},
		{"http-cleartext", "swift", `let u = "http://example.com/api"`, `let u = "https://example.com/api"`},
		{"placeholder-content", "swift", `let t = "Coming soon"`, `let t = "Welcome"`},
	}
	byID := map[string]Rule{}
	for _, r := range AllRules() {
		byID[r.ID()] = r
	}
	for _, c := range cases {
		r, ok := byID[c.ruleID]
		if !ok {
			t.Errorf("rule %q not found in AllRules()", c.ruleID)
			continue
		}
		if got := r.Check(ctx("F", c.lang, c.hit)); len(got) == 0 {
			t.Errorf("%s should match %q", c.ruleID, c.hit)
		}
		if got := r.Check(ctx("F", c.lang, c.miss)); len(got) != 0 {
			t.Errorf("%s should NOT match %q", c.ruleID, c.miss)
		}
	}
}

func fakeStripeLiveKey() string {
	return "sk_" + "live_" + "abcdefghij0123456789ABCD"
}

func TestAllRulesHaveBilingualText(t *testing.T) {
	for _, r := range AllRules() {
		pr, ok := r.(*PatternRule)
		if !ok {
			continue
		}
		if pr.TitleZH == "" || pr.TitleEN == "" || pr.FixZH == "" || pr.FixEN == "" {
			t.Errorf("rule %q missing bilingual title/fix", pr.IDStr)
		}
	}
}

// 确保内置规则集里的所有正则都能编译，防止坏正则导致运行时 panic。
func TestAllRulesCompile(t *testing.T) {
	for _, r := range AllRules() {
		// Check 内部会触发 compile()；空 FileContext 不应 panic。
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("rule %q panicked on compile/check: %v", r.ID(), rec)
				}
			}()
			r.Check(FileContext{Lang: "swift"})
		}()
	}
}
