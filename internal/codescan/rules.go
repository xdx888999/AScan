package codescan

// AllRules 返回内置规则集。文案均为中英双语，Fix 用大白话。
func AllRules() []Rule {
	return []Rule{
		&PatternRule{
			IDStr: "private-api", Guideline: "2.5.1", Severity: SeverityCritical,
			TitleZH: "疑似调用私有 API", TitleEN: "Possible private API usage",
			DetailZH: "通过字符串调用以下划线开头的方法/属性，通常是 Apple 私有 API，会被拒。",
			DetailEN: "Calling underscore-prefixed methods via strings usually means private Apple APIs and gets rejected.",
			FixZH:    "删掉对下划线开头方法的调用，改用 Apple 公开 API。",
			FixEN:    "Remove calls to underscore-prefixed methods and use public Apple APIs instead.",
			Langs:    []string{"swift", "objc"},
			Patterns: []string{`NSSelectorFromString\s*\(\s*"_`, `valueForKey:\s*@?"_`},
		},
		&PatternRule{
			IDStr: "hardcoded-secret", Guideline: "5.1", Severity: SeverityCritical,
			TitleZH: "代码里写死了密钥", TitleEN: "Hardcoded secret in source",
			DetailZH: "源码中出现疑似私密密钥（如支付/云服务密钥），泄露后果严重。",
			DetailEN: "A secret key (payment/cloud) appears in source code, which is a serious leak risk.",
			FixZH:    "把密钥从代码里删掉，放到服务端或安全存储，不要打进 App。",
			FixEN:    "Remove the secret from code; keep it on a server or secure storage, never in the app.",
			Patterns: []string{`sk_live_[a-zA-Z0-9]{16,}`, `AKIA[0-9A-Z]{16}`},
		},
		&PatternRule{
			IDStr: "dynamic-code-exec", Guideline: "2.5.2", Severity: SeverityCritical,
			TitleZH: "疑似动态执行代码 / 热更新", TitleEN: "Possible dynamic code execution / hot update",
			DetailZH: "动态加载并执行代码（如 dlopen、JSPatch）违反 2.5.2，会被拒。",
			DetailEN: "Loading and executing code at runtime (dlopen, JSPatch) violates 2.5.2 and gets rejected.",
			FixZH:    "去掉热更新/动态执行逻辑，所有可执行代码必须随包提交审核。",
			FixEN:    "Remove hot-update/dynamic execution; all executable code must ship in the reviewed build.",
			Patterns: []string{`\bdlopen\s*\(`, `(?i)jspatch`},
		},
		&PatternRule{
			IDStr: "external-payment", Guideline: "3.1.1", Severity: SeverityHigh,
			TitleZH: "疑似绕过内购的外部支付", TitleEN: "Possible external payment bypassing IAP",
			DetailZH: "数字商品/服务用第三方支付绕过苹果内购，违反 3.1.1。",
			DetailEN: "Using third-party payment for digital goods bypasses Apple IAP, violating 3.1.1.",
			FixZH:    "数字商品必须用 Apple 内购（StoreKit）；实物/线下服务才可用外部支付。",
			FixEN:    "Use Apple IAP (StoreKit) for digital goods; external payment is only for physical/offline goods.",
			Patterns: []string{`(?i)stripe[^\n]*paymentintent`, `(?i)paypal[^\n]*checkout`},
		},
		&PatternRule{
			IDStr: "uiwebview", Severity: SeverityHigh,
			TitleZH: "使用了已废弃的 UIWebView", TitleEN: "Deprecated UIWebView in use",
			DetailZH: "Apple 已不接受含 UIWebView 的新构建。",
			DetailEN: "Apple no longer accepts new builds that contain UIWebView.",
			FixZH:    "把 UIWebView 全部替换成 WKWebView。",
			FixEN:    "Replace all UIWebView usage with WKWebView.",
			Langs:    []string{"swift", "objc"},
			Patterns: []string{`\bUIWebView\b`},
		},
		&PatternRule{
			IDStr: "http-cleartext", Severity: SeverityWarn,
			TitleZH: "存在明文 HTTP 连接", TitleEN: "Cleartext HTTP connection",
			DetailZH:       "明文 http:// 连接不安全，且可能触发 ATS 相关问询。",
			DetailEN:       "Cleartext http:// is insecure and may trigger ATS-related questions.",
			FixZH:          "把 http:// 改成 https://；确需明文时在 Info.plist 配置 ATS 例外。",
			FixEN:          "Change http:// to https://; if cleartext is required, configure an ATS exception in Info.plist.",
			Patterns:       []string{`"http://[^"]+"`},
			IgnorePatterns: []string{`^\s*//`, `(?i)http://(localhost|127\.0\.0\.1|www\.w3\.org|schemas\.)`},
		},
		&PatternRule{
			IDStr: "placeholder-content", Guideline: "2.1", Severity: SeverityWarn,
			TitleZH: "存在占位/未完成内容", TitleEN: "Placeholder / unfinished content",
			DetailZH: "出现 lorem ipsum / coming soon 等占位文案，审核会认为 App 未完成。",
			DetailEN: "Placeholder text like lorem ipsum / coming soon makes the app look unfinished to reviewers.",
			FixZH:    "提交前把占位文案换成真实内容。",
			FixEN:    "Replace placeholder text with real content before submitting.",
			Patterns: []string{`(?i)lorem ipsum`, `(?i)\bcoming soon\b`},
		},
	}
}
