package runback

import (
	"encoding/base64"
	"regexp"
)

// Named secret/PII detectors, ported from packages/redact/src/patterns.ts.
// Ordered specific -> general so a provider key isn't first eaten by a
// looser rule. See that file's own comment for the honest limits of a
// regex-based (not parsing) redactor — the same limits apply here.

type redactionTier string

const (
	tierStandard redactionTier = "standard"
	tierStrict   redactionTier = "strict"
)

type redactionRule struct {
	name     string
	tier     redactionTier
	regex    *regexp.Regexp
	validate func(string) bool
	replace  func(string) string
}

// luhnValid keeps random digit runs from being flagged as card numbers.
func luhnValid(s string) bool {
	var digits []byte
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits = append(digits, s[i])
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func tag(name string) string { return "[redacted:" + name + "]" }

var keyValueRe = regexp.MustCompile(`^"([^"]+)"`)

var redactRules = []redactionRule{
	// ── cryptographic material ──
	{name: "private_key", tier: tierStandard, regex: regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----`)},
	// ── provider / vendor API keys ──
	{name: "anthropic_key", tier: tierStandard, regex: regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{name: "openai_key", tier: tierStandard, regex: regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{20,}`)},
	{name: "groq_key", tier: tierStandard, regex: regexp.MustCompile(`gsk_[A-Za-z0-9]{20,}`)},
	{name: "stripe_key", tier: tierStandard, regex: regexp.MustCompile(`(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`)},
	{name: "github_token", tier: tierStandard, regex: regexp.MustCompile(`gh[posru]_[A-Za-z0-9]{36,}`)},
	{name: "slack_token", tier: tierStandard, regex: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{name: "google_api_key", tier: tierStandard, regex: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{name: "aws_access_key", tier: tierStandard, regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	// ── tokens ──
	{name: "jwt", tier: tierStandard, regex: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{
		name: "bearer", tier: tierStandard,
		regex:   regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]{12,}`),
		replace: func(string) string { return "Bearer [redacted]" },
	},
	// ── personal data ──
	{name: "email", tier: tierStandard, regex: regexp.MustCompile(`[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)},
	{name: "ssn", tier: tierStandard, regex: regexp.MustCompile(`\b\d{3}[-. ]\d{2}[-. ]\d{4}\b`)},
	{name: "credit_card", tier: tierStandard, regex: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), validate: luhnValid},
	// ── secrets embedded as literal JSON-in-string text (not real object keys) ──
	{
		name: "json_embedded_secret", tier: tierStandard,
		regex: regexp.MustCompile(`(?i)"(password|passwd|pwd|secret|token|access_token|refresh_token|id_token|api_key|apikey|authorization|client_secret|private_key)"\s*:\s*"(?:[^"\\]|\\.)*"`),
		replace: func(m string) string {
			key := "secret"
			if sub := keyValueRe.FindStringSubmatch(m); sub != nil {
				key = sub[1]
			}
			return `"` + key + `": "[redacted:key:` + key + `]"`
		},
	},
	// ── strict-only (noisier) ──
	{name: "phone", tier: tierStrict, regex: regexp.MustCompile(`(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b`)},
	{name: "phone_intl", tier: tierStrict, regex: regexp.MustCompile(`\+[1-9]\d{0,3}(?:[\s.-]?\d){7,14}\b`)},
	{name: "ipv4", tier: tierStrict, regex: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)},
}

// base64Candidate finds base64-shaped substrings so a secret pasted through
// a base64 encoder can still be caught by re-running the rules above against
// the decoded text — see decodeBase64Utf8.
var base64Candidate = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)

// decodeBase64Utf8 returns the decoded string only if it round-trips back to
// the same candidate — legitimate base64 that happens to decode to garbage
// bytes must not be treated as "real" text and scanned/mangled.
func decodeBase64Utf8(candidate string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(candidate)
	if err != nil {
		return "", false
	}
	reencoded := base64.StdEncoding.EncodeToString(decoded)
	trimEq := func(s string) string {
		i := len(s)
		for i > 0 && s[i-1] == '=' {
			i--
		}
		return s[:i]
	}
	if trimEq(reencoded) != trimEq(candidate) {
		return "", false
	}
	return string(decoded), true
}

// sensitiveKeys are object keys whose value is redacted wholesale, regardless of content.
var sensitiveKeys = map[string]struct{}{
	"password": {}, "passwd": {}, "pwd": {}, "secret": {}, "token": {},
	"access_token": {}, "refresh_token": {}, "id_token": {}, "api_key": {},
	"apikey": {}, "authorization": {}, "auth": {}, "client_secret": {},
	"private_key": {}, "ssn": {}, "credit_card": {}, "card_number": {},
	"cvv": {}, "cvc": {}, "pin": {},
}

func applyRule(rule redactionRule, input string, onMatch func()) (string, int) {
	count := 0
	out := rule.regex.ReplaceAllStringFunc(input, func(m string) string {
		if rule.validate != nil && !rule.validate(m) {
			return m
		}
		count++
		if onMatch != nil {
			onMatch()
		}
		if rule.replace != nil {
			return rule.replace(m)
		}
		return tag(rule.name)
	})
	return out, count
}
