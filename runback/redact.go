package runback

import (
	"encoding/json"
	"strings"
)

// RedactionMode selects the built-in redaction tier, ported from
// packages/redact/src/redact.ts's `preset` option. Empty string (the zero
// value) means "standard" — redaction is ON by default, matching the TS/
// Python SDKs, not an opt-in a caller has to remember to enable.
type RedactionMode string

const (
	RedactStandard RedactionMode = "standard"
	RedactStrict   RedactionMode = "strict"
	RedactOff      RedactionMode = "off"
)

const (
	defaultMaxDepth        = 24
	defaultMaxStringLength = 50_000
)

// redactor walks arbitrary captured values (map[string]any / []any / string /
// ...) and redacts secrets/PII before an event is buffered for send. Only the
// built-in tiers are ported in this phase — no customPatterns/redactKeys/
// allowKeys/custom-callback escape hatches yet (see events.go's package
// comment on what Phase 1 covers).
type redactor struct {
	rules           []redactionRule
	maxDepth        int
	maxStringLength int
	lifetime        int
	byType          map[string]int
	fieldsTruncated int
}

func newRedactor(mode RedactionMode) *redactor {
	if mode == RedactOff {
		return nil
	}
	tier := tierStandard
	if mode == RedactStrict {
		tier = tierStrict
	}
	var rules []redactionRule
	for _, r := range redactRules {
		if tier == tierStrict || r.tier == tierStandard {
			rules = append(rules, r)
		}
	}
	return &redactor{rules: rules, maxDepth: defaultMaxDepth, maxStringLength: defaultMaxStringLength, byType: map[string]int{}}
}

// total, truncatedFields, and typeCounts mirror the TS/Python redactor's own
// accessors — surfaced in the run-end event's metadata (see collector.go's
// Finish) so a customer can check what was scrubbed instead of taking it on faith.
func (r *redactor) total() int               { return r.lifetime }
func (r *redactor) truncatedFieldCount() int { return r.fieldsTruncated }
func (r *redactor) typeCounts() map[string]int {
	out := make(map[string]int, len(r.byType))
	for k, v := range r.byType {
		out[k] = v
	}
	return out
}

// capLength is a size guard independent of redaction — applied BEFORE
// redaction's own regex passes so one huge field can't also make redaction
// itself slow (a long base64-alphabet run makes the base64-candidate scan
// pathologically slow otherwise). See redact.ts's own comment for the
// measured cost this avoids.
func (r *redactor) capLength(s string) string {
	if len(s) <= r.maxStringLength {
		return s
	}
	r.fieldsTruncated++
	overBy := len(s) - r.maxStringLength
	return s[:r.maxStringLength] + "…[truncated: " + itoa(overBy) + " more chars]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func (r *redactor) redactString(s string) string {
	out := r.capLength(s)
	for _, rule := range r.rules {
		name := rule.name
		next, count := applyRule(rule, out, func() { r.byType[name]++ })
		out = next
		r.lifetime += count
	}
	return r.redactBase64Secrets(out)
}

// redactBase64Secrets finds base64-shaped substrings, decodes each, and
// re-checks the decoded text against every active rule — a real hit redacts
// the original encoded substring wholesale. Legitimate base64 (an image
// blob, a content hash) decodes to bytes that don't match anything and is
// left untouched.
func (r *redactor) redactBase64Secrets(s string) string {
	return base64Candidate.ReplaceAllStringFunc(s, func(candidate string) string {
		decoded, ok := decodeBase64Utf8(candidate)
		if !ok {
			return candidate
		}
		for _, rule := range r.rules {
			if _, count := applyRule(rule, decoded, nil); count > 0 {
				r.lifetime++
				r.byType["base64:"+rule.name]++
				return "[redacted:base64]"
			}
		}
		return candidate
	})
}

// walk mirrors redact.ts's walk(): key-based whole-value redaction first,
// then recurse into maps/slices, redacting every string leaf. depth guards
// against runaway/cyclic structures — Go's encoding/json never produces
// cycles when decoding into `any`, so this is a simpler bound than the TS
// WeakSet-based cycle guard, sufficient for JSON-shaped trace data.
func (r *redactor) walk(value any, key string, depth int) any {
	if key != "" {
		if _, sensitive := sensitiveKeys[strings.ToLower(key)]; sensitive && value != nil {
			r.lifetime++
			r.byType["key:"+key]++
			return "[redacted:key:" + key + "]"
		}
	}
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		return r.redactString(v)
	case float64, int, bool:
		return v
	}
	if depth >= r.maxDepth {
		return value
	}
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = r.walk(item, "", depth+1)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = r.walk(item, k, depth+1)
		}
		return out
	}
	return value
}

// redactValue redacts an arbitrary already-JSON-decoded value (map[string]any,
// []any, string, or a scalar) in place structurally, returning the redacted copy.
func (r *redactor) redactValue(value any) any {
	return r.walk(value, "", 0)
}

// redactInto redacts a typed value (a string, a struct, a slice of structs —
// anything JSON-marshalable) by round-tripping it through a generic
// map[string]any/[]any tree, walking that tree, then decoding the result
// back into T. This lets one generic walk() cover every typed sub-structure
// in events.go (ModelMessage, ToolDefinition, ToolCall, TraceError, ...)
// without a hand-written redaction case for each — the tradeoff is a JSON
// round-trip per field rather than in-place mutation, acceptable at Phase 1's
// scale. key mirrors the TS SDK's redactEvent call sites, which pass the
// field name so a key like "authorization" can still trigger whole-value
// redaction even for a field that isn't nested inside an object.
func redactInto[T any](r *redactor, v T, key string) T {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return v
	}
	redacted := r.walk(generic, key, 0)
	rb, err := json.Marshal(redacted)
	if err != nil {
		return v
	}
	var out T
	if err := json.Unmarshal(rb, &out); err != nil {
		return v
	}
	return out
}

// redactEvent redacts the content-bearing fields of a captured event —
// envelope/metrics fields (schema_version, run_id, span_id, seq, timestamps,
// model id, latency, tool name/call id, status) are left untouched, matching
// packages/redact/src/redact.ts's redactEvent switch. A type with no case
// below is returned as-is, never silently dropped.
func redactEvent(r *redactor, event any) any {
	switch e := event.(type) {
	case LlmEvent:
		if e.Request.System != nil {
			s := redactInto(r, *e.Request.System, "system")
			e.Request.System = &s
		}
		e.Request.Messages = redactInto(r, e.Request.Messages, "messages")
		e.Request.Tools = redactInto(r, e.Request.Tools, "tools")
		if e.Response.Text != nil {
			s := redactInto(r, *e.Response.Text, "text")
			e.Response.Text = &s
		}
		if e.Response.Reasoning != nil {
			s := redactInto(r, *e.Response.Reasoning, "reasoning")
			e.Response.Reasoning = &s
		}
		e.Response.ToolCalls = redactInto(r, e.Response.ToolCalls, "tool_calls")
		if e.Error != nil {
			er := redactInto(r, *e.Error, "error")
			e.Error = &er
		}
		return e
	case ToolEvent:
		if e.Input != nil {
			e.Input = redactInto(r, e.Input, "input")
		}
		if e.Output != nil {
			e.Output = redactInto(r, e.Output, "output")
		}
		if e.Error != nil {
			er := redactInto(r, *e.Error, "error")
			e.Error = &er
		}
		return e
	case ReasoningEvent:
		e.Text = redactInto(r, e.Text, "text")
		return e
	case RunEvent:
		if e.Input != nil {
			e.Input = redactInto(r, e.Input, "input")
		}
		if e.Output != nil {
			e.Output = redactInto(r, e.Output, "output")
		}
		if e.Metadata != nil {
			e.Metadata = redactInto(r, e.Metadata, "metadata")
		}
		if e.Error != nil {
			er := redactInto(r, *e.Error, "error")
			e.Error = &er
		}
		return e
	default:
		return event
	}
}
