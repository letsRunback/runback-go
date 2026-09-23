package runback

// Cassette hash-chaining, ported from packages/replay/src/cassette.ts —
// closes the one remaining Phase 1 gap noted in events.go and the README.
// A Go-recorded run now gets a real cassette_digest, computed the same way
// the TS/Python SDKs and the server do, so digest equality is a real
// cross-language proof rather than a Go-only convention. See cassette_test.go
// for values pinned by running the actual TS cassette.ts, not derived from
// this port — the same discipline packages/sdk-python's test_cassette.py
// uses.
//
// Canonicalization only: this does NOT port packages/replay/src/replay.ts's
// re-execution engine (reexecuteRun) — a Go-recorded run's digest can be
// verified for tamper-evidence, but step-by-step replay/bisection of a
// Go-recorded run isn't implemented here.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// jsonString encodes a Go string exactly as JavaScript's JSON.stringify does.
//
// encoding/json cannot be used here, with or without SetEscapeHTML(false), and
// both of its differences changed the digest:
//
//	json.Marshal("a<b>&c")  -> "a\u003cb\u003e\u0026c"   JS -> "a<b>&c"
//	SetEscapeHTML(false)    -> "line\u2028sep"              JS -> "line<U+2028>sep"
//
// The first is Go's HTML-safety default; the second is unconditional, because
// U+2028/U+2029 are valid in JSON but break JavaScript source, so Go escapes
// them even when asked not to escape. Both are sensible defaults for serving
// JSON and wrong for canonicalisation, where the only correct answer is the one
// the reference implementation produces. Agent output containing "&" or a line
// separator is not exotic — it is Tuesday — so this hashed differently in Go
// than in JS for a large share of real records.
//
// Escapes exactly the set RFC 8785 mandates and nothing else: quote,
// backslash, the five short-form control escapes, and \u00XX for the remaining
// C0 controls. Every other code point is written through as-is.
//
// U+FFFD is deliberately NOT special-cased. The first draft escaped it, because
// Go's utf8.RuneError IS U+FFFD and `for range` yields it both for a genuine
// replacement character and for an undecodable byte — so a string legitimately
// containing U+FFFD came out as "\ufffd" where the reference emits it raw, and
// the fixture's non-BMP vector failed on the escape rather than the key order it
// was written to test. Ranging already substitutes U+FFFD for invalid bytes,
// which is exactly what a UTF-8 decoder feeding the reference would have
// produced, so writing the rune through covers both cases correctly.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				b.WriteString(`\u`)
				b.WriteString(strings.ToLower(strconv.FormatInt(int64(r)+0x10000, 16))[1:])
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// lessUTF16 orders two strings by UTF-16 code unit, which is what RFC 8785
// requires for object keys.
//
// sort.Strings compares UTF-8 bytes, which is Unicode CODE POINT order. That
// agrees with UTF-16 order across the BMP and disagrees above it: a non-BMP
// character encodes as a surrogate pair in 0xD800-0xDFFF, sorting BELOW
// ordinary characters in 0xE000-0xFFFF, while its code point sorts above them.
//
// Measured: {"\U0001F600": 1, "\uFFFD": 2} canonicalises with the emoji key
// first in JS and second in Go. Same object, two digests, and a Go verifier
// would call a genuine record tampered.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// canonicalJSON is RFC 8785 (JSON Canonicalization Scheme)-equivalent,
// ported from cassette.ts's canonical(). Operates on the same generic
// map[string]any/[]any tree produced by decoding JSON into `any` — the same
// shape redact.go's walk() already uses, so a redacted event can be chained
// without a further conversion step.
func canonicalJSON(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		return jsonString(val)
	case float64:
		// ECMAScript's Number::toString (what JSON.stringify uses, and what
		// RFC 8785 is defined against) serializes -0 as "0" — Go's
		// strconv/json would otherwise emit "-0" for a negative-zero float,
		// diverging from the TS/Python implementations' digest for the same
		// value. See packages/sdk-python/runback/cassette.py's identical note.
		if val == 0 && math.Signbit(val) {
			return "0"
		}
		b, _ := json.Marshal(val)
		return string(b)
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = canonicalJSON(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			// Match JSON.stringify: a property whose value is undefined is
			// omitted — Go's map[string]any has no "undefined", only absence
			// from the map, which already can't appear in `keys` to begin
			// with, so there's nothing extra to check for here (same
			// reasoning as the Python port's comment).
			parts = append(parts, jsonString(k)+":"+canonicalJSON(val[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

// chainStep is one step of the hash chain over an entry's defining content
// (not its own hash) — ported from cassette.ts's chainStep().
func chainStep(prev string, kind, key string, output any) string {
	return sha256Hex(prev + canonicalJSON(map[string]any{"kind": kind, "key": key, "output": output}))
}

// toolKey and llmKey are the content addresses for tool/model calls — ported
// from cassette.ts's toolKeyP/llmKeyP, without the optional salience
// projection (keyProjection) parameter, which isn't ported in this phase.
func toolKey(name string, input any) string {
	return sha256Hex("tool:" + name + ":" + canonicalJSON(toAny(input)))
}

func llmKey(modelID string, request any) string {
	return sha256Hex("llm:" + modelID + ":" + canonicalJSON(toAny(request)))
}

// toAny round-trips a typed value through JSON so canonicalJSON always sees
// the same map[string]any/[]any/string/float64 shape it's written against,
// regardless of whether the caller passed a Go struct or an already-generic value.
func toAny(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

// oracleEntry is the pre-hash shape of one chain entry — ported from
// cassette.ts's OracleEntry.
type oracleEntry struct {
	kind   string
	key    string
	output any
}

// oracleEntryOfEvent maps a captured event to the entry it contributes to
// the deterministic chain, or nil if it isn't a nondeterminism boundary
// (run/reasoning envelopes) — the same rule cassette.ts's oracleEntryOf
// enforces, so a digest computed here and one computed server-side from the
// same stored events are identical by construction. Env-read events aren't
// part of this SDK's event set yet, so only llm/tool are handled (matching
// what NewRun/LLM/Tool/Reasoning/Finish can actually produce).
func oracleEntryOfEvent(event any) *oracleEntry {
	switch e := event.(type) {
	case LlmEvent:
		var output any = e.Response
		if e.Error != nil {
			output = map[string]any{"error": e.Error}
		}
		return &oracleEntry{kind: "llm", key: llmKey(e.Model.ModelID, e.Request), output: toAny(output)}
	case ToolEvent:
		var output any = e.Output
		if e.Error != nil {
			output = map[string]any{"error": e.Error}
		}
		return &oracleEntry{kind: "tool", key: toolKey(e.ToolName, e.Input), output: toAny(output)}
	default:
		return nil
	}
}
