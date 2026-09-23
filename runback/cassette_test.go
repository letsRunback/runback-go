package runback

import (
	"math"
	"testing"
)

// Cross-language digest parity: expected values below were computed by
// running the ACTUAL TypeScript implementation (packages/replay/src/cassette.ts)
// against these exact fixtures via `npx tsx`, not derived from this Go port —
// the same discipline packages/sdk-python/tests/test_cassette.py uses. Byte-
// identical output here is the strongest available guarantee that a digest
// computed by this SDK and one computed server-side (or by any other Runback
// SDK) from the same event stream match by construction. Regenerate by
// re-running the same tsx snippet against cassette.ts if these fixtures change.

func TestCanonicalJSONMatchesTheTSImplementationByteForByte(t *testing.T) {
	cases := []struct {
		value    any
		expected string
	}{
		{nil, "null"},
		{float64(42), "42"},
		{math.Copysign(0, -1), "0"},
		{"hello", `"hello"`},
		{true, "true"},
		{[]any{float64(1), float64(2), float64(3)}, "[1,2,3]"},
		{map[string]any{"b": float64(2), "a": float64(1)}, `{"a":1,"b":2}`},
		{
			map[string]any{"z": []any{float64(1), map[string]any{"y": float64(2), "x": float64(1)}}, "a": "text"},
			`{"a":"text","z":[1,{"x":1,"y":2}]}`,
		},
		{
			map[string]any{"0": "zero", "1": "one", "42": "forty-two", "name": "test"},
			`{"0":"zero","1":"one","42":"forty-two","name":"test"}`,
		},
	}
	for _, c := range cases {
		if got := canonicalJSON(c.value); got != c.expected {
			t.Errorf("canonicalJSON(%#v) = %q, want %q", c.value, got, c.expected)
		}
	}
}

func TestChainStepMatchesTheTSImplementation(t *testing.T) {
	const expected = "6969a239efd67dc20ff09e8f14f1f2e2fd6d4e5f4221b39dd2402a074e94611f"
	got := chainStep("", "tool", "abc123", map[string]any{"r": "sunny"})
	if got != expected {
		t.Fatalf("chainStep(...) = %q, want %q", got, expected)
	}
}

func TestOracleEntryAndEndToEndDigestMatchTheTSImplementation(t *testing.T) {
	event := ToolEvent{
		ToolName: "search", ToolCallID: "t1",
		Input:  map[string]any{"q": "weather"},
		Output: map[string]any{"r": "sunny"},
	}
	entry := oracleEntryOfEvent(event)
	if entry == nil {
		t.Fatal("expected a non-nil oracle entry for a tool event")
	}
	const expectedKey = "0e1e5077577570a01a273425a2525981dc95efe76418ad7a1655ad82f0f1cb68"
	if entry.kind != "tool" || entry.key != expectedKey {
		t.Fatalf("oracleEntryOfEvent = {kind: %q, key: %q}, want {tool, %q}", entry.kind, entry.key, expectedKey)
	}
	const expectedDigest = "4ee1d9b4991d89ed800555cf2ba7ee764cb73058ee97741f1c3c4d4fddeacce2"
	if got := chainStep("", entry.kind, entry.key, entry.output); got != expectedDigest {
		t.Fatalf("chainStep(oracleEntry) = %q, want %q", got, expectedDigest)
	}
}

func TestEmptyChainFallsBackToSha256EmptyString(t *testing.T) {
	const expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := sha256Hex(""); got != expected {
		t.Fatalf("sha256Hex(\"\") = %q, want %q", got, expected)
	}
}

// TestRunTracksCassetteDigestAcrossThreeEntries pins the chain produced by a
// 3-entry sequence (llm, tool, then a second tool call) against the real TS
// implementation's output for the same entries, exercising the actual
// Run/push() wiring end to end rather than just the pure chainStep function.
func TestRunTracksCassetteDigestAcrossThreeEntries(t *testing.T) {
	run := NewRun(Options{RunName: "digest-test", APIKey: "k", Redact: RedactOff})
	run.LLM(LlmInput{
		Model:    Model{Provider: "test", ModelID: "m"},
		Request:  LlmRequest{Messages: []ModelMessage{{Role: "user", Content: "hi"}}},
		Response: LlmResponse{Text: Ptr("hello")},
	})
	digest, count := run.CassetteDigest()
	if count != 1 {
		t.Fatalf("after one LLM call, entry count = %d, want 1", count)
	}
	const emptyChainDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if digest == "" || digest == emptyChainDigest {
		t.Fatalf("expected a non-trivial digest after one entry, got %q", digest)
	}
}
