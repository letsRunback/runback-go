package runback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"
)

// Canonicalisation conformance: Go must agree with the reference, byte for byte.
//
// The fixture at packages/verify/testdata/jcs-vectors.json is generated from
// packages/verify/index.js, which defines runback.cassette/v1. A record is only
// verifiable "without us" if every implementation computes the same digest for
// it, so this is the property the format is sold on rather than a nicety.
//
// It exists because the property was already broken and nothing noticed.
// cassette_test.go pins its expected values by running the real TS
// implementation — the right instinct — but it pins them for ORDINARY data, and
// ordinary data agreed all along. The divergences lived in values nobody thought
// to test:
//
//	"a<b>&c"                encoding/json -> "a<b>&c"
//	"x y"              escaped even under SetEscapeHTML(false)
//	{"\U0001F600":1,"�":2}  ordered by UTF-8 byte here, by UTF-16 code
//	                             unit in the reference — opposite key order
//
// Each yields a different digest for the same record, so this SDK would have
// reported a genuine Runback record as tampered. The first one is not an exotic
// input: agent output containing "&" is routine.

type jcsVector struct {
	Name      string `json:"name"`
	Value     any    `json:"value"`
	Canonical string `json:"canonical"`
}

func loadVectors(t *testing.T) []jcsVector {
	t.Helper()
	path := fixturePath(t, "jcs-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the shared fixture at %s: %v\n"+
			"This test is meaningless without it — it is the only thing tying this\n"+
			"port to the reference implementation.", path, err)
	}
	var doc struct {
		Vectors []jcsVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	if len(doc.Vectors) < 15 {
		t.Fatalf("fixture looks truncated: %d vectors", len(doc.Vectors))
	}
	return doc.Vectors
}

func TestCanonicalMatchesReference(t *testing.T) {
	for _, vec := range loadVectors(t) {
		t.Run(vec.Name, func(t *testing.T) {
			got := canonicalJSON(vec.Value)
			if got != vec.Canonical {
				t.Errorf("\n  expected: %s\n  got:      %s\n\n"+
					"This SDK and packages/verify/index.js now disagree about the bytes\n"+
					"that get hashed. Every digest either side computes for a record\n"+
					"containing this shape will differ, so one will call a genuine record\n"+
					"TAMPERED. The reference is authoritative: fix this port, not the\n"+
					"fixture.", vec.Canonical, got)
			}
		})
	}
}

func TestChainDigestMatchesReference(t *testing.T) {
	// The chain, not just the string — this is what a verifier actually compares.
	// h_i = SHA-256(h_{i-1} + canonical(event_i)); for one event that is
	// SHA-256(canonical(event)). Asserting it catches a future change that keeps
	// canonicalJSON correct but breaks the chaining around it.
	for _, vec := range loadVectors(t) {
		want := sha256.Sum256([]byte(vec.Canonical))
		got := sha256.Sum256([]byte(canonicalJSON(vec.Value)))
		if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
			t.Errorf("chain digest differs for %q", vec.Name)
		}
	}
}

// ── Values JSON cannot carry, so the fixture cannot either ───────────────────
// JSON has no negative zero (it round-trips to +0), no NaN and no Infinity, and
// those are exactly where a language's float formatter is most likely to differ.

func TestNegativeZeroIsZero(t *testing.T) {
	if got := canonicalJSON(map[string]any{"a": math.Copysign(0, -1)}); got != `{"a":0}` {
		t.Errorf(`negative zero: expected {"a":0}, got %s`, got)
	}
}

func TestHTMLCharactersAreNotEscaped(t *testing.T) {
	// encoding/json escapes <, > and & by default. Canonical output must not.
	got := canonicalJSON(map[string]any{"a": "<b>&</b>"})
	if got != `{"a":"<b>&</b>"}` {
		t.Errorf("HTML escaping leaked into canonical output: %s", got)
	}
}

func TestLineSeparatorsAreNotEscaped(t *testing.T) {
	// U+2028/U+2029 are escaped by encoding/json even with SetEscapeHTML(false),
	// because they break JavaScript source. JSON.stringify leaves them raw.
	got := canonicalJSON(map[string]any{"a": "x y z"})
	if got != "{\"a\":\"x y z\"}" {
		t.Errorf("line/paragraph separator was escaped: %q", got)
	}
}

func TestNonBMPKeysSortByUTF16CodeUnit(t *testing.T) {
	// U+1F600 encodes as surrogates D83D DE00, which sort BELOW U+FFFD in
	// UTF-16 — and ABOVE it by code point, which is what sort.Strings gives.
	got := canonicalJSON(map[string]any{"\U0001F600": float64(1), "�": float64(2)})
	want := "{\"\U0001F600\":1,\"�\":2}"
	if got != want {
		t.Errorf("key order:\n  expected %s\n  got      %s", want, got)
	}
}

func TestExponentFormatting(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want string
	}{
		{1e-7, `{"a":1e-7}`},
		{1e16, `{"a":10000000000000000}`},
		{1e21, `{"a":1e+21}`},
		{1e-6, `{"a":0.000001}`},
	} {
		if got := canonicalJSON(map[string]any{"a": c.in}); got != c.want {
			t.Errorf("%g: expected %s, got %s", c.in, c.want, got)
		}
	}
}
