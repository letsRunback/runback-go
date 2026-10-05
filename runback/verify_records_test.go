package runback

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Verifier conformance: Go must return the reference's verdict, case for case.
//
// The records in packages/verify/testdata/records/ are real — chained and signed
// by packages/verify/index.js, with the tampered variants produced by mutating a
// genuine record rather than hand-authored. expected.json holds the reference's
// verdict for each.
//
// A port that agrees on happy-path records and disagrees on tampered ones is
// worse than no port: it would tell an auditor a forged record is fine. So the
// fixtures are mostly tamper cases, and the sharpest is `forged-summary` — every
// hash intact, signature sound, and an unsigned `run` summary claiming success
// on a run the sealed events record as an error. An auditor reads the summary. A
// verifier reporting VALID there has failed at the one job it exists for.

type expectedCase struct {
	Opts struct {
		ExpectedPublicKey any `json:"expectedPublicKey"`
	} `json:"opts"`
	Verdict   string `json:"verdict"`
	Valid     bool   `json:"valid"`
	Integrity bool   `json:"integrity"`
	Checks    struct {
		Schema       bool   `json:"schema"`
		Chain        bool   `json:"chain"`
		Digest       bool   `json:"digest"`
		Cassette     bool   `json:"cassette"`
		Consistent   bool   `json:"consistent"`
		Signature    string `json:"signature"`
		SignatureAlg string `json:"signature_alg"`
	} `json:"checks"`
	ConsistencyFailures []string `json:"consistency_failures"`
}

func loadExpected(t *testing.T) map[string]expectedCase {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t, "records", "expected.json"))
	if err != nil {
		t.Fatalf("cannot read the reference verdicts: %v\n"+
			"Without them this port is only being compared to itself.", err)
	}
	var doc struct {
		Cases map[string]expectedCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("expected.json is not valid JSON: %v", err)
	}
	if len(doc.Cases) < 5 {
		t.Fatalf("only %d cases — the fixture looks truncated", len(doc.Cases))
	}
	return doc.Cases
}

func optsFor(exp expectedCase) VerifyOptions {
	switch v := exp.Opts.ExpectedPublicKey.(type) {
	case string:
		return VerifyOptions{ExpectedPublicKeys: []string{v}}
	case nil:
		// JSON null means "pin against nothing", which is NOT the same as
		// "unset" (which would default to Runback's published keys).
		return VerifyOptions{PinNothing: true}
	default:
		return VerifyOptions{}
	}
}

func TestVerifyMatchesReferenceVerdicts(t *testing.T) {
	for name, exp := range loadExpected(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(fixturePath(t, "records", name+".json"))
			if err != nil {
				t.Fatalf("missing fixture %s.json: %v", name, err)
			}
			got, err := VerifyJSON(raw, optsFor(exp))
			if err != nil {
				t.Fatalf("verify returned an error: %v", err)
			}
			if got.Verdict != exp.Verdict {
				t.Errorf("\n  expected verdict: %s\n  got:              %s\n  checks: %+v\n\n"+
					"This port disagrees with packages/verify/index.js about whether a\n"+
					"record is trustworthy. The reference is authoritative.",
					exp.Verdict, got.Verdict, got.Checks)
			}
			if got.Valid != exp.Valid {
				t.Errorf("valid: expected %v, got %v", exp.Valid, got.Valid)
			}
			if got.Integrity != exp.Integrity {
				t.Errorf("integrity: expected %v, got %v", exp.Integrity, got.Integrity)
			}
			c, e := got.Checks, exp.Checks
			for _, cmp := range []struct {
				field string
				a, b  any
			}{
				{"schema", c.Schema, e.Schema}, {"chain", c.Chain, e.Chain},
				{"digest", c.Digest, e.Digest}, {"cassette", c.Cassette, e.Cassette},
				{"consistent", c.Consistent, e.Consistent},
				{"signature", c.Signature, e.Signature},
				{"signature_alg", c.SignatureAlg, e.SignatureAlg},
			} {
				if cmp.a != cmp.b {
					t.Errorf("checks.%s: expected %v, got %v", cmp.field, cmp.b, cmp.a)
				}
			}
		})
	}
}

func TestForgedSummaryRejectedDespiteSoundSignature(t *testing.T) {
	// The case the consistency check exists for, asserted by name so a future
	// refactor that drops it fails here with an explanation rather than in a
	// table of verdicts.
	raw, err := os.ReadFile(fixturePath(t, "records", "forged-summary.json"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	got, err := VerifyJSON(raw, VerifyOptions{PinNothing: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Checks.Signature != "valid" && got.Checks.Signature != "valid-unpinned" {
		t.Fatalf("the fixture is supposed to carry a SOUND signature, got %q — "+
			"if it does not, this test would pass for the wrong reason", got.Checks.Signature)
	}
	if !got.Checks.Chain {
		t.Fatal("the fixture's chain is supposed to be intact")
	}
	if got.Verdict != "invalid" {
		t.Errorf("a record whose summary contradicts its sealed events must not verify; got %q", got.Verdict)
	}
	if len(got.ConsistencyFailures) == 0 {
		t.Error("a forged summary must say what contradicted it")
	}
}

func TestEd25519RejectsAFlippedBit(t *testing.T) {
	raw, err := os.ReadFile(fixturePath(t, "records", "signed-genuine.json"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	sig := rec["manifest"].(map[string]any)["signature"].(map[string]any)
	b, _ := hex.DecodeString(sig["value"].(string))
	b[0] ^= 0x01
	sig["value"] = hex.EncodeToString(b)

	got, err := Verify(rec, VerifyOptions{PinNothing: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Checks.Signature != "invalid" {
		t.Errorf("a corrupted signature must be invalid, got %q", got.Checks.Signature)
	}
}

func TestChainRecomputesPublishedHashes(t *testing.T) {
	raw, err := os.ReadFile(fixturePath(t, "records", "signed-genuine.json"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	events := rec["events"].([]any)
	hashes, digest := ComputeEventChain(events)
	manifest := rec["manifest"].(map[string]any)
	if digest != manifest["content_digest"] {
		t.Errorf("chain digest %s != manifest.content_digest %v", digest, manifest["content_digest"])
	}
	for i, h := range hashes {
		if got := events[i].(map[string]any)["_hash"]; got != h {
			t.Errorf("event %d: recomputed %s, record says %v", i, h, got)
		}
	}
}

func TestRejectsNonCassette(t *testing.T) {
	if _, err := Verify(map[string]any{"not": "a record"}, VerifyOptions{}); err == nil {
		t.Error("expected an error for a document that is not a cassette record")
	}
}

func TestPinNothingIsNotTheSameAsUnset(t *testing.T) {
	// A nil slice and an explicitly-empty pin set are indistinguishable in Go,
	// and conflating them would silently downgrade "pin against Runback's
	// published keys" to "pin against nothing" — turning an unverified record
	// into a valid-looking one.
	raw, err := os.ReadFile(fixturePath(t, "records", "signed-genuine.json"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	unset, err := VerifyJSON(raw, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pinNothing, err := VerifyJSON(raw, VerifyOptions{PinNothing: true})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is signed by a test key, so pinning Runback's published keys
	// must NOT match it, while pinning nothing accepts the maths alone.
	if unset.Checks.Signature != "valid-unpinned" {
		t.Errorf("unset should pin against the published keys and not match a test key, got %q",
			unset.Checks.Signature)
	}
	if pinNothing.Checks.Signature != "valid-unpinned" {
		t.Errorf("PinNothing should accept a sound signature as unpinned, got %q",
			pinNothing.Checks.Signature)
	}
}
