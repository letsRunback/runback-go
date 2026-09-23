package runback

// Verify a runback.cassette/v1 audit record — offline, with nothing installed.
//
//	res, err := runback.VerifyJSON(raw, runback.VerifyOptions{})
//	fmt.Println(res.Verdict)   // "valid" | "unverified" | "invalid"
//
// A faithful port of packages/verify/index.js, which is the reference
// implementation and the definition of the format. Where the two ever disagree,
// the reference is right and this is wrong — packages/verify/testdata/records/
// holds real signed records and the reference's verdict for each, and
// verify_records_test.go holds this port to them.
//
// Everything here is standard library. That is deliberate rather than
// incidental: the claim the format makes is "you can check our evidence without
// us", and an auditor who must first vendor a dependency into a locked-down
// build is an auditor who cannot check it where the question was asked.
// crypto/ed25519 and encoding/pem cover it.
//
// WHAT "VALID" MEANS, AND WHAT IT DOES NOT
//
// The chain algorithm is public. Anyone can author a self-consistent record from
// nothing, or edit a real one and re-chain it; every integrity check then
// passes. Integrity proves only internal coherence.
//
// Provenance is a separate question, answered only by a signature verifying
// against a key pinned OUT OF BAND. Hence three outcomes, not two:
//
//	valid        integrity holds AND the signer is a key you pinned
//	unverified   self-consistent, but the origin is unproven
//	invalid      something failed — not the record it claims to be
//
// "valid-unpinned" is deliberately not "valid": the maths holds, but the signer
// is whoever generated the keypair travelling inside the record, which an
// attacker controls.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

// KnownSchemas are the record schemas this verifier understands. A file that
// declares something else — or nothing — has not claimed to follow the rules it
// is about to be judged by, and is reported as failing rather than assumed.
var KnownSchemas = map[string]bool{
	"runback.audit/v2":    true,
	"runback.cassette/v1": true,
}

// RunbackAuditPubkeysPEM mirrors packages/verify/index.js. A list, so a
// rotated-out key stays accepted for the lifetime of records it signed.
var RunbackAuditPubkeysPEM = []string{
	"-----BEGIN PUBLIC KEY-----\n" +
		"MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n" +
		"-----END PUBLIC KEY-----\n",
}

// RunbackAuditRevokedPubkeysPEM are keys whose signatures must be rejected
// outright, however sound the maths.
var RunbackAuditRevokedPubkeysPEM []string

// VerifyOptions controls signer pinning.
type VerifyOptions struct {
	// ExpectedPublicKeys pins the Ed25519 signer. Nil means "use Runback's
	// published keys"; an explicitly empty non-nil slice means "pin against
	// nothing", which yields valid-unpinned for a sound signature.
	ExpectedPublicKeys []string
	// PinNothing distinguishes an explicitly empty pin set from an unset one,
	// since a nil and an empty slice are otherwise indistinguishable in Go.
	PinNothing bool
	// RevokedPublicKeys overrides RunbackAuditRevokedPubkeysPEM, so a
	// compromise can be reacted to without waiting for a release.
	RevokedPublicKeys []string
	// SigningKey is the shared secret for legacy HMAC-SHA256 records. Without
	// it such a record reports "no-key" — by construction, not by omission.
	SigningKey string
}

// VerifyChecks is the per-check breakdown behind a verdict.
type VerifyChecks struct {
	Schema       bool   `json:"schema"`
	Chain        bool   `json:"chain"`
	Digest       bool   `json:"digest"`
	Cassette     bool   `json:"cassette"`
	Consistent   bool   `json:"consistent"`
	Signature    string `json:"signature"`
	SignatureAlg string `json:"signature_alg,omitempty"`
}

// VerifyMeta describes the record, using values the signature actually covers.
type VerifyMeta struct {
	Schema      string `json:"schema"`
	RunID       string `json:"run_id"`
	EventCount  int    `json:"event_count"`
	GeneratedAt string `json:"generated_at,omitempty"`
	SpecURL     string `json:"spec_url"`
}

// VerifyResult is the verdict and its evidence.
type VerifyResult struct {
	Valid               bool         `json:"valid"`
	Verdict             string       `json:"verdict"`
	Integrity           bool         `json:"integrity"`
	Checks              VerifyChecks `json:"checks"`
	ConsistencyFailures []string     `json:"consistency_failures"`
	Meta                VerifyMeta   `json:"meta"`
}

// ComputeEventChain recomputes the SHA-256 event chain.
//
//	h_0 = ""
//	h_i = SHA-256( h_{i-1} + canonical(event_i without _hash) )
func ComputeEventChain(events []any) (hashes []string, digest string) {
	prev := ""
	for _, e := range events {
		body := map[string]any{}
		if m, ok := e.(map[string]any); ok {
			for k, v := range m {
				if k == "_hash" {
					continue
				}
				body[k] = v
			}
		}
		h := sha256Hex(prev + canonicalJSON(body))
		hashes = append(hashes, h)
		prev = h
	}
	if prev == "" {
		return hashes, sha256Hex("")
	}
	return hashes, prev
}

// ComputeCassetteDigest recomputes the oracle-stream digest: the ordered
// sequence of every nondeterministic value the agent received.
func ComputeCassetteDigest(events []any) (digest string, entryCount int) {
	ordered := make([]any, len(events))
	copy(ordered, events)
	seqOf := func(v any) float64 {
		if m, ok := v.(map[string]any); ok {
			if s, ok := m["seq"].(float64); ok {
				return s
			}
		}
		return 0
	}
	sort.SliceStable(ordered, func(i, j int) bool { return seqOf(ordered[i]) < seqOf(ordered[j]) })

	prev := ""
	for _, e := range ordered {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		entry := oracleEntryOfMap(m)
		if entry == nil {
			continue
		}
		prev = chainStep(prev, entry.kind, entry.key, entry.output)
		entryCount++
	}
	if prev == "" {
		return sha256Hex(""), entryCount
	}
	return prev, entryCount
}

// projectInput applies an event's key_projection before the oracle key is
// hashed, mirroring projectInput() in packages/verify/index.js.
//
// cassette.go's recording path does not implement projections — its comment
// says so — which is fine for runs this SDK records, since it never sets one.
// It is NOT fine for verification: a record produced by the TS or Python SDK
// with a projection would have its oracle keys computed differently here, the
// cassette digest would not match, and a genuine record would be reported as
// tampered.
//
// `keep` is applied at the top level only (by first path segment), `drop` walks
// the full dotted path — exactly as the reference does.
func projectInput(input any, projection any) any {
	proj, _ := projection.(map[string]any)
	if proj == nil {
		return input
	}
	keep, _ := proj["keep"].([]any)
	drop, _ := proj["drop"].([]any)
	if len(keep) == 0 && len(drop) == 0 {
		return input
	}
	obj, ok := input.(map[string]any)
	if !ok {
		return input
	}

	// Deep copy, so projecting never mutates the caller's event.
	work := map[string]any{}
	raw, err := json.Marshal(obj)
	if err != nil || json.Unmarshal(raw, &work) != nil {
		return input
	}

	if len(keep) > 0 {
		keepTop := map[string]bool{}
		for _, k := range keep {
			if ks, ok := k.(string); ok {
				keepTop[strings.SplitN(ks, ".", 2)[0]] = true
			}
		}
		for k := range work {
			if !keepTop[k] {
				delete(work, k)
			}
		}
	}
	for _, d := range drop {
		if ds, ok := d.(string); ok {
			dropPath(work, strings.Split(ds, "."))
		}
	}
	return work
}

func dropPath(node any, segs []string) {
	if len(segs) == 0 || node == nil {
		return
	}
	if arr, ok := node.([]any); ok {
		for _, el := range arr {
			dropPath(el, segs)
		}
		return
	}
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if len(segs) == 1 {
		delete(m, segs[0])
		return
	}
	if child, present := m[segs[0]]; present {
		dropPath(child, segs[1:])
	}
}

// oracleEntryOfMap is oracleEntryOfEvent for a record DECODED FROM JSON.
//
// cassette.go's version switches on this SDK's own typed event structs, because
// it serves the recording path. A verifier reads someone else's file, so every
// event arrives as map[string]any and falls straight through that switch to
// nil — which produced an empty oracle stream, a cassette digest of sha256(""),
// and "cassette: false" on every genuine record. Same rule, different input
// shape; the rule itself is mirrored from packages/verify/index.js.
func oracleEntryOfMap(e map[string]any) *oracleEntry {
	str := func(k string) string { v, _ := e[k].(string); return v }
	switch e["type"] {
	case "llm":
		modelID := ""
		if m, ok := e["model"].(map[string]any); ok {
			modelID, _ = m["model_id"].(string)
		}
		key := sha256Hex("llm:" + modelID + ":" + canonicalJSON(projectInput(e["request"], e["key_projection"])))
		var output any = e["response"]
		if err, present := e["error"]; present && err != nil {
			output = map[string]any{"error": err}
		}
		return &oracleEntry{kind: "llm", key: key, output: output}
	case "tool":
		key := sha256Hex("tool:" + str("tool_name") + ":" + canonicalJSON(projectInput(e["input"], e["key_projection"])))
		var output any = e["output"]
		if err, present := e["error"]; present && err != nil {
			output = map[string]any{"error": err}
		}
		return &oracleEntry{kind: "tool", key: key, output: output}
	case "env":
		return &oracleEntry{kind: str("kind"), key: str("key"), output: e["output"]}
	}
	return nil
}

// spkiEd25519 extracts the raw 32-byte key from an SPKI PEM.
//
// An Ed25519 SPKI DER is a fixed 44 bytes whose last 32 are the key, so the
// prefix is matched rather than parsed: a full ASN.1 parser here would be more
// code and more attack surface for one fixed shape. Comparing the extracted key
// rather than the PEM text also makes the verdict immune to whitespace and line
// wrapping, which differ between exporters.
func spkiEd25519(pemText string) ed25519.PublicKey {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || len(block.Bytes) != 44 {
		return nil
	}
	prefix, _ := hex.DecodeString("302a300506032b6570032100")
	if !bytes.Equal(block.Bytes[:12], prefix) {
		return nil
	}
	return ed25519.PublicKey(block.Bytes[12:])
}

// checkConsistency binds the record's unsigned summary to its signed events.
//
// The signed material is the event chain plus the cassette digest. It does NOT
// cover manifest.run_id or the top-level `run` summary — so on a genuinely
// signed record those can be rewritten and every hash still verifies. The
// reference implementation demonstrated it: a real signed record with run.status
// flipped from error to completed, and a fabricated approval, passed.
//
// An auditor reads the summary, not the raw event stream, so a record that
// misrepresents its own outcome is not valid however intact its chain.
func checkConsistency(record map[string]any) (ok bool, reasons []string) {
	events, _ := record["events"].([]any)
	manifest, _ := record["manifest"].(map[string]any)

	runIDs := map[string]bool{}
	for _, e := range events {
		if m, ok := e.(map[string]any); ok {
			if id, ok := m["run_id"].(string); ok && id != "" {
				runIDs[id] = true
			}
		}
	}
	if manifest != nil {
		if mid, ok := manifest["run_id"].(string); ok && mid != "" && len(runIDs) > 0 && !runIDs[mid] {
			reasons = append(reasons, fmt.Sprintf(
				"manifest.run_id (%s) is not the run_id in the signed events", mid))
		}
	}

	var end map[string]any
	for _, e := range events {
		if m, ok := e.(map[string]any); ok && m["type"] == "run" && m["phase"] == "end" {
			end = m
			break
		}
	}
	if run, ok := record["run"].(map[string]any); ok && end != nil {
		if v, present := run["status"]; present && !jsonEqual(v, end["status"]) {
			reasons = append(reasons, fmt.Sprintf(
				"run.status (%v) contradicts the sealed run-end event (%v)", v, end["status"]))
		}
		if v, present := run["output"]; present && !jsonEqual(v, end["output"]) {
			reasons = append(reasons, "run.output does not match the sealed run-end event")
		}
		if v, present := run["error"]; present && !jsonEqual(v, end["error"]) {
			reasons = append(reasons, "run.error does not match the sealed run-end event")
		}
	}
	return len(reasons) == 0, reasons
}

// jsonEqual is key-order-independent deep equality for decoded JSON.
func jsonEqual(a, b any) bool {
	return canonicalJSON(a) == canonicalJSON(b)
}

// Verify checks a decoded cassette record. Mirrors packages/verify/index.js.
func Verify(record map[string]any, opts VerifyOptions) (*VerifyResult, error) {
	manifest, hasManifest := record["manifest"].(map[string]any)
	events, hasEvents := record["events"].([]any)
	if !hasManifest || !hasEvents {
		return nil, fmt.Errorf("not a runback.cassette record — missing manifest or events array")
	}

	hashes, chainDigest := ComputeEventChain(events)
	cassetteDigest, _ := ComputeCassetteDigest(events)

	chainOK := true
	for i, h := range hashes {
		m, _ := events[i].(map[string]any)
		if m == nil || m["_hash"] != h {
			chainOK = false
			break
		}
	}
	digestOK := manifest["content_digest"] == chainDigest
	replay, _ := manifest["replay"].(map[string]any)
	cassetteOK := replay != nil && replay["cassette_digest"] == cassetteDigest
	schemaStr, _ := record["$schema"].(string)
	schemaOK := KnownSchemas[schemaStr]

	signature := "unsigned"
	signatureAlg := ""
	if sig, ok := manifest["signature"].(map[string]any); ok {
		if value, ok := sig["value"].(string); ok && value != "" {
			// Must match web/lib/audit.ts exactly: the signature covers both the
			// event chain and the replay digest, so a record cannot be
			// re-pointed at a different cassette without breaking it.
			cd, _ := manifest["content_digest"].(string)
			rd := ""
			if replay != nil {
				rd, _ = replay["cassette_digest"].(string)
			}
			payload := []byte(cd + ":" + rd)

			switch sig["alg"] {
			case "Ed25519":
				signatureAlg = "Ed25519"
				pinned := opts.ExpectedPublicKeys
				if pinned == nil && !opts.PinNothing {
					pinned = RunbackAuditPubkeysPEM
				}
				revoked := opts.RevokedPublicKeys
				if revoked == nil {
					revoked = RunbackAuditRevokedPubkeysPEM
				}

				embedded, _ := sig["pubkey"].(string)
				if embedded == "" {
					signature = "no-key"
					break
				}
				key := spkiEd25519(embedded)
				raw, err := hex.DecodeString(value)
				if key == nil || err != nil || !ed25519.Verify(key, payload, raw) {
					signature = "invalid"
					break
				}
				matches := func(list []string) bool {
					for _, p := range list {
						if k := spkiEd25519(p); k != nil && bytes.Equal(k, key) {
							return true
						}
					}
					return false
				}
				switch {
				case matches(revoked):
					// A sound signature from a known-compromised key proves
					// nothing about who produced the record — checked before the
					// unpinned case so PinNothing cannot launder a revoked
					// signer into "valid-unpinned".
					signature = "revoked"
				case len(pinned) == 0:
					signature = "valid-unpinned"
				case matches(pinned):
					signature = "valid"
				default:
					signature = "valid-unpinned"
				}

			case "HMAC-SHA256", "hmac-sha256":
				signatureAlg = "HMAC-SHA256"
				if opts.SigningKey == "" {
					// Symmetric: only someone already holding the secret can
					// check it, so a third party gets "no-key" by construction.
					signature = "no-key"
					break
				}
				mac := hmac.New(sha256.New, []byte(opts.SigningKey))
				mac.Write(payload)
				if hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(value)) {
					signature = "valid"
				} else {
					signature = "invalid"
				}
			}
		}
	}

	consistent, reasons := checkConsistency(record)
	integrity := chainOK && digestOK && cassetteOK && schemaOK && consistent
	valid := integrity && signature == "valid"

	verdict := "unverified"
	switch {
	case !integrity || signature == "invalid":
		verdict = "invalid"
	case valid:
		verdict = "valid"
	}

	// Report the run_id from the SIGNED events, not the unsigned manifest, so
	// the displayed identity is one the signature actually covers.
	runID, _ := manifest["run_id"].(string)
	for _, e := range events {
		if m, ok := e.(map[string]any); ok {
			if id, ok := m["run_id"].(string); ok && id != "" {
				runID = id
				break
			}
		}
	}
	generatedAt, _ := manifest["generated_at"].(string)
	specURL, _ := manifest["spec_url"].(string)
	if specURL == "" {
		specURL = "https://runback.dev/spec"
	}
	if reasons == nil {
		reasons = []string{}
	}

	return &VerifyResult{
		Valid:     valid,
		Verdict:   verdict,
		Integrity: integrity,
		Checks: VerifyChecks{
			Schema: schemaOK, Chain: chainOK, Digest: digestOK, Cassette: cassetteOK,
			Consistent: consistent, Signature: signature, SignatureAlg: signatureAlg,
		},
		ConsistencyFailures: reasons,
		Meta: VerifyMeta{
			Schema: schemaStr, RunID: runID, EventCount: len(events),
			GeneratedAt: generatedAt, SpecURL: specURL,
		},
	}, nil
}

// VerifyJSON verifies a cassette from its raw JSON bytes.
func VerifyJSON(raw []byte, opts VerifyOptions) (*VerifyResult, error) {
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	return Verify(record, opts)
}
