// Package runback is the Go SDK for Runback — Phase 1: event capture and
// ingest only. Mirrors packages/sdk/src/core.ts's framework-agnostic
// startRun() (not the Vercel AI SDK auto-instrumentation, which has no Go
// equivalent): call Run methods by hand at the point in your own agent loop
// where a model or tool call happens.
//
// No client-side redaction, no cassette hash-chaining in this phase — see
// events.go's package comment for why, and use the OTel ingest path if you
// need redaction today.
package runback

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// crockford32Alphabet is ULID's base32 alphabet (RFC 4648 without I, L, O, U
// to avoid transcription ambiguity).
const crockford32Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULID generates a lexicographically-sortable id: a 48-bit millisecond
// timestamp followed by 80 bits of randomness, matching the ULID spec the
// TS/Python SDKs already use for run_id/span_id.
func newULID() string {
	var buf [16]byte
	ms := uint64(time.Now().UnixMilli())
	buf[0] = byte(ms >> 40)
	buf[1] = byte(ms >> 32)
	buf[2] = byte(ms >> 24)
	buf[3] = byte(ms >> 16)
	buf[4] = byte(ms >> 8)
	buf[5] = byte(ms)
	if _, err := rand.Read(buf[6:]); err != nil {
		// crypto/rand failing is a startup-time OS-level fault, not a
		// recoverable ingest error — a run with a colliding id is worse
		// than a loud crash.
		panic(fmt.Sprintf("runback: crypto/rand unavailable: %v", err))
	}
	return encodeCrockford32(buf)
}

func encodeCrockford32(data [16]byte) string {
	// 16 bytes = 128 bits -> 26 base32 characters (130 bits of capacity, top
	// 2 always zero). big.Int's DivMod is the simplest correct way to peel
	// off 5-bit groups from the most-significant end.
	n := new(big.Int).SetBytes(data[:])
	base := big.NewInt(32)
	mod := new(big.Int)
	var out [26]byte
	for i := 25; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = crockford32Alphabet[mod.Int64()]
	}
	return string(out[:])
}

// Actor and error helpers.

func toTraceError(err error) *TraceError {
	if err == nil {
		return nil
	}
	return &TraceError{Name: "Error", Message: err.Error()}
}

func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// Ptr returns a pointer to v — a convenience for building the *int/*float64
// literal fields several event structs require (Go has no address-of-literal
// syntax), e.g. LlmInput{LatencyMs: runback.Ptr(940)}.
func Ptr[T any](v T) *T { return &v }

// LlmInput is the argument to Run.LLM.
type LlmInput struct {
	Model     Model
	Request   LlmRequest
	Response  LlmResponse
	Usage     *TokenUsage
	LatencyMs *int
	Error     error
}

// ToolInput is the argument to Run.Tool.
type ToolInput struct {
	ToolName   string
	ToolCallID string
	Input      any
	Output     any
	LatencyMs  *int
	Error      error
}

// FinishInput is the argument to Run.Finish.
type FinishInput struct {
	Output any
	Status string // "success" | "error" — defaults to "success", or "error" if Error is set
	Error  error
}

// Options configures a new Run.
type Options struct {
	RunName string
	Input   any
	Tags    map[string]any
	Actor   *Actor
	// IngestURL overrides RUNBACK_INGEST_URL. Defaults to http://localhost:3000.
	IngestURL string
	// APIKey overrides RUNBACK_API_KEY.
	APIKey string
	// FlushAt auto-flushes once this many events are buffered. Defaults to 25.
	FlushAt int
	// HTTPClient overrides the default http.Client (10s timeout).
	HTTPClient *http.Client
	// Redact selects the built-in redaction tier applied to content-bearing
	// fields before an event is buffered. Zero value (RedactStandard's
	// underlying "") redacts at the standard tier — ON by default, matching
	// the TS/Python SDKs. Pass RedactOff to disable, or RedactStrict for the
	// noisier tier (phone numbers, IPv4 addresses).
	Redact RedactionMode
}

// Run owns one agent invocation's identity and buffers its trace events,
// flushing them to the ingest endpoint. Every public method is internally
// guarded — instrumentation must never propagate a panic into the caller's
// agent loop.
type Run struct {
	RunID string

	mu         sync.Mutex
	runName    string
	rootSpanID string
	seq        int
	buffer     []any
	actor      *Actor
	flushAt    int
	ingestURL  string
	apiKey     string
	httpClient *http.Client
	redactor   *redactor

	// Running oracle-stream chain — the deterministic cassette digest at
	// capture time. See cassette.go's package comment.
	cassettePrev  string
	cassetteCount int
}

// NewRun starts a run and records its start envelope.
func NewRun(opts Options) *Run {
	flushAt := opts.FlushAt
	if flushAt <= 0 {
		flushAt = 25
	}
	ingestURL := opts.IngestURL
	if ingestURL == "" {
		ingestURL = os.Getenv("RUNBACK_INGEST_URL")
	}
	if ingestURL == "" {
		ingestURL = "http://localhost:3000"
	}
	ingestURL = strings.TrimRight(ingestURL, "/")
	apiKey := opts.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("RUNBACK_API_KEY")
	}
	if ingestURL == "http://localhost:3000" && opts.IngestURL == "" && os.Getenv("RUNBACK_INGEST_URL") == "" && strings.HasPrefix(apiKey, "rb_live_") {
		log.Printf("[runback] RUNBACK_INGEST_URL is not set, so events will be sent to http://localhost:3000 — but your API key is a hosted key. Set RUNBACK_INGEST_URL=https://runback.dev (or your self-host origin), or nothing will be recorded.")
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	r := &Run{
		RunID:      newULID(),
		runName:    opts.RunName,
		rootSpanID: newULID(),
		actor:      opts.Actor,
		flushAt:    flushAt,
		ingestURL:  ingestURL,
		apiKey:     apiKey,
		httpClient: httpClient,
		redactor:   newRedactor(opts.Redact),
	}

	tags := opts.Tags
	if tags == nil {
		tags = map[string]any{}
	}
	r.push(RunEvent{
		baseEvent: r.newBase(r.rootSpanID, nil),
		Type:      "run",
		Phase:     "start",
		Name:      opts.RunName,
		Input:     opts.Input,
		Status:    "running",
		Error:     nil,
		Metadata:  tags,
	})
	return r
}

func (r *Run) newBase(spanID string, parentSpanID *string) baseEvent {
	seq := r.seq
	r.seq++
	now := nowISO()
	return baseEvent{
		SchemaVersion: SchemaVersion,
		RunID:         r.RunID,
		SpanID:        spanID,
		ParentSpanID:  parentSpanID,
		Seq:           seq,
		TsStart:       now,
		TsEnd:         &now,
		Actor:         r.actor,
	}
}

func (r *Run) push(event any) {
	if r.redactor != nil {
		event = redactEvent(r.redactor, event)
	}
	r.mu.Lock()
	r.buffer = append(r.buffer, event)
	// Advance the capture-time oracle chain through the SAME
	// oracleEntryOfEvent used everywhere else this digest is recomputed —
	// so the capture-time, server, and verification digests are identical
	// by construction. Chains the REDACTED event (matches TS/Python), so
	// the recorded and replayed values stay identical and the digest is
	// computed over the scrubbed value.
	if entry := oracleEntryOfEvent(event); entry != nil {
		r.cassettePrev = chainStep(r.cassettePrev, entry.kind, entry.key, entry.output)
		r.cassetteCount++
	}
	shouldFlush := len(r.buffer) >= r.flushAt
	r.mu.Unlock()
	if shouldFlush {
		r.Flush()
	}
}

// LLM records a completed (or failed) model call.
func (r *Run) LLM(in LlmInput) {
	r.push(LlmEvent{
		baseEvent: r.newBase(newULID(), &r.rootSpanID),
		Type:      "llm",
		Model:     in.Model,
		Request:   in.Request,
		Response:  in.Response,
		Usage:     in.Usage,
		LatencyMs: in.LatencyMs,
		Error:     toTraceError(in.Error),
	})
}

// Tool records a tool execution (success or error).
func (r *Run) Tool(in ToolInput) {
	r.push(ToolEvent{
		baseEvent:  r.newBase(newULID(), &r.rootSpanID),
		Type:       "tool",
		ToolName:   in.ToolName,
		ToolCallID: in.ToolCallID,
		Input:      in.Input,
		Output:     in.Output,
		LatencyMs:  in.LatencyMs,
		Error:      toTraceError(in.Error),
	})
}

// Reasoning records a captured intermediate thought, independent of any
// specific model call. label is optional — pass "" for none.
func (r *Run) Reasoning(text string, label string) {
	var labelPtr *string
	if label != "" {
		labelPtr = &label
	}
	r.push(ReasoningEvent{
		baseEvent: r.newBase(newULID(), &r.rootSpanID),
		Type:      "reasoning",
		Text:      text,
		Label:     labelPtr,
	})
}

// FlushResult reports the outcome of a Flush.
type FlushResult struct {
	OK    bool
	Sent  int
	Error error
}

// Flush POSTs whatever is buffered. Clears the buffer on success; requeues
// on failure so a later Flush (or Finish) can retry within the same process.
// Never persisted to disk — if the process exits with events still
// buffered, they are lost.
func (r *Run) Flush() FlushResult {
	r.mu.Lock()
	batch := r.buffer
	r.buffer = nil
	r.mu.Unlock()

	if len(batch) == 0 {
		return FlushResult{OK: true}
	}
	if r.apiKey == "" {
		log.Printf("[runback] no RUNBACK_API_KEY set — dropped %d event(s)", len(batch))
		return FlushResult{OK: false, Error: fmt.Errorf("no RUNBACK_API_KEY set")}
	}

	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		r.requeue(batch)
		return FlushResult{OK: false, Error: err}
	}

	req, err := http.NewRequest(http.MethodPost, r.ingestURL+"/api/ingest", bytes.NewReader(body))
	if err != nil {
		r.requeue(batch)
		return FlushResult{OK: false, Error: err}
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+r.apiKey)

	res, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("[runback] ingest error contacting %s: %v", r.ingestURL, err)
		r.requeue(batch)
		return FlushResult{OK: false, Error: err}
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		err := fmt.Errorf("ingest failed %d", res.StatusCode)
		log.Printf("[runback] %v", err)
		r.requeue(batch)
		return FlushResult{OK: false, Error: err}
	}
	return FlushResult{OK: true, Sent: len(batch)}
}

func (r *Run) requeue(batch []any) {
	r.mu.Lock()
	r.buffer = append(batch, r.buffer...)
	r.mu.Unlock()
}

// CassetteDigest returns the current capture-time oracle-chain digest and
// entry count — the same value that lands in the run-end event's metadata,
// available before Finish() if a caller needs it earlier.
func (r *Run) CassetteDigest() (digest string, entryCount int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cassettePrev == "" {
		return sha256Hex(""), r.cassetteCount
	}
	return r.cassettePrev, r.cassetteCount
}

// Finish records the run-end envelope and flushes everything.
func (r *Run) Finish(in FinishInput) FlushResult {
	status := in.Status
	if status == "" {
		if in.Error != nil {
			status = "error"
		} else {
			status = "success"
		}
	}
	digest := r.cassettePrev
	if digest == "" {
		digest = sha256Hex("")
	}
	// redaction_count/redaction_by_type/truncated_fields are self-reported by
	// the SDK — the server never sees the raw value, so it can't
	// independently verify a redaction happened — same trust boundary as
	// every other client-supplied field on this event.
	metadata := map[string]any{
		"cassette_digest":  digest,
		"cassette_entries": r.cassetteCount,
	}
	if r.redactor != nil {
		metadata["redaction_count"] = r.redactor.total()
		metadata["redaction_by_type"] = r.redactor.typeCounts()
		metadata["truncated_fields"] = r.redactor.truncatedFieldCount()
	}
	r.push(RunEvent{
		baseEvent: r.newBase(newULID(), &r.rootSpanID),
		Type:      "run",
		Phase:     "end",
		Name:      r.runName,
		Output:    in.Output,
		Status:    status,
		Error:     toTraceError(in.Error),
		Metadata:  metadata,
	})
	return r.Flush()
}
