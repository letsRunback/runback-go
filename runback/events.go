package runback

// Wire format for /api/ingest — Phase 1 subset of packages/schema/src/events.ts.
// Field names are snake_case to match the wire schema exactly; Go's JSON tags
// carry the translation instead of a separate marshaling layer.
//
// Phase 1 covers event capture, ingest, client-side redaction (see redact.go,
// ported from packages/redact/src/patterns.ts, on by default at the standard
// tier), and cassette hash-chaining (see cassette.go, ported from
// packages/replay/src/cassette.ts) — a Go-recorded run gets a real
// cassette_digest, cross-checked byte-for-byte against the TS implementation
// in cassette_test.go. What's NOT ported: packages/replay/src/replay.ts's
// re-execution engine, so a Go-recorded run's digest proves tamper-evidence
// but can't be stepped through/bisected the way a TS- or Python-recorded run
// can. That's the real remaining gap for a future phase.

const SchemaVersion = 1

// Actor identifies who or what triggered an event — a specific end-user, a
// service/API-key identity, or an automated schedule.
type Actor struct {
	Type  string `json:"type"` // "user" | "api_key" | "system"
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// TraceError is the wire shape for a captured error.
type TraceError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Stack   string `json:"stack,omitempty"`
}

// Model identifies the provider and model_id of an LLM call.
type Model struct {
	Provider string `json:"provider"`
	ModelID  string `json:"model_id"`
}

// ModelMessage is one message in the request sent to the model.
type ModelMessage struct {
	Role    string `json:"role"` // "system" | "user" | "assistant" | "tool"
	Content any    `json:"content"`
}

// ToolDefinition is a tool exposed to the model in an LLM request.
type ToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

// ModelParams are the sampling parameters sent with an LLM request.
type ModelParams struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	MaxOutputTokens *float64 `json:"max_output_tokens,omitempty"`
	TopP            *float64 `json:"top_p,omitempty"`
}

// LlmRequest is the exact context window sent to the model.
type LlmRequest struct {
	System   *string          `json:"system"`
	Messages []ModelMessage   `json:"messages"`
	Tools    []ToolDefinition `json:"tools"`
	Params   ModelParams      `json:"params"`
}

// ToolCall is a tool the model asked to invoke, as returned in an LLM response.
type ToolCall struct {
	ToolCallID string `json:"tool_call_id"`
	ToolName   string `json:"tool_name"`
	Input      any    `json:"input,omitempty"`
}

// LlmResponse is what the model returned.
type LlmResponse struct {
	Text         *string    `json:"text"`
	Reasoning    *string    `json:"reasoning"`
	FinishReason *string    `json:"finish_reason"`
	ToolCalls    []ToolCall `json:"tool_calls"`
}

// TokenUsage is the token accounting for one LLM call.
type TokenUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// baseEvent carries the fields common to every event type. Each concrete
// event type embeds it; encoding/json promotes its fields to the top level
// of the marshaled object, matching the flat wire shape.
type baseEvent struct {
	SchemaVersion int     `json:"schema_version"`
	RunID         string  `json:"run_id"`
	SpanID        string  `json:"span_id"`
	ParentSpanID  *string `json:"parent_span_id"`
	Seq           int     `json:"seq"`
	TsStart       string  `json:"ts_start"`
	TsEnd         *string `json:"ts_end"`
	Actor         *Actor  `json:"actor,omitempty"`
}

// LlmEvent is a single call to a language model.
type LlmEvent struct {
	baseEvent
	Type      string      `json:"type"` // always "llm"
	Model     Model       `json:"model"`
	Request   LlmRequest  `json:"request"`
	Response  LlmResponse `json:"response"`
	Usage     *TokenUsage `json:"usage"`
	LatencyMs *int        `json:"latency_ms"`
	Error     *TraceError `json:"error"`
}

// ToolEvent is a single tool execution.
type ToolEvent struct {
	baseEvent
	Type       string      `json:"type"` // always "tool"
	ToolName   string      `json:"tool_name"`
	ToolCallID string      `json:"tool_call_id"`
	Input      any         `json:"input,omitempty"`
	Output     any         `json:"output,omitempty"`
	LatencyMs  *int        `json:"latency_ms"`
	Error      *TraceError `json:"error"`
}

// ReasoningEvent is a captured intermediate thought, independent of any
// specific model call — e.g. a routing decision in a graph-based agent.
type ReasoningEvent struct {
	baseEvent
	Type  string  `json:"type"` // always "reasoning"
	Text  string  `json:"text"`
	Label *string `json:"label"`
}

// RunEvent is the start or end envelope for one agent invocation.
type RunEvent struct {
	baseEvent
	Type     string         `json:"type"`  // always "run"
	Phase    string         `json:"phase"` // "start" | "end"
	Name     string         `json:"name"`
	Input    any            `json:"input,omitempty"`
	Output   any            `json:"output,omitempty"`
	Status   string         `json:"status"`
	Error    *TraceError    `json:"error"`
	Metadata map[string]any `json:"metadata"`
}
