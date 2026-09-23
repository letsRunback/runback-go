package runback

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunSendsExpectedEvents(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %q", r.Header.Get("authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("invalid JSON sent to ingest: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run := NewRun(Options{RunName: "test-run", IngestURL: srv.URL, APIKey: "test-key"})
	run.LLM(LlmInput{
		Model:     Model{Provider: "test", ModelID: "m"},
		Request:   LlmRequest{Messages: []ModelMessage{{Role: "user", Content: "hi"}}},
		Response:  LlmResponse{Text: Ptr("hello"), FinishReason: Ptr("stop")},
		Usage:     &TokenUsage{InputTokens: 5, OutputTokens: 2, TotalTokens: 7},
		LatencyMs: Ptr(120),
	})
	run.Tool(ToolInput{ToolName: "search", ToolCallID: "t1", Input: map[string]any{"q": "x"}, Output: map[string]any{"r": []any{}}})
	run.Reasoning("decided to search", "chain")
	result := run.Finish(FinishInput{Output: "done"})

	if !result.OK {
		t.Fatalf("Finish failed: %v", result.Error)
	}
	if result.Sent != 5 {
		t.Fatalf("expected 5 events sent (run-start, llm, tool, reasoning, run-end), got %d", result.Sent)
	}
}

func TestFlushWithNoAPIKeyDropsEvents(t *testing.T) {
	run := NewRun(Options{RunName: "no-key-run", IngestURL: "http://unused"})
	run.Reasoning("x", "")
	result := run.Finish(FinishInput{})
	if result.OK {
		t.Fatal("expected Finish to fail with no API key set")
	}
}

func TestNewULIDIsSortableAndUnique(t *testing.T) {
	a := newULID()
	b := newULID()
	if len(a) != 26 || len(b) != 26 {
		t.Fatalf("expected 26-char ULIDs, got %d and %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("expected two calls to newULID to produce distinct ids")
	}
}

// TestEventsConformToIngestSchema validates real Go-SDK-constructed events
// against packages/schema/schema.json — the JSON Schema exported from
// packages/schema/src/validate.ts's zod validator, the actual source of
// truth for what /api/ingest accepts. Mirrors
// packages/sdk-python/tests/test_schema_conformance.py's approach, but
// checks required-field presence directly (no jsonschema library dependency)
// rather than full schema validation — sufficient to catch the common drift
// case (a required field renamed/dropped on either side) without adding an
// external dependency for a Phase 1 SDK.
func TestEventsConformToIngestSchema(t *testing.T) {
	schemaPath := schemaPath(t)
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Skipf("%s not found — run: npm run export-json-schema --workspace @runback/schema", schemaPath)
	}
	var schema struct {
		Definitions struct {
			IngestPayload struct {
				Properties struct {
					Events struct {
						Items struct {
							AnyOf []struct {
								Properties struct {
									Type struct {
										Const string `json:"const"`
									} `json:"type"`
								} `json:"properties"`
								Required []string `json:"required"`
							} `json:"anyOf"`
						} `json:"items"`
					} `json:"events"`
				} `json:"properties"`
			} `json:"IngestPayload"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("could not parse schema.json: %v", err)
	}
	required := map[string][]string{}
	for _, variant := range schema.Definitions.IngestPayload.Properties.Events.Items.AnyOf {
		required[variant.Properties.Type.Const] = variant.Required
	}
	if len(required) == 0 {
		t.Fatal("schema.json parsed but no event variants found — check the struct shape above still matches")
	}

	run := NewRun(Options{RunName: "conformance", APIKey: "k"})
	run.LLM(LlmInput{
		Model:    Model{Provider: "test", ModelID: "m"},
		Request:  LlmRequest{Messages: []ModelMessage{{Role: "user", Content: "hi"}}},
		Response: LlmResponse{Text: Ptr("hi"), FinishReason: Ptr("stop")},
		Usage:    &TokenUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2},
	})
	run.Tool(ToolInput{ToolName: "search", ToolCallID: "t1"})
	run.Reasoning("thought", "")

	for _, event := range run.buffer {
		asJSON, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("could not marshal event: %v", err)
		}
		var asMap map[string]json.RawMessage
		if err := json.Unmarshal(asJSON, &asMap); err != nil {
			t.Fatalf("could not unmarshal event back to a map: %v", err)
		}
		var typ string
		if err := json.Unmarshal(asMap["type"], &typ); err != nil {
			t.Fatalf("event has no type field: %v", err)
		}
		req, ok := required[typ]
		if !ok {
			t.Fatalf("schema.json has no variant for event type %q — Go and TS event types have diverged", typ)
		}
		for _, field := range req {
			if _, present := asMap[field]; !present {
				t.Errorf("event type %q is missing required field %q per schema.json", typ, field)
			}
		}
	}
}
