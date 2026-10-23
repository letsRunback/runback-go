package runback

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDocsCapture is the Go integration page's conformance capture.
//
// A small agent loop calls a scripted OpenAI Chat Completions endpoint (a tool
// turn, then a text turn: the shape every other integration's capture has),
// runs the tool, and records each step with this package's real Run. A local
// ingest endpoint keeps exactly what the SDK POSTs. Nothing leaves the machine
// and no key is needed.
//
// Two environment variables, both optional, let the monorepo's docs test drive
// it (packages/sdk/test/capture/goFixture.test.ts):
//
//	DOCS_MODEL_URL     use this model endpoint instead of the in-process one
//	                   (the docs test passes the scripted provider the
//	                   TypeScript and Python captures run against)
//	DOCS_CAPTURE_OUT   also write the captured batches to this file
//
// Without them it still captures and asserts the shape, so `go test ./...`
// means the same thing in the published standalone module.
func TestDocsCapture(t *testing.T) {
	const secret = "jane.doe@example.com"

	modelURL := os.Getenv("DOCS_MODEL_URL")
	if modelURL == "" {
		srv := httptest.NewServer(scriptedChatModel())
		defer srv.Close()
		modelURL = srv.URL
	}

	var mu sync.Mutex
	var batches []json.RawMessage
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest" || r.Header.Get("authorization") != "Bearer rb_live_docs_capture" {
			t.Errorf("unexpected ingest request %s %s", r.URL.Path, r.Header.Get("authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Events json.RawMessage `json:"events"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("ingest body is not JSON: %v", err)
		}
		mu.Lock()
		batches = append(batches, payload.Events)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ingest.Close()

	task := "Weather in Paris? Reply to " + secret
	run := NewRun(Options{RunName: "weather-agent", Input: task, IngestURL: ingest.URL, APIKey: "rb_live_docs_capture"})

	system := "You are a weather bot."
	tools := []ToolDefinition{{
		Name:        "get_weather",
		Description: "Weather for a city",
		Parameters: map[string]any{
			"type":       "object",
			"properties": map[string]any{"city": map[string]any{"type": "string"}},
			"required":   []any{"city"},
		},
	}}
	// What the model is sent (OpenAI wire shape) and what the run records
	// (schema-v1 messages; the system prompt is recorded separately).
	wire := []map[string]any{{"role": "system", "content": system}, {"role": "user", "content": task}}
	recorded := []ModelMessage{{Role: "user", Content: task}}
	var answer string

	for turn := 0; turn < 3 && answer == ""; turn++ {
		start := time.Now()
		reply := callChatModel(t, modelURL, "gpt-4o-mini", wire, tools)
		latency := int(time.Since(start).Milliseconds())
		choice := reply.Choices[0]

		calls := []ToolCall{} // explicit: v0.2.0 sends a nil slice as null and ingest refuses the batch
		for _, c := range choice.Message.ToolCalls {
			var input map[string]any
			_ = json.Unmarshal([]byte(c.Function.Arguments), &input)
			calls = append(calls, ToolCall{ToolCallID: c.ID, ToolName: c.Function.Name, Input: input})
		}
		run.LLM(LlmInput{
			Model:     Model{Provider: "openai", ModelID: reply.Model},
			Request:   LlmRequest{System: &system, Messages: append([]ModelMessage(nil), recorded...), Tools: tools},
			Response:  LlmResponse{Text: choice.Message.Content, FinishReason: &choice.FinishReason, ToolCalls: calls},
			Usage:     &TokenUsage{InputTokens: reply.Usage.PromptTokens, OutputTokens: reply.Usage.CompletionTokens, TotalTokens: reply.Usage.TotalTokens},
			LatencyMs: &latency,
		})

		if len(calls) == 0 {
			if choice.Message.Content != nil {
				answer = *choice.Message.Content
			}
			break
		}
		wire = append(wire, choice.Message.raw())
		recorded = append(recorded, ModelMessage{Role: "assistant", Content: calls})
		for _, c := range calls {
			start := time.Now()
			output := map[string]any{"city": c.Input.(map[string]any)["city"], "forecast": "sunny"}
			run.Tool(ToolInput{ToolName: c.ToolName, ToolCallID: c.ToolCallID, Input: c.Input, Output: output, LatencyMs: Ptr(int(time.Since(start).Milliseconds()))})
			out, _ := json.Marshal(output)
			wire = append(wire, map[string]any{"role": "tool", "tool_call_id": c.ToolCallID, "content": string(out)})
			recorded = append(recorded, ModelMessage{Role: "tool", Content: string(out)})
		}
	}

	res := run.Finish(FinishInput{Output: answer, Status: "success"})
	if !res.OK {
		t.Fatalf("Finish: %v", res.Error)
	}

	all, err := json.Marshal(batches)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(all)
	if strings.Contains(blob, secret) {
		t.Fatal("the planted email reached ingest unredacted")
	}
	if !strings.Contains(blob, "[redacted:email]") {
		t.Fatal("expected standard-tier redaction to replace the planted email")
	}
	var events []map[string]any
	for _, b := range batches {
		var evs []map[string]any
		if err := json.Unmarshal(b, &evs); err != nil {
			t.Fatal(err)
		}
		events = append(events, evs...)
	}
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, fmt.Sprint(e["type"]))
	}
	if got := strings.Join(types, ","); got != "run,llm,tool,llm,run" {
		t.Fatalf("event types = %s, want run,llm,tool,llm,run", got)
	}
	if answer == "" {
		t.Fatal("the agent never got a text answer")
	}

	if out := os.Getenv("DOCS_CAPTURE_OUT"); out != "" {
		fixture, _ := json.MarshalIndent(map[string]any{"integration": "go-sdk", "kind": "sdk", "batches": batches}, "", " ")
		if err := os.WriteFile(out, append(fixture, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// ── a minimal OpenAI Chat Completions client and a scripted endpoint ──

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatMessage struct {
	Role      string         `json:"role"`
	Content   *string        `json:"content"`
	ToolCalls []chatToolCall `json:"tool_calls,omitempty"`
}

func (m chatMessage) raw() map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

type chatReply struct {
	Model   string `json:"model"`
	Choices []struct {
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func callChatModel(t *testing.T, baseURL, model string, messages []map[string]any, tools []ToolDefinition) chatReply {
	t.Helper()
	wireTools := make([]map[string]any, 0, len(tools))
	for _, tl := range tools {
		wireTools = append(wireTools, map[string]any{"type": "function", "function": map[string]any{"name": tl.Name, "description": tl.Description, "parameters": tl.Parameters}})
	}
	body, _ := json.Marshal(map[string]any{"model": model, "messages": messages, "tools": wireTools})
	res, err := http.Post(strings.TrimRight(baseURL, "/")+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("model call: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("model call: HTTP %d", res.StatusCode)
	}
	var reply chatReply
	if err := json.NewDecoder(res.Body).Decode(&reply); err != nil {
		t.Fatalf("model reply: %v", err)
	}
	if len(reply.Choices) == 0 {
		t.Fatal("model reply has no choices")
	}
	return reply
}

// scriptedChatModel follows the same script as the monorepo's shared capture
// provider (packages/sdk/test/capture/harness/mockProvider.mjs): call each
// offered tool once with "Paris" for every string argument, then answer in
// text. Usage is 12 in / 5 out on the tool turn and 20 in / 8 out on the text
// turn.
func scriptedChatModel() http.Handler {
	n := 0
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		defer mu.Unlock()
		called := false
		for _, m := range req.Messages {
			if m.Role == "tool" {
				called = true
			}
		}
		var msg map[string]any
		var finish string
		var in, out int
		if len(req.Tools) > 0 && !called {
			n++
			msg = map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{
				"id": fmt.Sprintf("call_%d", n), "type": "function",
				"function": map[string]any{"name": req.Tools[0].Function.Name, "arguments": `{"city":"Paris"}`},
			}}}
			finish, in, out = "tool_calls", 12, 5
		} else {
			msg = map[string]any{"role": "assistant", "content": "It is sunny in Paris."}
			finish, in, out = "stop", 20, 8
		}
		n++
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": fmt.Sprintf("chatcmpl_%d", n), "object": "chat.completion", "created": 1760000000, "model": req.Model,
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   map[string]any{"prompt_tokens": in, "completion_tokens": out, "total_tokens": in + out},
		})
	})
}
