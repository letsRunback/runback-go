package runback

import (
	"strings"
	"testing"
)

// Mirrors packages/redact/test/redact.test.ts's own cases so the two
// implementations can be eyeballed against each other for drift — not a
// generated cross-language digest-parity test (that's Phase 2, alongside the
// cassette port; see events.go's package comment).

func standardRedactor() *redactor { return newRedactor(RedactStandard) }
func strictRedactor() *redactor   { return newRedactor(RedactStrict) }

func TestSecretAndPIIDetectors(t *testing.T) {
	cases := []struct {
		label, input, tag string
	}{
		{"email", "ping me at jane.doe@acme.co please", "email"},
		{"openai_key", "key=sk-proj-abc123def456ghi789jkl012", "openai_key"},
		{"anthropic_key", "sk-ant-api03-abc123def456ghi789jkl012mno", "anthropic_key"},
		{"groq_key", "gsk_0GSAAh4qypNTnJBjcatHWGdyb3FYAbCdEf", "groq_key"},
		{"github_token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_token"},
		{"slack_token", "xoxb-1234567890-abcdefghij", "slack_token"},
		{"google_api_key", "AIzaSyA1234567890abcdefghijklmnopqrstuv", "google_api_key"},
		{"stripe_key", "sk_live_abcdefghijklmnop1234", "stripe_key"},
		{"aws_access_key", "AKIAIOSFODNN7EXAMPLE", "aws_access_key"},
		{"ssn", "ssn 123-45-6789 on file", "ssn"},
		{"jwt", "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF123456", "jwt"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			out := standardRedactor().redactValue(c.input).(string)
			want := "[redacted:" + c.tag + "]"
			if !strings.Contains(out, want) {
				t.Fatalf("redactValue(%q) = %q, want it to contain %q", c.input, out, want)
			}
			for _, word := range strings.Fields(c.input) {
				if len(word) > 12 && strings.Contains(out, word) {
					t.Fatalf("redactValue(%q) = %q, still contains the original secret %q", c.input, out, word)
				}
			}
		})
	}
}

func TestEmailAtRFC5321Limit(t *testing.T) {
	local64 := strings.Repeat("a", 64)
	out := standardRedactor().redactValue("contact " + local64 + "@example.com now").(string)
	if !strings.Contains(out, "[redacted:email]") {
		t.Fatalf("expected email redaction, got %q", out)
	}
	if strings.Contains(out, local64) {
		t.Fatalf("original 64-char local part leaked: %q", out)
	}
}

func TestBearerTokenKeepsScheme(t *testing.T) {
	out := standardRedactor().redactValue("authorization: Bearer abcdef0123456789xyz").(string)
	if !strings.Contains(out, "Bearer [redacted]") {
		t.Fatalf("expected 'Bearer [redacted]', got %q", out)
	}
	if strings.Contains(out, "abcdef0123456789xyz") {
		t.Fatalf("token leaked: %q", out)
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANB\nkqhki==\n-----END RSA PRIVATE KEY-----"
	out := standardRedactor().redactValue(pem).(string)
	if out != "[redacted:private_key]" {
		t.Fatalf("got %q, want exactly [redacted:private_key]", out)
	}
}

func TestLuhnValidVsInvalidCard(t *testing.T) {
	valid := standardRedactor().redactValue("card 4111 1111 1111 1111").(string)
	if !strings.Contains(valid, "[redacted:credit_card]") {
		t.Fatalf("expected Luhn-valid card to redact, got %q", valid)
	}
	invalid := standardRedactor().redactValue("order 4111 1111 1111 1112").(string)
	if !strings.Contains(invalid, "4111 1111 1111 1112") {
		t.Fatalf("expected Luhn-invalid card to survive, got %q", invalid)
	}
}

func TestTiers(t *testing.T) {
	if out := standardRedactor().redactValue("call 415-555-0142").(string); !strings.Contains(out, "415-555-0142") {
		t.Fatalf("standard tier should leave phone numbers alone, got %q", out)
	}
	if out := strictRedactor().redactValue("call 415-555-0142").(string); !strings.Contains(out, "[redacted:phone]") {
		t.Fatalf("strict tier should redact phone numbers, got %q", out)
	}
	if out := standardRedactor().redactValue("host 10.0.0.42").(string); !strings.Contains(out, "10.0.0.42") {
		t.Fatalf("standard tier should leave IPs alone, got %q", out)
	}
	if out := strictRedactor().redactValue("host 10.0.0.42").(string); !strings.Contains(out, "[redacted:ipv4]") {
		t.Fatalf("strict tier should redact IPs, got %q", out)
	}
}

func TestOffReturnsNoRedactor(t *testing.T) {
	if newRedactor(RedactOff) != nil {
		t.Fatal("expected newRedactor(RedactOff) to return nil")
	}
}

func TestSensitiveKeyRedactsWholesale(t *testing.T) {
	out := standardRedactor().redactValue(map[string]any{"password": "hunter2", "note": "fine"}).(map[string]any)
	if out["password"] != "[redacted:key:password]" {
		t.Fatalf("password = %v, want [redacted:key:password]", out["password"])
	}
	if out["note"] != "fine" {
		t.Fatalf("note = %v, want unchanged", out["note"])
	}
}

func TestWalksNestedObjectsAndArrays(t *testing.T) {
	input := map[string]any{
		"user": map[string]any{
			"email":   "a@b.com",
			"profile": map[string]any{"ssn": "123-45-6789"},
		},
		"items": []any{
			map[string]any{"api_key": "secret123"},
			map[string]any{"ok": float64(1)},
		},
	}
	out := standardRedactor().redactValue(input).(map[string]any)
	user := out["user"].(map[string]any)
	if !strings.Contains(user["email"].(string), "[redacted:email]") {
		t.Fatalf("user.email = %v, want redacted", user["email"])
	}
	profile := user["profile"].(map[string]any)
	if profile["ssn"] != "[redacted:key:ssn]" {
		t.Fatalf("user.profile.ssn = %v, want [redacted:key:ssn]", profile["ssn"])
	}
	items := out["items"].([]any)
	if items[0].(map[string]any)["api_key"] != "[redacted:key:api_key]" {
		t.Fatalf("items[0].api_key = %v, want [redacted:key:api_key]", items[0].(map[string]any)["api_key"])
	}
	if items[1].(map[string]any)["ok"] != float64(1) {
		t.Fatalf("items[1].ok = %v, want unchanged 1", items[1].(map[string]any)["ok"])
	}
}

func TestRedactEventScrubsContentPreservesEnvelope(t *testing.T) {
	r := standardRedactor()
	latency := 42
	event := LlmEvent{
		baseEvent: baseEvent{SchemaVersion: 1, RunID: "run1", SpanID: "span1", Seq: 0, TsStart: "t0"},
		Type:      "llm",
		Model:     Model{Provider: "openai", ModelID: "gpt-4o"},
		Request: LlmRequest{
			Messages: []ModelMessage{{Role: "user", Content: "email me at jane.doe@acme.co"}},
		},
		Response:  LlmResponse{Text: Ptr("sk-proj-abc123def456ghi789jkl012")},
		LatencyMs: &latency,
	}
	out := redactEvent(r, event).(LlmEvent)

	if out.RunID != "run1" || out.SpanID != "span1" || out.Model.ModelID != "gpt-4o" || *out.LatencyMs != 42 {
		t.Fatalf("envelope/metrics fields were altered: %+v", out)
	}
	content := out.Request.Messages[0].Content.(string)
	if !strings.Contains(content, "[redacted:email]") {
		t.Fatalf("request content not redacted: %q", content)
	}
	if !strings.Contains(*out.Response.Text, "[redacted:openai_key]") {
		t.Fatalf("response content not redacted: %q", *out.Response.Text)
	}
}

func TestRedactOffSkipsEntirely(t *testing.T) {
	run := NewRun(Options{RunName: "no-redact-test", APIKey: "k", Redact: RedactOff})
	run.LLM(LlmInput{
		Model:    Model{Provider: "openai", ModelID: "m"},
		Request:  LlmRequest{Messages: []ModelMessage{{Role: "user", Content: "jane.doe@acme.co"}}},
		Response: LlmResponse{Text: Ptr("hi")},
	})
	found := false
	for _, e := range run.buffer {
		if llm, ok := e.(LlmEvent); ok {
			content := llm.Request.Messages[0].Content.(string)
			if content == "jane.doe@acme.co" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected the raw email to survive with Redact: RedactOff")
	}
}

func TestRedactDefaultsToStandardOn(t *testing.T) {
	run := NewRun(Options{RunName: "default-redact-test", APIKey: "k"})
	run.LLM(LlmInput{
		Model:    Model{Provider: "openai", ModelID: "m"},
		Request:  LlmRequest{Messages: []ModelMessage{{Role: "user", Content: "jane.doe@acme.co"}}},
		Response: LlmResponse{Text: Ptr("hi")},
	})
	for _, e := range run.buffer {
		if llm, ok := e.(LlmEvent); ok {
			content := llm.Request.Messages[0].Content.(string)
			if content == "jane.doe@acme.co" {
				t.Fatal("expected redaction ON by default with no Redact option set")
			}
		}
	}
}
