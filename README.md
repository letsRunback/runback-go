# runback-go

```bash
go get github.com/letsRunback/runback-go
```

> **Licence: Runback Community Licence — this is NOT open source.**
> Source-available. You may use, self-host, modify and redistribute it under the
> terms in [LICENSE](./LICENSE); Section 4 restricts offering it to third parties
> as a hosted service whose value is substantially this software's own
> functionality. Redistribution must keep the licence and this notice (§3).

This module is developed in the Runback monorepo at `packages/sdk-go` and
published here. To develop against a local checkout instead, add
`replace github.com/letsRunback/runback-go => ./packages/sdk-go` to your `go.mod`.


Event capture, redaction, and ingest for Go agents. Mirrors
`packages/sdk/src/core.ts`'s framework-agnostic `startRun()`: call methods by
hand at the point in your own agent loop where a model or tool call happens.

```go
import "github.com/letsRunback/runback-go/runback"

run := runback.NewRun(runback.Options{RunName: "support-agent", Input: task})

run.LLM(runback.LlmInput{
    Model:     runback.Model{Provider: "openai", ModelID: "gpt-4o"},
    Request:   runback.LlmRequest{Messages: []runback.ModelMessage{{Role: "user", Content: "Refund order #4471"}}},
    Response:  runback.LlmResponse{Text: runback.Ptr("Refund processed."), FinishReason: runback.Ptr("stop")},
    Usage:     &runback.TokenUsage{InputTokens: 120, OutputTokens: 18, TotalTokens: 138},
    LatencyMs: runback.Ptr(640),
})

run.Tool(runback.ToolInput{ToolName: "issue_refund", ToolCallID: "t1", Input: input, Output: output})

run.Finish(runback.FinishInput{Output: "Refund processed.", Status: "success"})
```

Set `RUNBACK_INGEST_URL` and `RUNBACK_API_KEY` (or pass `Options.IngestURL`/`Options.APIKey`
explicitly).

## Redaction

Client-side redaction is **on by default** (`Redact: RedactStandard`), ported
from `packages/redact/src/patterns.ts`: emails, SSNs, credit cards (Luhn-checked),
private key blocks, and provider/vendor API keys and tokens (OpenAI, Anthropic,
Groq, Stripe, GitHub, Slack, Google, AWS, JWTs, bearer tokens) are scrubbed
from event content — not the envelope/metrics fields — before an event is
buffered for send. Pass `Redact: RedactStrict` for the noisier tier (phone
numbers, IPv4 addresses) or `Redact: RedactOff` to disable:

```go
run := runback.NewRun(runback.Options{RunName: "support-agent", Redact: runback.RedactStrict})
```

This is a direct port of the regex rule set, not a byte-for-byte parity port —
see `packages/redact/test/redact.test.ts` vs. `redact_test.go` for the cases
both implementations are checked against. `customPatterns`/`redactKeys`/
`allowKeys`/a custom `redactor` callback (all present in the TS/Python SDKs)
aren't ported yet.

## Cassette digest

Every run also gets a real `cassette_digest` in its run-end event's metadata,
computed the same way the TS/Python SDKs and the server do — ported from
`packages/replay/src/cassette.ts`. `cassette_test.go` pins digests computed
by running the actual TS implementation via `npx tsx`, not derived from this
port (the same discipline `packages/sdk-python`'s `test_cassette.py` uses),
so digest equality across languages is a real proof, not a convention. Call
`run.CassetteDigest()` to read it before `Finish()` if you need it earlier.

## What Phase 1 is — and isn't

This SDK covers **event capture, ingest, redaction, and cassette hashing**.
It does **not** include:

- **Step-by-step replay/bisection.** `packages/replay/src/replay.ts`'s
  re-execution engine isn't ported. A Go-recorded run's digest proves
  tamper-evidence (the same guarantee a TS- or Python-recorded run gets),
  but you can't step through or bisect a divergence in it the way you can
  for a TS/Python-recorded run.

This is a real, tracked gap — not an omission we're pretending doesn't exist.
A future phase ports it once the re-execution engine's own spec work is
ready to hand-port faithfully.

## Testing

```
go test ./...
```

`TestEventsConformToIngestSchema` validates real Go-SDK-constructed events
against `packages/schema/schema.json` — the JSON Schema exported from
`packages/schema/src/validate.ts`'s zod validator, the actual source of truth
for what `/api/ingest` accepts. A TS schema change that isn't mirrored here
fails in this test, not silently in production. Regenerate the schema with
`npm run export-json-schema --workspace @runback/schema`.
