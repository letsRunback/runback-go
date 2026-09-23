package runback

import (
	"os"
	"path/filepath"
	"testing"
)

// Where the shared test fixtures live, in whichever tree this package is
// checked out into.
//
// This package is developed inside the Runback monorepo and PUBLISHED as a
// standalone module at github.com/letsRunback/runback-go, so its tests have to
// find the same fixtures under two different layouts:
//
//	monorepo    packages/sdk-go/runback/..  ->  ../../verify/testdata/...
//	standalone  runback/..                  ->  ../testdata/...
//
// Hardcoding either one means the tests pass in the tree they were written in
// and fail in the other. That matters more than it sounds: the published module
// is the artefact an outsider actually runs `go test ./...` against, and a
// conformance suite that cannot find its fixtures there proves nothing to the
// person best placed to check us.
//
// Missing fixtures are a FATAL error, never a skip. A silently skipped
// conformance suite reports success while verifying nothing, which is the exact
// shape of failure these tests exist to prevent elsewhere.
func fixturePath(t *testing.T, parts ...string) string {
	t.Helper()
	for _, base := range [][]string{
		{"..", "..", "verify", "testdata"}, // monorepo
		{"..", "testdata"},                 // published standalone module
	} {
		p := filepath.Join(append(append([]string{}, base...), parts...)...)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("cannot find fixture %v under either ../../verify/testdata or ../testdata.\n"+
		"These tests hold this port to the reference implementation; without the\n"+
		"fixtures they would be comparing this code only to itself.", parts)
	return ""
}

// schemaPath resolves the event-schema fixture under the same two layouts.
func schemaPath(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "..", "schema", "schema.json"), // monorepo
		filepath.Join("..", "testdata", "schema.json"),     // standalone
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatal("cannot find schema.json under either ../../schema or ../testdata")
	return ""
}
