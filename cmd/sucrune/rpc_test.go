package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRPCUsesOnePersistentServiceAndReturnsErrorEnvelopes(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	input := strings.NewReader("{\"op\":\"env.create\",\"name\":\"rpc\"}\n{\"op\":\"unknown\"}\n{\"op\":\"env.list\"}\n")
	if status := runWithInput([]string{"--data-dir", root, "rpc"}, input, &stdout, &stderr); status != 0 {
		t.Fatalf("rpc failed: %s", &stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected one response per line: %s", &stdout)
	}
	var responses [3]struct {
		OK     bool              `json:"ok"`
		Result json.RawMessage   `json:"result"`
		Error  map[string]string `json:"error"`
	}
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &responses[i]); err != nil {
			t.Fatal(err)
		}
	}
	if !responses[0].OK || responses[1].OK || responses[1].Error["code"] != "unsupported_operation" || !responses[2].OK || !bytes.Contains(responses[2].Result, []byte(`"name":"rpc"`)) {
		t.Fatalf("unexpected responses: %s", &stdout)
	}
}
