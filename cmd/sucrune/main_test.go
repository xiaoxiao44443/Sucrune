package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"sucrune/internal/capability"
	"sucrune/internal/environment"
)

func TestInfoReportsActualDevelopmentCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"info"}, &stdout, &stderr); status != 0 {
		t.Fatalf("status %d, stderr %s", status, &stderr)
	}
	var report capability.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.Features["linux_execution"].Status != capability.Unsupported {
		t.Fatal("unimplemented execution must be explicit")
	}
}

func TestEnvironmentCLIRequiresExplicitDataDirectory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"env", "create", "--name", "test"}, &stdout, &stderr); status == 0 {
		t.Fatal("implicit data directory accepted")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("data_directory_required")) || stdout.Len() != 0 {
		t.Fatalf("unexpected output: stdout %s, stderr %s", &stdout, &stderr)
	}
}

func TestCLIEnvironmentLifecycle(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	if status := run([]string{"--data-dir", root, "env", "create", "--name", "test"}, &stdout, &stderr); status != 0 {
		t.Fatalf("create: %s", &stderr)
	}
	var created environment.Environment
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--data-dir", root, "env", "get", created.ID}, &stdout, &stderr); status != 0 {
		t.Fatalf("get: %s", &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--data-dir", root, "env", "delete", created.ID}, &stdout, &stderr); status != 0 {
		t.Fatalf("delete: %s", &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--data-dir", root, "env", "get", created.ID}, &stdout, &stderr); status == 0 || !bytes.Contains(stderr.Bytes(), []byte("not_found")) {
		t.Fatalf("deleted environment still accessible: status %d, %s", status, &stderr)
	}
}

func TestExecNeverFallsBackToHostExecution(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"exec", "anything"}, &stdout, &stderr); status == 0 {
		t.Fatal("unimplemented execution reported success")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("not_implemented")) || stdout.Len() != 0 {
		t.Fatalf("unexpected response: %s %s", &stdout, &stderr)
	}
}
