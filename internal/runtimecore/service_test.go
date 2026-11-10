package runtimecore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"sucrune/internal/environment"
)

type testEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  *apiError       `json:"error"`
}

func call(t *testing.T, service *Service, req map[string]any) testEnvelope {
	t.Helper()
	input, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var response testEnvelope
	if err := json.Unmarshal(service.CallJSON(input), &response); err != nil {
		t.Fatal(err)
	}
	if response.OK == (response.Error != nil) {
		t.Fatalf("invalid envelope: %#v", response)
	}
	return response
}

func success[T any](t *testing.T, response testEnvelope) T {
	t.Helper()
	if !response.OK {
		t.Fatalf("request failed: %+v", response.Error)
	}
	var result T
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func failure(t *testing.T, response testEnvelope, code string) {
	t.Helper()
	if response.OK || response.Error == nil || response.Error.Code != code {
		t.Fatalf("want %s error, got %+v", code, response)
	}
}

func openTestService(t *testing.T, root string) *Service {
	t.Helper()
	service, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func createTestEnvironment(t *testing.T, service *Service, name string) environment.Environment {
	t.Helper()
	return success[environment.Environment](t, call(t, service, map[string]any{"op": "env.create", "name": name}))
}

func TestFilesPersistBinaryContentAndRemainEnvironmentRelative(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	first := createTestEnvironment(t, service, "first")
	second := createTestEnvironment(t, service, "second")
	success[any](t, call(t, service, map[string]any{"op": "file.mkdir", "env_id": first.ID, "path": "/nested/deep"}))
	content := []byte{0, 1, 255, '\n', 0x80}
	encoded := base64.StdEncoding.EncodeToString(content)
	success[any](t, call(t, service, map[string]any{"op": "file.write", "env_id": first.ID, "path": "nested/deep/data.bin", "content_base64": encoded}))
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": second.ID, "path": "/nested/deep/data.bin"}), "not_found")
	// A new manager sees the exact content, not just catalog metadata.
	service = openTestService(t, root)
	result := success[struct {
		Path    string `json:"path"`
		Content string `json:"content_base64"`
		Size    int    `json:"size"`
	}](t, call(t, service, map[string]any{"op": "file.read", "env_id": first.ID, "path": "/nested/deep/data.bin"}))
	if result.Content != encoded || result.Size != len(content) || result.Path != "/nested/deep/data.bin" {
		t.Fatalf("bad read: %+v", result)
	}
	list := success[struct {
		Entries []FileEntry `json:"entries"`
	}](t, call(t, service, map[string]any{"op": "file.list", "env_id": first.ID, "path": "/nested/deep"}))
	if len(list.Entries) != 1 || list.Entries[0].Name != "data.bin" || list.Entries[0].Kind != "file" {
		t.Fatalf("bad listing: %+v", list)
	}
	success[any](t, call(t, service, map[string]any{"op": "file.list", "env_id": first.ID, "path": "/"}))
	// Replacement is committed as a complete new file.
	success[any](t, call(t, service, map[string]any{"op": "file.write", "env_id": first.ID, "path": "/nested/deep/data.bin", "content_base64": ""}))
	read := success[map[string]any](t, call(t, service, map[string]any{"op": "file.read", "env_id": first.ID, "path": "nested/deep/data.bin"}))
	if read["content_base64"] != "" {
		t.Fatal("empty replacement was not persisted")
	}
}

func TestFilePathsRejectEscapesAndAmbiguousHostNames(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "paths")
	for _, path := range []string{"../outside", "/a/../outside", `a\b`, "C:/outside", "/file:stream", "\x00bad", "/AUX", "trailing.", "trailing ", strings.Repeat("x", 256)} {
		failure(t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID, "path": path, "content_base64": "eA=="}), "unsafe_path")
	}
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": "../outside", "path": "x"}), "invalid_arguments")
	failure(t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID, "path": "/"}), "invalid_arguments")
	failure(t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID, "path": "missing/file"}), "not_found")
}

func TestSymlinksCannotBeReadWrittenListedOrTraversed(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "links")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(paths.Workspace, "link")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	for _, req := range []map[string]any{
		{"op": "file.read", "path": "link/sentinel"},
		{"op": "file.write", "path": "link/sentinel", "content_base64": "eA=="},
		{"op": "file.mkdir", "path": "link/new"},
		{"op": "file.list", "path": "/"},
	} {
		req["env_id"] = env.ID
		failure(t, call(t, service, req), "unsafe_path")
	}
	if err := os.Symlink(sentinel, filepath.Join(paths.Workspace, "filelink")); err != nil {
		t.Fatal(err)
	}
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": "filelink"}), "unsafe_path")
	actual, err := os.ReadFile(sentinel)
	if err != nil || string(actual) != "unchanged" {
		t.Fatalf("outside file changed: %q %v", actual, err)
	}
}

func TestFileSizeLimitsAndInvalidBase64(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "bounds")
	maximum := strings.Repeat("x", MaxFileBytes)
	success[any](t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID, "path": "max", "content_base64": base64.StdEncoding.EncodeToString([]byte(maximum))}))
	result := success[map[string]any](t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": "max"}))
	if result["size"] != float64(MaxFileBytes) {
		t.Fatalf("bad maximum read: %v", result["size"])
	}
	failure(t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID, "path": "max", "content_base64": base64.StdEncoding.EncodeToString([]byte(maximum + "x"))}), "too_large")
	failure(t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID, "path": "max", "content_base64": "not base64!"}), "invalid_arguments")
	paths, _ := service.catalog.Paths(env.ID)
	if err := os.WriteFile(filepath.Join(paths.Workspace, "large"), []byte(maximum+"x"), 0600); err != nil {
		t.Fatal(err)
	}
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": "large"}), "too_large")
}

func TestExecutionActiveGuardTerminalImmutabilityAndHistory(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "execute")
	record := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID, "request": map[string]any{"command": "echo hello", "cwd": "/"}}))
	if !executionID.MatchString(record.ExecutionID) || record.State != "running" {
		t.Fatalf("bad running record: %+v", record)
	}
	failure(t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}), "conflict")
	failure(t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}), "conflict")
	active := success[environment.Environment](t, call(t, service, map[string]any{"op": "env.get", "env_id": env.ID}))
	if active.State != "running" {
		t.Fatal("active environment reported stopped")
	}
	failure(t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "running"}), "invalid_arguments")
	failure(t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "exited"}), "invalid_arguments")
	final := success[Execution](t, call(t, service, map[string]any{
		"op": "exec.finish", "execution_id": record.ExecutionID, "state": "exited", "exit_code": 42,
		"stdout": strings.Repeat("字", MaxOutputBytes), "stderr": "error",
		"result": map[string]any{"worker": map[string]any{"uid": 99001}, "binder_dead": true},
	}))
	if final.State != "exited" || final.FinishedAt == nil || *final.ExitCode != 42 || !final.Truncated ||
		len(final.Stdout) > MaxOutputBytes || !utf8.ValidString(final.Stdout) || final.Stderr != "error" {
		t.Fatalf("bad final record: %+v", final)
	}
	failure(t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "cancelled"}), "conflict")
	service = openTestService(t, root)
	persisted := success[Execution](t, call(t, service, map[string]any{"op": "exec.get", "execution_id": record.ExecutionID}))
	if !bytes.Equal(persisted.Result, final.Result) || !bytes.Equal(persisted.Request, final.Request) || persisted.State != "exited" {
		t.Fatal("terminal state or evidence changed across restart")
	}
	success[any](t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}))
	history := success[[]Execution](t, call(t, service, map[string]any{"op": "exec.list", "env_id": env.ID}))
	if len(history) != 1 || history[0].State != "exited" {
		t.Fatalf("history lost: %+v", history)
	}
}

func TestDeleteProjectPurgesOnlyItsTerminalHistoryAndResumesAfterRestart(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	diagnostic := createTestEnvironment(t, service, "diagnostic")
	other := createTestEnvironment(t, service, "normal")
	newRecord := func(envID string) Execution {
		return success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": envID}))
	}
	finish := func(record Execution) {
		success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "exited", "exit_code": 0}))
	}
	foreign := newRecord(other.ID)
	finish(foreign)
	first := newRecord(diagnostic.ID)
	finish(first)
	second := newRecord(diagnostic.ID)
	purge := map[string]any{"op": "env.delete", "env_id": diagnostic.ID, "purge_execution_history": true}
	failure(t, call(t, service, purge), "conflict")
	success[Execution](t, call(t, service, map[string]any{"op": "exec.get", "execution_id": first.ExecutionID}))
	finish(second)
	// Simulate manager death after the first atomic detach. The stage can
	// already be partly erased while every visible record remains readable.
	parent := filepath.Join(root, "executions")
	stage := filepath.Join(parent, ".pending-purge-"+diagnostic.ID)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(parent, first.ExecutionID), filepath.Join(stage, first.ExecutionID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stage, first.ExecutionID, "initial.json")); err != nil {
		t.Fatal(err)
	}
	service = openTestService(t, root)
	success[any](t, call(t, service, purge))
	success[any](t, call(t, service, purge)) // Caller may miss a successful result.
	failure(t, call(t, service, map[string]any{"op": "env.get", "env_id": diagnostic.ID}), "not_found")
	for _, id := range []string{first.ExecutionID, second.ExecutionID} {
		failure(t, call(t, service, map[string]any{"op": "exec.get", "execution_id": id}), "not_found")
	}
	success[Execution](t, call(t, service, map[string]any{"op": "exec.get", "execution_id": foreign.ExecutionID}))
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("purge staging remains: %v", err)
	}
	failure(t, call(t, service, map[string]any{"op": "env.delete", "env_id": "", "purge_execution_history": true}), "invalid_arguments")
}

func TestManagerRestartMarksRunningLostAndAllowsNextExecution(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "restart")
	first := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID, "request": map[string]any{"command": "sleep 5"}}))
	service = openTestService(t, root) // previous manager has stopped
	recovered := success[Execution](t, call(t, service, map[string]any{"op": "exec.get", "execution_id": first.ExecutionID}))
	if recovered.State != "lost" || recovered.ExitCode != nil || recovered.FinishedAt == nil || !bytes.Contains(recovered.Result, []byte(`"process_resumed":false`)) {
		t.Fatalf("incorrect recovery: %+v", recovered)
	}
	second := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}))
	if second.ExecutionID == first.ExecutionID {
		t.Fatal("execution ID reused")
	}
	success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": second.ExecutionID, "state": "timed_out", "truncated": true}))
	service = openTestService(t, root)
	records := success[[]Execution](t, call(t, service, map[string]any{"op": "exec.list"}))
	if len(records) != 2 || records[0].State != "lost" || records[1].State != "timed_out" || !records[1].Truncated {
		t.Fatalf("recovery altered terminal records: %+v", records)
	}
}

func TestConcurrentExecutionCreateAllowsExactlyOneActive(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "concurrent")
	var wg sync.WaitGroup
	responses := make(chan testEnvelope, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses <- call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID})
		}()
	}
	wg.Wait()
	close(responses)
	count := 0
	for response := range responses {
		if response.OK {
			count++
		} else {
			failure(t, response, "conflict")
		}
	}
	if count != 1 {
		t.Fatalf("%d active executions accepted", count)
	}
}

func TestSharedBridgeKeepsLiveExecutionAcrossCallsAndPathAliases(t *testing.T) {
	root := t.TempDir()
	makeCall := func(req map[string]any, path string) testEnvelope {
		input, _ := json.Marshal(req)
		var response testEnvelope
		if err := json.Unmarshal(SharedCallJSON(path, input), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	env := success[environment.Environment](t, makeCall(map[string]any{"op": "env.create", "name": "shared"}, root))
	record := success[Execution](t, makeCall(map[string]any{"op": "exec.create", "env_id": env.ID}, filepath.Join(root, ".")))
	loaded := success[Execution](t, makeCall(map[string]any{"op": "exec.get", "execution_id": record.ExecutionID}, root))
	if loaded.State != "running" {
		t.Fatal("repeated bridge call falsely recovered active execution")
	}
	failure(t, makeCall(map[string]any{"op": "exec.create", "env_id": env.ID}, root), "conflict")
}

func TestProtocolRejectsMalformedAndOversizedRequests(t *testing.T) {
	service := openTestService(t, t.TempDir())
	for _, input := range []string{`null`, `[]`, `{}`, `{"op":"env.list","extra":true}`, `{"op":"env.list"}{}`, `{`} {
		var response testEnvelope
		if err := json.Unmarshal(service.CallJSON([]byte(input)), &response); err != nil {
			t.Fatal(err)
		}
		failure(t, response, "invalid_request")
	}
	failure(t, call(t, service, map[string]any{"op": "host.exec"}), "unsupported_operation")
	env := createTestEnvironment(t, service, "metadata")
	failure(t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID, "request": []string{"bad"}}), "invalid_arguments")
	failure(t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID, "request": map[string]string{"large": strings.Repeat("x", MaxMetadataBytes)}}), "too_large")
	var response testEnvelope
	if err := json.Unmarshal(service.CallJSON(bytes.Repeat([]byte(" "), MaxRequestBytes+1)), &response); err != nil {
		t.Fatal(err)
	}
	failure(t, response, "too_large")
}

func TestRecoveryRejectsCorruptTerminalAndIgnoresUnpublishedStaging(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "corruption")
	record := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}))
	if err := os.Mkdir(filepath.Join(root, "executions", ".pending-incomplete"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "executions", record.ExecutionID, "terminal.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("corrupt terminal record silently discarded")
	}
	if err := os.Remove(filepath.Join(root, "executions", record.ExecutionID, "terminal.json")); err != nil {
		t.Fatal(err)
	}
	service = openTestService(t, root)
	recovered := success[Execution](t, call(t, service, map[string]any{"op": "exec.get", "execution_id": record.ExecutionID}))
	if recovered.State != "lost" {
		t.Fatal("incomplete staging prevented recovery")
	}
}

func TestFailedAtomicPublishLeavesDestinationAndRemovesTemporaryFile(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(destination, "sentinel")
	if err := os.WriteFile(sentinel, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(destination, []byte("replacement")); err == nil {
		t.Fatal("file replaced directory")
	}
	content, err := os.ReadFile(sentinel)
	if err != nil || string(content) != "original" {
		t.Fatalf("failed publication damaged destination: %q %v", content, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file leaked: %v %v", entries, err)
	}
}
