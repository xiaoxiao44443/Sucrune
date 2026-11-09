package runtimecore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sucrune/internal/environment"
	"sucrune/internal/storagefs"
)

func assertActiveState(t *testing.T, service *Service, envID string, active bool) {
	t.Helper()
	env := success[environment.Environment](t, call(t, service, map[string]any{"op": "env.get", "env_id": envID}))
	if (env.State == "running") != active {
		t.Fatalf("environment %s active=%v, state=%s", envID, active, env.State)
	}
	listed := success[[]environment.Environment](t, call(t, service, map[string]any{"op": "env.list"}))
	for _, item := range listed {
		if item.ID == envID {
			if item.State != env.State {
				t.Fatalf("get/list disagree: %s / %s", env.State, item.State)
			}
			return
		}
	}
	t.Fatal("environment missing from list")
}

func TestActiveIndexCreatePublicationFailures(t *testing.T) {
	for _, phase := range []string{"initial_write", "before_rename", "after_rename"} {
		t.Run(phase, func(t *testing.T) {
			service := openTestService(t, t.TempDir())
			env := createTestEnvironment(t, service, "failed-create")
			original := service.executionStorage
			injected := errors.New("injected execution commit error")
			if phase == "initial_write" {
				service.executionStorage.write = func(string, []byte) error { return injected }
			} else {
				service.executionStorage.publish = func(stage, destination string) error {
					if phase == "after_rename" {
						if err := storagefs.RenameDirectory(stage, destination); err != nil {
							return err
						}
					}
					return injected
				}
			}
			response := call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID})
			failure(t, response, "storage_error")
			if response.Error.Message != injected.Error() {
				t.Fatalf("expected the injected %s error, got %v", phase, response.Error)
			}
			service.executionStorage = original
			published := phase == "after_rename"
			assertActiveState(t, service, env.ID, published)
			history := success[[]Execution](t, call(t, service, map[string]any{"op": "exec.list"}))
			if published {
				if len(history) != 1 || history[0].State != "running" {
					t.Fatalf("visible commit lost: %+v", history)
				}
				failure(t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}), "conflict")
				failure(t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}), "conflict")
				success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": history[0].ExecutionID, "state": "lost"}))
			} else if len(history) != 0 {
				t.Fatalf("failed unpublished record escaped: %+v", history)
			}
			assertActiveState(t, service, env.ID, false)
			success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}))
			entries, err := os.ReadDir(filepath.Join(service.root, "executions"))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !executionID.MatchString(entry.Name()) {
					t.Fatalf("unpublished staging leaked: %s", entry.Name())
				}
			}
		})
	}
}

func TestActiveIndexFinishFailuresPreserveOtherEnvironments(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprintf("published_%v", published), func(t *testing.T) {
			service := openTestService(t, t.TempDir())
			first := createTestEnvironment(t, service, "first")
			second := createTestEnvironment(t, service, "second")
			one := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": first.ID}))
			two := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": second.ID}))
			original := service.executionStorage.write
			service.executionStorage.write = func(path string, data []byte) error {
				if published {
					if err := original(path, data); err != nil {
						return err
					}
				}
				return errors.New("injected terminal publication error")
			}
			finish := map[string]any{"op": "exec.finish", "execution_id": one.ExecutionID, "state": "exited", "exit_code": 7}
			failure(t, call(t, service, finish), "storage_error")
			service.executionStorage.write = original
			assertActiveState(t, service, first.ID, !published)
			assertActiveState(t, service, second.ID, true)
			_, hash := stageImport(t, service, []byte("x"))
			failure(t, call(t, service, importRequest(second.ID, "/blocked", 1, hash)), "conflict")
			if published {
				failure(t, call(t, service, finish), "conflict")
			} else {
				failure(t, call(t, service, map[string]any{"op": "exec.create", "env_id": first.ID}), "conflict")
				success[Execution](t, call(t, service, finish))
			}
			assertActiveState(t, service, first.ID, false)
			success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": first.ID}))
			success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": two.ExecutionID, "state": "cancelled"}))
			assertActiveState(t, service, second.ID, false)
		})
	}
}

func TestUncertainCommitWithCorruptMetadataFailsClosedAndCanRecover(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "uncertain")
	record := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}))
	original := service.executionStorage.write
	service.executionStorage.write = func(path string, _ []byte) error {
		if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
			return err
		}
		return errors.New("injected corrupt storage")
	}
	failure(t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "lost"}), "storage_error")
	service.executionStorage.write = original
	for _, op := range []string{"env.get", "env.list", "env.delete", "exec.create"} {
		failure(t, call(t, service, map[string]any{"op": op, "env_id": env.ID}), "corrupt_metadata")
	}
	if err := os.Remove(filepath.Join(service.root, "executions", record.ExecutionID, "terminal.json")); err != nil {
		t.Fatal(err)
	}
	assertActiveState(t, service, env.ID, true)
	success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "lost"}))
	assertActiveState(t, service, env.ID, false)
}

func TestActiveQueriesDoNotRescanTerminalHistoryButHistoryQueriesValidate(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "history")
	record := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}))
	success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "cancelled"}))
	// Simulate an unsupported external edit after commit. It must still be
	// rejected by explicit historical reads and restart, without putting an
	// O(history) audit back into every environment/import operation.
	if err := os.WriteFile(filepath.Join(root, "executions", record.ExecutionID, "terminal.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	assertActiveState(t, service, env.ID, false)
	_, hash := stageImport(t, service, []byte("x"))
	success[any](t, call(t, service, importRequest(env.ID, "/imported", 1, hash)))
	next := success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID}))
	assertActiveState(t, service, env.ID, true)
	success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": next.ExecutionID, "state": "lost"}))
	success[any](t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}))
	failure(t, call(t, service, map[string]any{"op": "exec.get", "execution_id": record.ExecutionID}), "corrupt_metadata")
	failure(t, call(t, service, map[string]any{"op": "exec.list"}), "corrupt_metadata")
	failure(t, call(t, service, map[string]any{"op": "exec.list", "env_id": "env_00000000000000000000000000000000"}), "corrupt_metadata")
	if _, err := Open(root); err == nil {
		t.Fatal("restart ignored corrupt terminal history")
	}
}

func TestActiveIndexRestartRecoversEveryEnvironment(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	var records []Execution
	for _, name := range []string{"one", "two", "three"} {
		env := createTestEnvironment(t, service, name)
		records = append(records, success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID})))
	}
	service = openTestService(t, root) // old manager has stopped
	for _, record := range records {
		assertActiveState(t, service, record.EnvID, false)
		recovered := success[Execution](t, call(t, service, map[string]any{"op": "exec.get", "execution_id": record.ExecutionID}))
		if recovered.State != "lost" {
			t.Fatalf("running record not recovered: %+v", recovered)
		}
		success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": record.EnvID}))
	}
}

func TestResidentExecutionSharesProjectAndRetainsOwnership(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "shared-workspace")
	ordinary := map[string]any{"op": "exec.create", "env_id": env.ID}
	resident := map[string]any{"op": "exec.create", "env_id": env.ID, "request": map[string]any{"kind": "linux", "resident": true}}
	serviceA := success[Execution](t, call(t, service, resident))
	command := success[Execution](t, call(t, service, ordinary))
	serviceB := success[Execution](t, call(t, service, resident))
	// Rebuild the index exactly as after an uncertain durable publication.
	service.activeExecutionsValid = false
	failure(t, call(t, service, ordinary), "conflict")
	finish := func(record Execution) {
		success[Execution](t, call(t, service, map[string]any{"op": "exec.finish", "execution_id": record.ExecutionID, "state": "cancelled"}))
	}
	finish(command)
	finish(serviceA)
	assertActiveState(t, service, env.ID, true)
	failure(t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}), "conflict")
	finish(success[Execution](t, call(t, service, ordinary)))
	finish(serviceB)
	assertActiveState(t, service, env.ID, false)
	success[any](t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}))
}

func BenchmarkEnvironmentGetWithHistory(b *testing.B) {
	for _, count := range []int{0, 1000} {
		b.Run(fmt.Sprintf("records_%d", count), func(b *testing.B) {
			root := b.TempDir()
			service, err := Open(root)
			if err != nil {
				b.Fatal(err)
			}
			env, err := service.catalog.Create("benchmark", "")
			if err != nil {
				b.Fatal(err)
			}
			now, zero := time.Now().UTC(), 0
			for i := 0; i < count; i++ {
				record := Execution{SchemaVersion: 1, ExecutionID: fmt.Sprintf("exec_%032x", i), EnvID: env.ID, State: "running", CreatedAt: now}
				directory := filepath.Join(root, "executions", record.ExecutionID)
				if err := os.Mkdir(directory, 0700); err != nil {
					b.Fatal(err)
				}
				for _, name := range []string{"initial.json", "terminal.json"} {
					if name == "terminal.json" {
						record.State, record.FinishedAt, record.ExitCode = "exited", &now, &zero
					}
					data, err := json.Marshal(record)
					if err != nil {
						b.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
						b.Fatal(err)
					}
				}
			}
			service, err = Open(root) // startup validates all benchmark fixtures
			if err != nil {
				b.Fatal(err)
			}
			input := []byte(fmt.Sprintf(`{"op":"env.get","env_id":%q}`, env.ID))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !bytes.Contains(service.CallJSON(input), []byte(`"ok":true`)) {
					b.Fatal("env.get failed")
				}
			}
		})
	}
}
