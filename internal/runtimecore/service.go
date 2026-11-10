// Package runtimecore manages persistent environments, files, and execution
// records. It never executes a host command. One trusted manager must own each
// data directory; there is no cross-process lock or hostile-code boundary.
package runtimecore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"sucrune/internal/environment"
)

const (
	MaxFileBytes     = 1 << 20
	MaxImportBytes   = 256 << 20
	MaxOutputBytes   = 64 << 10
	MaxRequestBytes  = 4 << 20
	MaxMetadataBytes = 256 << 10
)

type request struct {
	Op                    string          `json:"op"`
	Name                  string          `json:"name,omitempty"`
	EnvID                 string          `json:"env_id,omitempty"`
	PurgeExecutionHistory bool            `json:"purge_execution_history,omitempty"`
	Path                  string          `json:"path,omitempty"`
	ContentBase64         string          `json:"content_base64,omitempty"`
	ImportID              string          `json:"import_id,omitempty"`
	Size                  *int64          `json:"size,omitempty"`
	SHA256                string          `json:"sha256,omitempty"`
	Executable            bool            `json:"executable,omitempty"`
	ExecutionID           string          `json:"execution_id,omitempty"`
	State                 string          `json:"state,omitempty"`
	ExitCode              *int            `json:"exit_code,omitempty"`
	Stdout                string          `json:"stdout,omitempty"`
	Stderr                string          `json:"stderr,omitempty"`
	Truncated             bool            `json:"truncated,omitempty"`
	Request               json.RawMessage `json:"request,omitempty"`
	Result                json.RawMessage `json:"result,omitempty"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string        { return e.Message }
func problem(code, message string) error { return &apiError{code, message} }

// Service serializes calls, including active-execution checks and commits.
// Open is a manager restart boundary: old running records become lost. Do not
// open a second live Service on the same directory. The C bridge uses the
// process-wide SharedCallJSON cache instead.
// Active state is a manager-owned index, not a recurring audit of terminal
// history. Open and exec.get/list still validate persisted execution records;
// env.get/list do not detect external edits to old records during this lifetime.
type Service struct {
	mu                    sync.Mutex
	catalog               *environment.Catalog
	root                  string
	activeExecutions      map[string]executionCounts
	activeExecutionsValid bool
	executionStorage      executionStorage
}

func Open(dataDir string) (*Service, error) {
	root, err := prepareRoot(dataDir)
	if err != nil {
		return nil, err
	}
	catalog, err := environment.Open(root)
	if err != nil {
		return nil, err
	}
	executions := filepath.Join(root, "executions")
	if err := os.MkdirAll(executions, 0700); err != nil {
		return nil, err
	}
	if err := realDirectory(executions); err != nil {
		return nil, err
	}
	imports := filepath.Join(root, "imports")
	if err := os.MkdirAll(imports, 0700); err != nil {
		return nil, err
	}
	if err := realDirectory(imports); err != nil {
		return nil, err
	}
	service := &Service{catalog: catalog, root: root,
		executionStorage: executionStorage{write: atomicWrite, publish: publishExecutionDirectory}}
	records, err := service.listExecutions("")
	if err != nil {
		return nil, err
	}
	service.indexActiveExecutions(records)
	for _, record := range records {
		if record.State == "running" {
			_, err = service.finishExecution(request{
				ExecutionID: record.ExecutionID, State: "lost",
				Result: json.RawMessage(`{"reason":"manager_restarted","process_resumed":false}`),
			})
			if err != nil {
				return nil, fmt.Errorf("recover execution: %w", err)
			}
		}
	}
	return service, nil
}

func prepareRoot(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", problem("invalid_arguments", "an explicit data directory is required")
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	if err := realDirectory(root); err != nil {
		return "", err
	}
	// Resolve ancestor aliases so repeated bridge calls share one catalog.
	return filepath.EvalSymlinks(root)
}

// CallJSON accepts one bounded JSON object and always returns a JSON envelope.
// exec.create allocates a running record; Android must start/monitor the worker
// and call exec.finish after it has stopped. No process is started by Go.
func (s *Service) CallJSON(input []byte) []byte {
	if len(input) > MaxRequestBytes {
		return ErrorJSON(problem("too_large", "request exceeds 4 MiB"))
	}
	var req request
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return ErrorJSON(problem("invalid_request", err.Error()))
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrorJSON(problem("invalid_request", "expected one JSON object"))
	}
	if req.Op == "" {
		return ErrorJSON(problem("invalid_request", "op is required"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.call(req)
	if err != nil {
		return ErrorJSON(err)
	}
	output, err := json.Marshal(struct {
		OK     bool `json:"ok"`
		Result any  `json:"result"`
	}{true, result})
	if err != nil {
		return ErrorJSON(err)
	}
	return output
}

func (s *Service) call(req request) (any, error) {
	switch req.Op {
	case "env.create":
		env, err := s.catalog.Create(req.Name, "")
		if err != nil {
			return nil, err
		}
		paths, err := s.catalog.Paths(env.ID)
		if err != nil {
			return nil, err
		}
		if err := syncDirectory(paths.Environment); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Dir(paths.Environment)); err != nil {
			return nil, err
		}
		return env, nil
	case "env.get":
		env, err := s.catalog.Get(req.EnvID)
		if err != nil {
			return nil, err
		}
		active, err := s.hasActive(req.EnvID)
		if active {
			env.State = "running"
		}
		return env, err
	case "env.list":
		envs, err := s.catalog.List()
		if err != nil {
			return nil, err
		}
		if err := s.ensureActiveExecutions(); err != nil {
			return nil, err
		}
		for i := range envs {
			if _, active := s.activeExecutions[envs[i].ID]; active {
				envs[i].State = "running"
			}
		}
		return envs, nil
	case "env.paths":
		return s.catalog.Paths(req.EnvID)
	case "env.delete":
		active, err := s.hasActive(req.EnvID)
		if err != nil {
			return nil, err
		}
		if active {
			return nil, problem("conflict", "environment has an active execution")
		}
		if req.PurgeExecutionHistory {
			if _, err := s.catalog.Get(req.EnvID); err != nil && !errors.Is(err, environment.ErrNotFound) {
				return nil, err
			}
			if err := s.purgeExecutionHistory(req.EnvID); err != nil {
				return nil, err
			}
		}
		if err := s.catalog.Delete(req.EnvID); err != nil && !(req.PurgeExecutionHistory && errors.Is(err, environment.ErrNotFound)) {
			return nil, err
		}
		if err := syncDirectory(filepath.Join(s.root, "environments")); err != nil {
			return nil, err
		}
		return map[string]any{"env_id": req.EnvID, "deleted": true}, nil
	case "file.write", "file.read", "file.mkdir", "file.list":
		return s.fileCall(req)
	case "file.import":
		return s.importFile(req)
	case "exec.create":
		return s.createExecution(req)
	case "exec.finish":
		return s.finishExecution(req)
	case "exec.get":
		return s.getExecution(req.ExecutionID)
	case "exec.list":
		// Historical execution records remain queryable after env.delete.
		if req.EnvID != "" && !environmentID.MatchString(req.EnvID) {
			return nil, environment.ErrInvalidID
		}
		return s.listExecutions(req.EnvID)
	default:
		return nil, problem("unsupported_operation", "unknown operation: "+req.Op)
	}
}

// ErrorJSON is also used by the bridge for startup/argument errors.
func ErrorJSON(err error) []byte {
	api := &apiError{Code: "storage_error", Message: err.Error()}
	var explicit *apiError
	switch {
	case errors.As(err, &explicit):
		api = explicit
	case errors.Is(err, environment.ErrInvalidID), errors.Is(err, environment.ErrInvalidName):
		api.Code = "invalid_arguments"
	case errors.Is(err, environment.ErrNotFound), errors.Is(err, os.ErrNotExist):
		api.Code = "not_found"
	case errors.Is(err, environment.ErrUnsafePath):
		api.Code = "unsafe_path"
	case errors.Is(err, environment.ErrCorrupt):
		api.Code = "corrupt_metadata"
	}
	output, _ := json.Marshal(struct {
		OK    bool      `json:"ok"`
		Error *apiError `json:"error"`
	}{false, api})
	return output
}

var shared = struct {
	sync.Mutex
	services map[string]*Service
}{services: make(map[string]*Service)}

// SharedCallJSON reuses one Service per canonical data directory in this
// process, including requests from concurrent JNI calls. The cache deliberately
// lives until manager-process exit; there is no reset that could lose ownership.
func SharedCallJSON(dataDir string, input []byte) []byte {
	service, err := sharedService(dataDir)
	if err != nil {
		return ErrorJSON(err)
	}
	return service.CallJSON(input)
}

func sharedService(dataDir string) (*Service, error) {
	shared.Lock()
	defer shared.Unlock()
	root, err := prepareRoot(dataDir)
	if err != nil {
		return nil, err
	}
	key := root
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	if service := shared.services[key]; service != nil {
		return service, nil
	}
	service, err := Open(root)
	if err != nil {
		return nil, err
	}
	shared.services[key] = service
	return service, nil
}

func realDirectory(path string) error {
	stat, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if stat.Mode()&os.ModeSymlink != 0 || !stat.IsDir() {
		return problem("unsafe_path", "expected a real directory: "+path)
	}
	return nil
}
