package runtimecore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"sucrune/internal/storagefs"
)

var (
	executionID   = regexp.MustCompile(`^exec_[0-9a-f]{32}$`)
	environmentID = regexp.MustCompile(`^env_[0-9a-f]{32}$`)
)

type Execution struct {
	SchemaVersion int             `json:"schema_version"`
	ExecutionID   string          `json:"execution_id"`
	EnvID         string          `json:"env_id"`
	State         string          `json:"state"`
	CreatedAt     time.Time       `json:"created_at"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	ExitCode      *int            `json:"exit_code,omitempty"`
	Stdout        string          `json:"stdout"`
	Stderr        string          `json:"stderr"`
	Truncated     bool            `json:"truncated"`
	Request       json.RawMessage `json:"request,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
}

func (s *Service) createExecution(req request) (Execution, error) {
	if _, err := s.catalog.Get(req.EnvID); err != nil {
		return Execution{}, err
	}
	if err := validateObject(req.Request); err != nil {
		return Execution{}, err
	}
	if err := s.ensureActiveExecutions(); err != nil {
		return Execution{}, err
	}
	if s.activeExecutions[req.EnvID].ordinary > 0 && !isResidentExecution(req.Request) {
		return Execution{}, problem("conflict", "environment already has an active ordinary execution")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Execution{}, err
	}
	record := Execution{
		SchemaVersion: 1, ExecutionID: "exec_" + hex.EncodeToString(random[:]),
		EnvID: req.EnvID, State: "running", CreatedAt: time.Now().UTC(),
		Request: req.Request,
	}
	parent, err := s.executionRoot()
	if err != nil {
		return Execution{}, err
	}
	stage, err := os.MkdirTemp(parent, ".pending-")
	if err != nil {
		return Execution{}, err
	}
	defer os.RemoveAll(stage)
	data, err := json.Marshal(record)
	if err != nil {
		return Execution{}, err
	}
	if err := s.executionStorage.write(filepath.Join(stage, "initial.json"), data); err != nil {
		return Execution{}, err
	}
	destination := filepath.Join(parent, record.ExecutionID)
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return Execution{}, problem("storage_error", "execution ID collision or inaccessible destination")
	}
	if err := s.executionStorage.publish(stage, destination); err != nil {
		// A directory-sync failure can follow a successful rename. Reconcile
		// visible metadata before any subsequent guard; never assume no record.
		s.activeExecutionsValid = false
		return Execution{}, err
	}
	s.countExecution(record, 1)
	return record, nil
}

func (s *Service) finishExecution(req request) (Execution, error) {
	record, err := s.getExecution(req.ExecutionID)
	if err != nil {
		return Execution{}, err
	}
	if record.State != "running" {
		return Execution{}, problem("conflict", "execution is already terminal")
	}
	if !terminalState(req.State) {
		return Execution{}, problem("invalid_arguments", "finish state must be exited, cancelled, timed_out or lost")
	}
	if req.State == "exited" && req.ExitCode == nil {
		return Execution{}, problem("invalid_arguments", "exited requires exit_code")
	}
	if err := validateObject(req.Result); err != nil {
		return Execution{}, err
	}
	now := time.Now().UTC()
	record.State, record.FinishedAt, record.ExitCode = req.State, &now, req.ExitCode
	record.Stdout, record.Stderr = clipOutput(req.Stdout), clipOutput(req.Stderr)
	record.Truncated = req.Truncated || record.Stdout != req.Stdout || record.Stderr != req.Stderr
	record.Result = req.Result
	data, err := json.Marshal(record)
	if err != nil {
		return Execution{}, err
	}
	// A separate immutable terminal file avoids overwriting the initial record.
	// Readers see either the complete running record or the complete terminal
	// record after a same-directory rename; incomplete temp files are ignored.
	parent, err := s.executionRoot()
	if err != nil {
		return Execution{}, err
	}
	if err := s.executionStorage.write(filepath.Join(parent, record.ExecutionID, "terminal.json"), data); err != nil {
		// The terminal file may already be visible even when directory sync
		// fails. A later guard repairs the index from complete records once.
		s.activeExecutionsValid = false
		return Execution{}, err
	}
	if s.activeExecutionsValid {
		s.countExecution(record, -1)
	}
	return record, nil
}

func clipOutput(text string) string {
	if len(text) <= MaxOutputBytes {
		return text
	}
	end := MaxOutputBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

func validateObject(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > MaxMetadataBytes {
		return problem("too_large", "request/result metadata exceeds 256 KiB")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' || !json.Valid(raw) {
		return problem("invalid_arguments", "request/result metadata must be a JSON object")
	}
	return nil
}

func terminalState(state string) bool {
	return state == "exited" || state == "cancelled" || state == "timed_out" || state == "lost"
}

func (s *Service) executionRoot() (string, error) {
	if err := realDirectory(s.root); err != nil {
		return "", err
	}
	root := filepath.Join(s.root, "executions")
	if err := realDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}

func (s *Service) getExecution(id string) (Execution, error) {
	if !executionID.MatchString(id) {
		return Execution{}, problem("invalid_arguments", "invalid execution ID")
	}
	parent, err := s.executionRoot()
	if err != nil {
		return Execution{}, err
	}
	directory := filepath.Join(parent, id)
	if err := realDirectory(directory); err != nil {
		return Execution{}, err
	}
	initial, err := readExecution(filepath.Join(directory, "initial.json"), id)
	if err != nil {
		return Execution{}, err
	}
	if initial.State != "running" || initial.FinishedAt != nil || initial.ExitCode != nil || initial.Result != nil || initial.Stdout != "" || initial.Stderr != "" || initial.Truncated {
		return Execution{}, problem("corrupt_metadata", "initial execution record is not running")
	}
	final, err := readExecution(filepath.Join(directory, "terminal.json"), id)
	if errors.Is(err, os.ErrNotExist) {
		return initial, nil
	}
	if err != nil {
		return Execution{}, err
	}
	if !terminalState(final.State) || final.FinishedAt == nil || final.FinishedAt.IsZero() || final.EnvID != initial.EnvID || !final.CreatedAt.Equal(initial.CreatedAt) || !bytes.Equal(final.Request, initial.Request) {
		return Execution{}, problem("corrupt_metadata", "inconsistent terminal execution record")
	}
	return final, nil
}

func readExecution(path, id string) (Execution, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Execution{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return Execution{}, problem("corrupt_metadata", "execution record is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Execution{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, (2<<20)+1))
	decoder.DisallowUnknownFields()
	var record Execution
	if err := decoder.Decode(&record); err != nil {
		return Execution{}, problem("corrupt_metadata", "invalid execution JSON: "+err.Error())
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Execution{}, problem("corrupt_metadata", "trailing execution metadata")
	}
	if record.SchemaVersion != 1 || record.ExecutionID != id || !environmentID.MatchString(record.EnvID) || record.CreatedAt.IsZero() || (record.State != "running" && !terminalState(record.State)) || len(record.Stdout) > MaxOutputBytes || len(record.Stderr) > MaxOutputBytes || (record.State == "exited" && record.ExitCode == nil) {
		return Execution{}, problem("corrupt_metadata", "inconsistent execution fields")
	}
	if validateObject(record.Request) != nil || validateObject(record.Result) != nil {
		return Execution{}, problem("corrupt_metadata", "invalid execution metadata object")
	}
	return record, nil
}

func (s *Service) listExecutions(envID string) ([]Execution, error) {
	parent, err := s.executionRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	result := make([]Execution, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		if !executionID.MatchString(entry.Name()) {
			return nil, problem("corrupt_metadata", fmt.Sprintf("unexpected execution entry %q", entry.Name()))
		}
		record, err := s.getExecution(entry.Name())
		if err != nil {
			return nil, err
		}
		if envID == "" || record.EnvID == envID {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ExecutionID < result[j].ExecutionID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *Service) hasActive(envID string) (bool, error) {
	if err := s.ensureActiveExecutions(); err != nil {
		return false, err
	}
	_, active := s.activeExecutions[envID]
	return active, nil
}

// Called under the manager lock. Detach each complete record atomically so a
// partial removal cannot make the execution index unreadable after restart.
func (s *Service) purgeExecutionHistory(envID string) error {
	if !environmentID.MatchString(envID) {
		return problem("invalid_arguments", "invalid environment ID")
	}
	records, err := s.listExecutions(envID)
	if err != nil {
		return err
	}
	for _, record := range records {
		if !terminalState(record.State) {
			return problem("conflict", "environment has an active execution")
		}
	}
	parent, err := s.executionRoot()
	if err != nil {
		return err
	}
	stage := filepath.Join(parent, ".pending-purge-"+envID)
	if len(records) > 0 {
		if err := os.Mkdir(stage, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if err := realDirectory(stage); err != nil {
		if errors.Is(err, os.ErrNotExist) && len(records) == 0 {
			return nil
		}
		return err
	}
	for _, record := range records {
		source := filepath.Join(parent, record.ExecutionID)
		if err := storagefs.RenameDirectory(source, filepath.Join(stage, record.ExecutionID)); err != nil {
			return err
		}
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	return syncDirectory(parent)
}
