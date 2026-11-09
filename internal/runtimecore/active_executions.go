package runtimecore

import (
	"encoding/json"
	"path/filepath"

	"sucrune/internal/storagefs"
)

// Execution persistence has two publication boundaries. Keeping the operations
// per Service also permits deterministic pre/post-publication I/O failure tests
// without global hooks or changing other managers' storage behavior.
type executionStorage struct {
	write   func(path string, data []byte) error
	publish func(stage, destination string) error
}

func publishExecutionDirectory(stage, destination string) error {
	if err := storagefs.RenameDirectory(stage, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

type executionCounts struct {
	ordinary int
	resident int
}

// Legacy requests carry arbitrary metadata. Only an explicit Linux resident
// request gets a separate slot; missing or unrecognized values stay ordinary.
func isResidentExecution(request json.RawMessage) bool {
	var options struct {
		Kind     string `json:"kind"`
		Resident bool   `json:"resident"`
	}
	return len(request) > 0 && json.Unmarshal(request, &options) == nil && options.Kind == "linux" && options.Resident
}

// Called under Service.mu or during unpublished Open.
func (s *Service) countExecution(record Execution, delta int) {
	counts := s.activeExecutions[record.EnvID]
	if isResidentExecution(record.Request) {
		counts.resident += delta
	} else {
		counts.ordinary += delta
	}
	if counts == (executionCounts{}) {
		delete(s.activeExecutions, record.EnvID)
	} else {
		s.activeExecutions[record.EnvID] = counts
	}
}

func (s *Service) indexActiveExecutions(records []Execution) {
	s.activeExecutions = make(map[string]executionCounts)
	for _, record := range records {
		if record.State == "running" {
			s.countExecution(record, 1)
		}
	}
	s.activeExecutionsValid = true
}

// Normal guards are O(1) and retain only active environment IDs. A persistence
// error can mean a rename succeeded but directory sync failed. In that exceptional
// case, rebuild once from validated, visible records; retain the invalid state on
// read failure so an uncertain commit can never silently release an environment.
// This is reconciliation, not restart: running records must not become lost.
func (s *Service) ensureActiveExecutions() error {
	if s.activeExecutionsValid {
		return nil
	}
	records, err := s.listExecutions("")
	if err != nil {
		return err
	}
	s.indexActiveExecutions(records)
	return nil
}
