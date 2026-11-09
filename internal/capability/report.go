// Package capability describes observed host capabilities. An unknown result is
// deliberately different from success: the Android probe must supply evidence.
package capability

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
)

const SchemaVersion = 1

type Status string

const (
	Supported   Status = "supported"
	Unsupported Status = "unsupported"
	Unknown     Status = "unknown"
)

type Evidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}

type Feature struct {
	Status   Status     `json:"status"`
	Reason   string     `json:"reason"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

type Host struct {
	OS                string `json:"os"`
	Architecture      string `json:"architecture"`
	PageSize          int    `json:"page_size"`
	AndroidAPI        *int   `json:"android_api,omitempty"`
	TargetSDK         *int   `json:"target_sdk,omitempty"`
	KernelRelease     string `json:"kernel_release,omitempty"`
	ExecutionIdentity string `json:"execution_identity"`
}

type Report struct {
	SchemaVersion  int                `json:"schema_version"`
	RuntimeVersion string             `json:"runtime_version"`
	ObservedAt     time.Time          `json:"observed_at"`
	Host           Host               `json:"host"`
	Features       map[string]Feature `json:"features"`
}

// NewHostReport reports only what this development CLI implements or observes.
// It does not infer Android permissions from a version or host architecture.
func NewHostReport(version string, now time.Time) Report {
	return Report{
		SchemaVersion: SchemaVersion, RuntimeVersion: version, ObservedAt: now.UTC(),
		Host: Host{
			OS: runtime.GOOS, Architecture: runtime.GOARCH,
			PageSize: os.Getpagesize(), ExecutionIdentity: "development_cli",
		},
		Features: map[string]Feature{
			"environment_catalog": {
				Status: Supported, Reason: "Persistent metadata, workspace and dependency directories are implemented.",
				Evidence: []Evidence{{Source: "implementation", Detail: "sucrune/internal/environment; metadata only, not a sandbox"}},
			},
			"linux_execution": {
				Status: Unsupported, Reason: "The standalone development CLI does not execute Linux programs. The Android runtime has a separate embedded ARM64 shell backend.",
			},
			"project_security_isolation": {
				Status: Unsupported, Reason: "Separate directories do not isolate untrusted programs.",
			},
			"seccomp_trap": {
				Status: Unknown, Reason: "Run the Android probe in the intended application process identity.",
			},
			"arm64_guest_loading": {
				Status: Unknown, Reason: "Requires an ARM64 Android program-loading experiment.",
			},
		},
	}
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported capability schema %d", r.SchemaVersion)
	}
	if r.RuntimeVersion == "" || r.ObservedAt.IsZero() {
		return errors.New("runtime version and observation time are required")
	}
	if r.Host.OS == "" || r.Host.Architecture == "" || r.Host.ExecutionIdentity == "" || r.Host.PageSize <= 0 {
		return errors.New("host observation is incomplete")
	}
	if len(r.Features) == 0 {
		return errors.New("at least one feature is required")
	}
	for name, feature := range r.Features {
		if name == "" || feature.Reason == "" {
			return errors.New("feature name and reason are required")
		}
		switch feature.Status {
		case Supported:
			if len(feature.Evidence) == 0 {
				return fmt.Errorf("supported feature %q needs evidence", name)
			}
		case Unsupported, Unknown:
		default:
			return fmt.Errorf("invalid feature status %q for %q", feature.Status, name)
		}
		for _, evidence := range feature.Evidence {
			if evidence.Source == "" || evidence.Detail == "" {
				return fmt.Errorf("incomplete evidence for %q", name)
			}
		}
	}
	return nil
}
