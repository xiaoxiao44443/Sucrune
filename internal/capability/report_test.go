package capability

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHostReportRoundTripDoesNotInventGuestSupport(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("test", 8*60*60))
	report := NewHostReport("test", now)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	bytes, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.Features["linux_execution"].Status != Unsupported || decoded.Features["project_security_isolation"].Status != Unsupported {
		t.Fatal("metadata implementation must not claim guest execution or isolation")
	}
	if decoded.Features["seccomp_trap"].Status != Unknown || decoded.Host.AndroidAPI != nil {
		t.Fatal("host CLI must not invent Android observations")
	}
	if !decoded.ObservedAt.Equal(now) || decoded.ObservedAt.Location() != time.UTC {
		t.Fatal("observation time must preserve the instant in UTC")
	}
}

func TestValidationRejectsUnsupportedSchemaAndUnprovenSuccess(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Report)
	}{
		{"future schema", func(r *Report) { r.SchemaVersion++ }},
		{"unproven success", func(r *Report) { r.Features["seccomp_trap"] = Feature{Status: Supported, Reason: "assumed"} }},
		{"unknown status", func(r *Report) { r.Features["test"] = Feature{Status: "maybe", Reason: "bad"} }},
		{"missing host", func(r *Report) { r.Host.ExecutionIdentity = "" }},
		{"missing reason", func(r *Report) { r.Features["test"] = Feature{Status: Unknown} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := NewHostReport("test", time.Now())
			test.edit(&report)
			if report.Validate() == nil {
				t.Fatal("accepted an invalid capability report")
			}
		})
	}
}
