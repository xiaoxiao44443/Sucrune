// Sucrune's development CLI manages metadata and exposes capability information.
// It does not run host commands on behalf of an environment.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"sucrune/internal/capability"
	"sucrune/internal/environment"
	"sucrune/internal/runtimecore"
)

const version = "0.7.0-linux-dev"

func main() { os.Exit(runWithInput(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	return runWithInput(args, strings.NewReader(""), stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sucrune", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dataDir := flags.String("data-dir", "", "explicit persistent data directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeUsage(stdout)
			return 0
		}
		return fail(stderr, "invalid_arguments", err)
	}
	args = flags.Args()
	if len(args) == 0 {
		writeUsage(stdout)
		return 0
	}
	if args[0] == "info" {
		if len(args) != 1 {
			return fail(stderr, "invalid_arguments", errors.New("info takes no arguments"))
		}
		return output(stdout, stderr, capability.NewHostReport(version, time.Now()))
	}
	if args[0] == "exec" {
		return fail(stderr, "not_implemented", errors.New("Linux execution is not implemented; host execution is never used as a sandbox substitute"))
	}
	if args[0] == "rpc" {
		if len(args) != 1 {
			return fail(stderr, "invalid_arguments", errors.New("rpc reads one JSON request per stdin line and takes no arguments"))
		}
		if *dataDir == "" {
			return fail(stderr, "data_directory_required", errors.New("pass --data-dir PATH before the command"))
		}
		service, err := runtimecore.Open(*dataDir)
		if err != nil {
			return catalogError(stderr, err)
		}
		scanner := bufio.NewScanner(stdin)
		scanner.Buffer(make([]byte, 4096), runtimecore.MaxRequestBytes+1)
		for scanner.Scan() {
			if _, err := fmt.Fprintln(stdout, string(service.CallJSON(scanner.Bytes()))); err != nil {
				return fail(stderr, "output_error", err)
			}
		}
		if err := scanner.Err(); err != nil {
			return fail(stderr, "input_error", err)
		}
		return 0
	}
	if args[0] != "env" || len(args) < 2 {
		return fail(stderr, "invalid_arguments", errors.New("expected info or env create/list/get/paths/delete; see --help"))
	}
	action := args[1]
	var name, baseReference, id string
	switch action {
	case "create":
		createFlags := flag.NewFlagSet("env create", flag.ContinueOnError)
		createFlags.SetOutput(io.Discard)
		createFlags.StringVar(&name, "name", "", "environment display name")
		createFlags.StringVar(&baseReference, "base", "", "descriptive base reference; no image is downloaded")
		if err := createFlags.Parse(args[2:]); err != nil {
			return fail(stderr, "invalid_arguments", err)
		}
		if createFlags.NArg() != 0 || name == "" {
			return fail(stderr, "invalid_arguments", errors.New("env create requires --name NAME and accepts optional --base REFERENCE"))
		}
	case "list":
		if len(args) != 2 {
			return fail(stderr, "invalid_arguments", errors.New("env list takes no arguments"))
		}
	case "get", "paths", "delete":
		if len(args) != 3 {
			return fail(stderr, "invalid_arguments", fmt.Errorf("env %s requires one environment ID", action))
		}
		id = args[2]
	default:
		return fail(stderr, "invalid_arguments", fmt.Errorf("unknown env command %q", action))
	}
	if *dataDir == "" {
		return fail(stderr, "data_directory_required", errors.New("pass --data-dir PATH before the command"))
	}
	catalog, err := environment.Open(*dataDir)
	if err != nil {
		return catalogError(stderr, err)
	}
	var result any
	switch action {
	case "create":
		result, err = catalog.Create(name, baseReference)
	case "list":
		result, err = catalog.List()
	case "get":
		result, err = catalog.Get(id)
	case "paths":
		result, err = catalog.Paths(id)
	case "delete":
		err = catalog.Delete(id)
		result = map[string]string{"id": id, "state": "deleted"}
	}
	if err != nil {
		return catalogError(stderr, err)
	}
	return output(stdout, stderr, result)
}

func catalogError(stderr io.Writer, err error) int {
	code := "storage_error"
	switch {
	case errors.Is(err, environment.ErrInvalidID), errors.Is(err, environment.ErrInvalidName):
		code = "invalid_arguments"
	case errors.Is(err, environment.ErrNotFound):
		code = "not_found"
	case errors.Is(err, environment.ErrCorrupt):
		code = "corrupt_metadata"
	case errors.Is(err, environment.ErrUnsafePath):
		code = "unsafe_path"
	}
	return fail(stderr, code, err)
}

func output(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fail(stderr, "output_error", err)
	}
	return 0
}

func fail(stderr io.Writer, code string, err error) int {
	_ = json.NewEncoder(stderr).Encode(map[string]any{"error": map[string]string{"code": code, "message": err.Error()}})
	return 1
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Sucrune development CLI (metadata and capability probes only)

Usage:
  sucrune info
  sucrune --data-dir PATH env create --name NAME [--base REFERENCE]
  sucrune --data-dir PATH env list
  sucrune --data-dir PATH env get ID
  sucrune --data-dir PATH env paths ID
  sucrune --data-dir PATH env delete ID
  sucrune --data-dir PATH rpc

env create prepares empty workspace/dependency directories; --base is metadata.
env delete permanently removes that environment's files.
Linux execution and untrusted-program isolation are not implemented.
Use only one catalog owner per data directory.`)
}
