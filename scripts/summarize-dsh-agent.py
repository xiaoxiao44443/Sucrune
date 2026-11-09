"""Summarize one run-dsh-agent-device.cjs --real-deepseek JSONL and two supplied APKs.

Required for a successful combined receipt: an independently collected cleanup
JSON object with workspace_projects_remaining, temporary_imports_remaining and
owned_adb_forwards_remaining (integer counts). Omit it for an interim receipt.
Exit 0 = all passed and cleanup verified, 1 = valid failed/incomplete receipt,
2 = invalid input or existing destination. No device access or credential input.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile


AGENT = tuple("linux_dsh_agent_" + name for name in
              ("prepare", "model_file_shell", "restart_resume", "cancel_active_turn"))
PREFLIGHT = frozenset("linux_" + name for name in """
argv_and_reuse dsh_native_flock_conflict_release dsh_native_process_report
dsh_profile_install_bundle dsh_profile_prepare dsh_persistent_bash_tool
dsh_sdk_initialize_shutdown dsh_sdk_minimal_eof dynamic_hello fork_cancel_session_lease
gnu_bash_builtins guest_fork_continuation_and_wait guest_fork_exec_debian_hello
guest_fork_unlinked_file_and_cwd guest_fork_stop_continue_wait guest_pselect6_mask_and_readiness
import_upstream invalid_image_and_permissions last_instruction_trap loader_dependency_list
local_io_concurrency node_cares_dns_records node_crypto_workflow node_esm_argv_unicode
node_fs_workflow node_glibc_dns_lookup node_interactive_empty_cancel node_interactive_empty_timeout
node_interactive_guest_closes_stdin node_interactive_roundtrip_eof node_javascript
node_jit_optimization node_jitless node_outbound_https_certificate node_parallel_projects
node_live_stdout_roundtrip node_live_stdout_overflow node_owned_proc_stat node_owned_child_kill_wait
node_pty_bash node_pty_load node_pty_open node_pty_stty_echo node_pty_job_control
node_secret_cancel_cleanup node_secret_output_events node_spawn_bash_with_connected_tcp
node_spawn_debian_hello_with_pipes node_timers_promises node_udp_multiple_datagrams
node_version node_worker_shared_atomics project_boundary runner_cancel_and_closed_stdin
runner_exit_without_stdin_read runner_timeout signal_delivery_and_return
thread_exit_group thread_parallel_and_join
""".split())
CATALOG = PREFLIGHT.union(AGENT)
STAGES = set("""prerequisite prepare credential_wait credential_received launch initialize resume
prompt wait model_stream tool_write tool_read tool_bash tool_other tool_result turn_end
turn_evidence shutdown terminal_evidence artifacts jsonl cancel_observe cancel reuse""".split())
REASONS = set("""progress rpc_error turn_error capture_limit partial_frame exit_before_reply
deadline tool_error assertion runtime_error invalid_schema protocol_io cleanup unexpected history_selection
history_size history_read history_framing history_identity history_path history_prefix history_append history_message""".split())
KINDS = set("""none AUTH QUOTA RATE_LIMIT SERVER TRANSPORT MISSING_CREDENTIAL INVALID_CREDENTIAL
INVALID_REQUEST CONTEXT_WINDOW_EXCEEDED EMPTY_RESPONSE TOOL_ACTIVATION_FAILED UNKNOWN other""".split())
FAILURES = set("""arguments descriptor yaml_integrity existing_forward forward_result forward_identity
forward_cleanup_identity forward_cleanup adb_command device_identity duplicate_exchange credential_window
credential_receipt instrument_exit missing_receipt device_case_failed credential_source_size
credential_source_format credential_ref_missing credential_shape yaml_dependency credential_source_directory
credential_source_changed credential_source_read connect connect_EACCES connect_EPERM connect_ECONNREFUSED
connect_ENETUNREACH server_proof credential_source credential_frame acknowledgment deadline
instrumentation_protocol""".split())
CLEANUP = ("workspace_projects_remaining", "temporary_imports_remaining", "owned_adb_forwards_remaining")
DIAG = {"status", "test", "stage", "safe_reason", "error_kind", "event_count", "tool_count",
        "http_status", "rpc_code"}


def require(condition):
    if not condition:
        raise ValueError("invalid evidence")


def integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def decode(data):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs))
        return result
    row = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    require(type(row) is dict)
    return row


def scan(path):
    states = dict.fromkeys(CATALOG, "not_started")
    active = final = None
    agent_started = 0
    failure = False
    events = tools = 0
    stages = set()
    confirmed = removed = 0
    sha = hashlib.sha256()
    with path.open("rb") as source:
        for index in range(769):
            line = source.readline(4097)
            if not line:
                break
            require(index < 768 and len(line) <= 4096 and final is None)
            sha.update(line)
            row = decode(line.removeprefix(b"\xef\xbb\xbf") if index == 0 else line)
            status = row.get("status")
            if set(row) == {"status", "test"}:
                name = row["test"]
                require(name in states)
                if status == "started":
                    require(active is None and states[name] == "not_started")
                    if name in AGENT:
                        require(agent_started < len(AGENT) and name == AGENT[agent_started])
                        agent_started += 1
                    active, failure, events, tools = name, False, 0, 0
                    stages.clear()
                else:
                    require(name == active and status in ("passed", "failed"))
                    require(not failure or status == "failed")
                    active = None
                states[name] = status
            elif set(row) == DIAG and status == "agent_diagnostic":
                require(row["test"] == active and active in AGENT and not failure)
                stage, reason, kind = row["stage"], row["safe_reason"], row["error_kind"]
                require(stage in STAGES and reason in REASONS and kind in KINDS)
                ec, tc = row["event_count"], row["tool_count"]
                require(integer(ec, 2048) and ec >= events and integer(tc, 8) and tc >= tools)
                events, tools = ec, tc
                http, rpc = row["http_status"], row["rpc_code"]
                require(integer(http, 599) and (http == 0 or http >= 100))
                require(type(rpc) is int and rpc in (0, -32700, -32600, -32601, -32602, -32603, -32000))
                if reason == "progress":
                    require(stage not in stages and kind == "none" and http == 0 and rpc == 0)
                    stages.add(stage)
                else:
                    failure = True
            elif set(row) == {"status", "stage"} and status == "failed":
                require(row["stage"] in FAILURES)
                final = "failed"
            else:
                require(set(row) == {"status", "mode", "passed", "confirmed_receipts", "removed_forwards"})
                require(status == "passed" and row["mode"] == "real" and active is None)
                require(integer(row["passed"], len(CATALOG)) and row["passed"] == len(CATALOG))
                require(all(value == "passed" for value in states.values()))
                for key in ("confirmed_receipts", "removed_forwards"):
                    require(type(row[key]) is int and row[key] == 1)
                final, confirmed, removed = "passed", 1, 1
    def counts(names):
        return {"expected": len(names), **{state: sum(states[name] == state for name in names)
                for state in ("passed", "failed", "started", "not_started")}}
    status = final or ("failed" if "failed" in states.values() else "incomplete")
    return {"status": status, "terminal_summary": final or "missing",
            "source_sha256": sha.hexdigest(), "preflight": counts(PREFLIGHT), "agent": counts(AGENT),
            "agent_cases": {name: states[name] for name in AGENT},
            "confirmed_receipts": confirmed if final == "passed" else None,
            "controller_removed_forwards": removed if final == "passed" else None}


def cleanup(path):
    if path is None:
        return {"status": "not_provided"}
    with path.open("rb") as stream:
        data = stream.read(4097)
    require(len(data) <= 4096)
    counts = decode(data.removeprefix(b"\xef\xbb\xbf"))
    require(set(counts) == set(CLEANUP) and all(integer(counts[k], 2**31-1) for k in CLEANUP))
    return {"status": "verified" if all(counts[k] == 0 for k in CLEANUP) else "remaining",
            **{name: counts[name] for name in CLEANUP}}


def apk(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            require(names.count("AndroidManifest.xml") == 1 and names.count("classes.dex") == 1)
        source.seek(0)
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("controller", "app-apk", "test-apk", "output", "cleanup"):
        parser.add_argument("--" + option, type=Path, required=option != "cleanup")
    args = parser.parse_args()
    try:
        real = scan(args.controller)
        leftovers = cleanup(args.cleanup)
        app, tests = apk(args.app_apk), apk(args.test_apk)
        require(app != tests)
        passed = real["status"] == "passed" and leftovers["status"] == "verified"
        status = ("passed" if passed else "failed" if real["status"] == "failed" or
                  leftovers["status"] == "remaining" else "incomplete")
        report = {"schema_version": 1, "status": status, "real_controller": real,
                  "supplied_apk_sha256": {"application": app, "instrumentation": tests},
                  "cleanup": leftovers}
        with args.output.open("x", encoding="utf-8", newline="\n") as target:
            target.write(json.dumps(report, indent=2) + "\n")
        print(status)
        return 0 if passed else 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError, zipfile.BadZipFile):
        print("Invalid input or destination unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
