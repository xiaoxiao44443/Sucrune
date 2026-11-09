"""Install the APK just built inside Sucrune, verify its Activity UI, then uninstall it."""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from contextlib import contextmanager
from xml.etree import ElementTree


RUNNER = "com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation"
WORKFLOWS = {
    "sdk": ("dev.sucrune.compiled", "jdk,android", "linux_android_java_signed_apk"),
    "kotlin": ("dev.sucrune.compiled", "jdk,android,gradle", "linux_android_kotlin_sdk_apk"),
    "gradle": ("dev.sucrune.gradleprobe", "jdk,android,gradle,gradle-maven,gradle-sdk", "linux_gradle_kotlin_apk"),
}


def extract_apk(output, expected):
    chunks = re.findall(r"^INSTRUMENTATION_STATUS: sucrune_apk_chunk=(\d+):([^\r\n]+)$", output, re.M)
    headers = re.findall(r"^INSTRUMENTATION_STATUS: sucrune_apk=(\{[^\r\n]+\})$", output, re.M)
    if len(headers) != 1:
        raise ValueError("Expected exactly one exported APK")
    meta = json.loads(headers[0])
    if (meta["package"] != expected or meta["activity"] != expected + ".MainActivity"
            or not meta["marker"] or not 0 < meta["bytes"] <= 16 * 1024 * 1024
            or len(chunks) != meta["chunks"] or [int(i) for i, _ in chunks] != list(range(len(chunks)))):
        raise ValueError("Incomplete or unexpected instrumentation APK")
    data = b"".join(base64.b64decode(part, validate=True) for _, part in chunks)
    if len(data) != meta["bytes"] or hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise ValueError("APK length or SHA-256 did not match the guest export")
    return meta, data


def receipt_path(apk_path):
    return apk_path.with_name(apk_path.name + ".json")


def save_export(path, workflow, case, meta, data):
    receipt = receipt_path(path)
    created = []
    try:
        with path.open("xb") as apk:
            created.append(path)
            apk.write(data)
        with receipt.open("x", encoding="utf-8") as record:
            created.append(receipt)
            json.dump(dict(workflow=workflow, case=case, apk=meta), record, indent=2)
    except BaseException:
        for new_path in created:
            new_path.unlink(missing_ok=True)
        raise
    print(f"Saved guest APK {path} and receipt {receipt}", flush=True)


def load_export(path, workflow, case, expected):
    with receipt_path(path).open("rb") as record:
        raw = record.read(4097)
    if len(raw) > 4096:
        raise ValueError("Export receipt is too large")
    receipt = json.loads(raw)
    meta = receipt["apk"]
    if (receipt["workflow"] != workflow or receipt["case"] != case or meta["package"] != expected
            or meta["activity"] != expected + ".MainActivity" or not 0 < meta["bytes"] <= 16 * 1024 * 1024):
        raise ValueError("Unexpected APK export receipt")
    with path.open("rb") as apk:
        data = apk.read(meta["bytes"] + 1)
    if len(data) != meta["bytes"] or hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise ValueError("Saved APK differs from the export receipt")
    return meta, data


@contextmanager
def staged_apk(adb, data, meta):
    remote = "/data/local/tmp/sucrune-install-" + uuid.uuid4().hex + ".apk"
    local = None
    push_started = False
    try:
        with tempfile.NamedTemporaryFile(prefix="sucrune-install-", suffix=".apk", delete=False) as out:
            local = Path(out.name)
            out.write(data)
        push_started = True
        adb("push", str(local), remote, timeout=120)
        size = adb("shell", "wc", "-c", remote).split()
        digest = adb("shell", "sha256sum", remote).split()
        if not size or size[0] != str(meta["bytes"]) or not digest or digest[0] != meta["sha256"]:
            raise RuntimeError("Phone APK bytes or SHA-256 differ from the verified guest export")
        print(f"Verified staged APK on device ({size[0]} bytes, SHA-256 {digest[0]})", flush=True)
        yield remote
    finally:
        original_error = sys.exc_info()[1]
        errors = []
        if push_started:
            try:
                adb("shell", "rm", "-f", remote)
            except Exception as error:
                errors.append(str(error))
        if local is not None:
            try:
                local.unlink(missing_ok=True)
            except OSError as error:
                errors.append(str(error))
        if errors:
            message = "APK transfer cleanup failed: " + ", ".join(errors)
            if original_error is None:
                raise RuntimeError(message)
            print(message, file=sys.stderr, flush=True)


def run_instrumentation(command):
    # Keep APK chunks in memory; print only workflow progress and optional JVM diagnostics.
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, encoding="utf-8", errors="replace") as process:
        deadline = threading.Timer(2100, process.kill)
        deadline.start()
        lines = []
        diagnostic_lines = 0
        try:
            for line in process.stdout:
                lines.append(line)
                if line.strip() == "Gradle threads":
                    diagnostic_lines = 14
                if diagnostic_lines and not line.startswith("INSTRUMENTATION_"):
                    print(line.rstrip()[:320], flush=True)
                    diagnostic_lines -= 1
                elif line.startswith("linux_"):
                    print(line.rstrip()[:430], flush=True)
                else:
                    diagnostic_lines = 0
            if process.wait() != 0:
                raise RuntimeError("ADB instrumentation failed or timed out")
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--workflow", choices=WORKFLOWS, required=True)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--apk-out", type=Path, help="Save the verified APK and a .apk.json receipt before system installation")
    source.add_argument("--verify-export", type=Path, help="Install and check a previous --apk-out export without rebuilding")
    parser.add_argument("--gradle-vm", choices=("interpreter", "c1"), default="interpreter")
    parser.add_argument("--gradle-timeout-ms", type=int, default=1_800_000)
    parser.add_argument("--trace-gradle", action="store_true", help="Sample the guest JVM during the build")
    parser.add_argument("--trace-faults", action="store_true", help="Emit a bounded report on a fatal guest fault")
    args = parser.parse_args()
    command = [args.adb, "-s", args.serial]
    package, profiles, case = WORKFLOWS[args.workflow]
    if args.apk_out and (args.apk_out.exists() or receipt_path(args.apk_out).exists()):
        parser.error("--apk-out refuses to replace an existing APK or receipt")

    def adb(*words, timeout=60, check=True):
        result = subprocess.run(command + list(words), capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout)
        if check and result.returncode:
            raise RuntimeError((result.stderr + result.stdout).strip()[:1500])
        return (result.stdout if check else result.stdout + result.stderr).strip()

    user = adb("shell", "am", "get-current-user")
    if not user.isdecimal():
        raise RuntimeError("Missing active Android user")
    def installed():
        return ("package:" + package) in adb("shell", "pm", "list", "packages", "--user", user, package).splitlines()

    if installed():
        raise RuntimeError("Test package already exists for this user: " + package)
    gradle_options = []
    if args.workflow == "gradle":
        if not 1_000 <= args.gradle_timeout_ms <= 1_800_000:
            parser.error("--gradle-timeout-ms must be within 1000..1800000")
        gradle_options = ["-e", "gradle_vm", args.gradle_vm, "-e", "gradle_timeout_ms", str(args.gradle_timeout_ms)]
        if args.trace_gradle:
            gradle_options += ["-e", "gradle_threads", "true"]
        if args.trace_faults:
            gradle_options += ["-e", "gradle_faults", "true"]
    if args.verify_export:
        meta, data = load_export(args.verify_export, args.workflow, case, package)
    else:
        output = run_instrumentation(command + ["shell", "am", "instrument", "-w", "-r", "-e", "probe", "linux",
                     "-e", "focus", "compiler", "-e", "compiler_profiles", profiles,
                     "-e", "compiler_cases", case, "-e", "export_apk", "true",
                     "-e", "keep_foreground", "true", *gradle_options, RUNNER])
        summary = output.rpartition("INSTRUMENTATION_RESULT: stream=")[2]
        if ("INSTRUMENTATION_RESULT: failed=0" not in output or case + ": PASS " not in summary
                or "INSTRUMENTATION_CODE: -1" not in summary):
            # Only print the bounded case summary. APK transport chunks aren't diagnostic output.
            failures = [line for line in summary.splitlines() if ": FAIL " in line]
            detail = summary[summary.index(failures[0]):] if failures else summary
            raise RuntimeError(detail[:5600] if detail else "instrumentation did not return a summary")
        meta, data = extract_apk(output, package)
    marker = meta["marker"]
    marker_patterns = {"sdk": r"Sucrune Build Probe",
                       "kotlin": r"Sucrune Kotlin SDK [0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                       "gradle": r"Sucrune Kotlin [0-9a-f]{8}"}
    if not re.fullmatch(marker_patterns[args.workflow], marker):
        raise ValueError("This workflow exported an unexpected UI marker")
    if args.apk_out:
        save_export(args.apk_out, args.workflow, case, meta, data)
    component = package + "/" + meta["activity"]
    ui = "/data/local/tmp/sucrune-apk-ui-" + uuid.uuid4().hex + ".xml"
    if installed():
        raise RuntimeError("Test package appeared during the build: " + package)
    print(f"Installing guest APK {package} ({meta['bytes']} bytes, SHA-256 {meta['sha256']})", flush=True)
    with staged_apk(adb, data, meta) as remote:
        # Retain the PM session id so an installer authorization timeout can be cancelled.
        # -R rejects replacing another app and --pkg binds the session to this test package.
        reply = adb("shell", "pm", "install-create", "--user", user, "-R", "-t", "--pkg", package, "-S", str(len(data)))
        match = re.fullmatch(r"Success: created install session \[(\d+)\]", reply)
        if not match:
            raise RuntimeError("Package Manager did not create the install session: " + reply)
        session = match.group(1)
        committed = False
        commit_started = False
        commit_replied = False
        try:
            reply = adb("shell", "pm", "install-write", "-S", str(len(data)), session, "base.apk", remote, timeout=90)
            if not reply.startswith("Success"):
                raise RuntimeError("APK session write failed: " + reply[:400])
            commit_started = True
            reply = adb("shell", "pm", "install-commit", session, timeout=600, check=False)
            commit_replied = "Success" in reply.splitlines() or any(line.startswith("Failure [") for line in reply.splitlines())
            if "Success" not in reply.splitlines():
                raise RuntimeError("Package Manager did not install the guest APK: " + reply)
            committed = True
            start = adb("shell", "am", "start", "-W", "--user", user, "-n", component)
            if "Status: ok" not in start or not installed():
                raise RuntimeError("Activity did not start: " + start)
            for _ in range(4):
                adb("shell", "rm", "-f", ui)
                adb("shell", "uiautomator", "dump", ui, timeout=25)
                document = ElementTree.fromstring(adb("exec-out", "cat", ui))
                if any(node.get("package") == package and node.get("class") == "android.widget.TextView"
                       and node.get("text") == marker for node in document.iter("node")):
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("The Activity's expected TextView did not appear in the foreground UI")
        finally:
            original_error = sys.exc_info()[1]
            try:
                try:
                    adb("shell", "rm", "-f", ui)
                finally:
                    abandon_failed = False
                    if not committed:
                        # A commit may already have succeeded on the phone when the host lost its reply.
                        abandon = adb("shell", "pm", "install-abandon", session, check=False)
                        abandon_failed = "Success" not in abandon.splitlines() and not re.search(
                            r"(?:unknown|invalid|no such) session", abandon, re.IGNORECASE)
                    if commit_started and installed():
                        locations = adb("shell", "pm", "path", "--user", user, package).splitlines()
                        bases = [line[len("package:"):] for line in locations if line.startswith("package:/") and line.endswith("/base.apk")]
                        if len(bases) != 1 or adb("shell", "sha256sum", bases[0]).split(maxsplit=1)[0] != meta["sha256"]:
                            raise RuntimeError("Installed base.apk differs from the exported APK; package left untouched")
                        removed = adb("uninstall", "--user", user, package)
                        if "Success" not in removed.splitlines() or installed():
                            raise RuntimeError("Failed to remove this run's test package " + package)
                    elif not commit_replied and abandon_failed:
                        raise RuntimeError(f"Could not confirm cancellation of install session {session}: {abandon[:350]}")
            except Exception as cleanup_error:
                if original_error is None:
                    raise
                print(f"Cleanup also failed: {cleanup_error}", file=sys.stderr, flush=True)
    print(json.dumps(dict(workflow=args.workflow, case=case, **meta,
                          installed=True, activity_started=True, text_view_verified=True,
                          temporary_package_removed=True), ensure_ascii=False))


if __name__ == "__main__":
    main()
