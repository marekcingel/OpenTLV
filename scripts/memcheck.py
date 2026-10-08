#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Run a CTest command and its children under Memcheck, retaining every report.

CTest expects one log per test. Valgrind needs one log per process to avoid
overwriting or interleaving reports when Python/CMake harnesses spawn binaries.
Checking every summary also catches defects in children whose nonzero exit
status is expected (and therefore accepted) by the harness.
"""

from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


ERROR_EXIT = 99
SUMMARY = re.compile(r"^==\d+== ERROR SUMMARY: ([\d,]+) errors from", re.MULTILINE)


def test_command(arguments, valgrind, reports):
    if Path(arguments[0]).resolve() != Path(sys.executable).resolve():
        return [*valgrind, *arguments]

    # The Python oracle is a harness, not a library under test. Instrument its
    # explicitly supplied native executables without suppressing interpreter
    # findings or changing diagnostic stderr consumed by the oracle.
    command = list(arguments)
    wrapped = 0
    for index, argument in enumerate(arguments[:-1]):
        if argument in ("--native", "--cli", "--checker"):
            wrapper = reports / f"native-{wrapped}"
            wrapper.write_text(
                "#!/bin/sh\n"
                + ": > " + shlex.quote(str(reports)) + '/"$$.started" || exit 99\n'
                + "exec " + shlex.join([*valgrind, arguments[index + 1]]) + ' "$@"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            command[index + 1] = str(wrapper)
            wrapped += 1
    if not wrapped:
        raise ValueError("Python Memcheck harness has no supported --native, --cli or --checker executable")
    return command


def run(arguments):
    valgrind, *arguments = arguments
    options = []
    log_file = None
    while arguments and arguments[0].startswith("-"):
        option = arguments.pop(0)
        if option.startswith("--log-file="):
            log_file = Path(option.split("=", 1)[1])
        else:
            options.append(option)
    if log_file is None or not arguments:
        raise ValueError("expected CTest --log-file and a test command")

    # A fresh directory excludes stale reports from an earlier run of this test.
    log_file.parent.mkdir(parents=True, exist_ok=True)
    reports = Path(tempfile.mkdtemp(prefix=log_file.stem + ".", dir=log_file.parent))
    command = test_command(
        arguments, [valgrind, *options, f"--log-file={reports / '%p.log'}"], reports)
    print("OpenTLV Memcheck started", flush=True)
    result = subprocess.run(command)

    paths = sorted(reports.glob("*.log"))
    failures = []
    if not paths:
        failures.append("Valgrind produced no reports")
    # exec preserves the trampoline PID. A marker without its report means
    # Valgrind could not start; clean sibling reports must not hide that failure.
    for started in sorted(reports.glob("*.started")):
        if not started.with_suffix(".log").is_file():
            failures.append(f"{started.stem}.log: missing report for a started native command")
    with log_file.open("w", encoding="utf-8") as combined:
        for path in paths:
            contents = path.read_text(encoding="utf-8", errors="replace")
            combined.write(f"\nOpenTLV Memcheck process report: {path.name}\n")
            combined.write(contents)
            summaries = SUMMARY.findall(contents)
            if not summaries:
                failures.append(f"{path.name}: missing ERROR SUMMARY (incomplete report)")
            elif any(int(count.replace(",", "")) for count in summaries):
                failures.append(f"{path.name}: Memcheck reported errors")
        for failure in failures:
            combined.write(f"\nOpenTLV Memcheck failure: {failure}\n")

    if failures:
        for failure in failures:
            print(f"OpenTLV Memcheck failure: {failure}", file=sys.stderr)
        print(f"Memcheck reports: {reports}", file=sys.stderr)
        return ERROR_EXIT
    # Preserve ordinary harness failures as well as Valgrind's error exit code.
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def main():
    try:
        return run(sys.argv[1:])
    except (OSError, ValueError) as error:
        print(f"OpenTLV Memcheck launcher failed: {error}", file=sys.stderr)
        return ERROR_EXIT


if __name__ == "__main__":
    sys.exit(main())
