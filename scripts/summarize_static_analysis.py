"""Append the findings of a cppcheck or clang-tidy log to the GitHub Actions step summary.

Usage: summarize_static_analysis.py cppcheck|clang-tidy LOG_FILE
"""

import argparse
import os
from pathlib import Path
import re

# Matches cppcheck's default "file:line:col: severity: message [id]" template;
# the note: follow-up lines some findings (e.g. shadowFunction) print have no
# [id] and are intentionally skipped.
CPPCHECK_PATTERN = re.compile(
    r"^(?P<file>.+):(?P<line>\d+):\d+: "
    r"(?P<severity>error|warning|style|performance|portability): "
    r"(?P<message>.+) \[(?P<id>[A-Za-z0-9_]+)\]$"
)

# Matches clang-tidy's default "file:line:col: severity: message [check-name]"
# diagnostic line; WarningsAsErrors: '*' (in .clang-tidy) turns every enabled
# check into a "error" with a trailing ",-warnings-as-errors" tag, which is
# split off in parse() to recover the actual check name.
CLANG_TIDY_PATTERN = re.compile(
    r"^(?P<file>.+):(?P<line>\d+):\d+: "
    r"(?P<severity>warning|error): (?P<message>.+) \[(?P<id>[A-Za-z0-9_.,-]+)\]$"
)

CPPCHECK_SEVERITIES = ["error", "warning", "style", "performance", "portability"]


def parse(lines, pattern):
    findings = []
    for line in lines:
        match = pattern.match(line.rstrip("\n"))
        if match:
            finding = match.groupdict()
            finding["id"] = finding["id"].split(",")[0]
            findings.append(finding)
    return findings


def write_summary(summary, tool, findings, severity_table):
    summary.write(f"### {tool} findings\n\n")
    if not findings:
        summary.write(f"No {tool} findings across `tlv` and `tlv++`.\n")
        return

    if severity_table:
        counts = {severity: 0 for severity in CPPCHECK_SEVERITIES}
        for finding in findings:
            counts[finding["severity"]] += 1
        summary.write("| Severity | Count |\n| --- | ---: |\n")
        for severity in CPPCHECK_SEVERITIES:
            if counts[severity]:
                summary.write(f"| {severity} | {counts[severity]} |\n")
        summary.write("\n")

    summary.write("| File | Line | Severity | Message |\n| --- | ---: | --- | --- |\n")
    for finding in findings:
        message = finding["message"].replace("|", "\\|")
        summary.write(
            f"| {finding['file']} | {finding['line']} | {finding['severity']} | "
            f"{message} (`{finding['id']}`) |\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("tool", choices=("cppcheck", "clang-tidy"))
    parser.add_argument("log", type=Path)
    options = parser.parse_args()

    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        if not options.log.exists():
            summary.write(f"### {options.tool} findings\n\n")
            summary.write(f"{options.tool} did not run; see the earlier failed step(s) above.\n")
            return
        lines = options.log.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        is_cppcheck = options.tool == "cppcheck"
        findings = parse(lines, CPPCHECK_PATTERN if is_cppcheck else CLANG_TIDY_PATTERN)
        write_summary(summary, options.tool, findings, severity_table=is_cppcheck)


if __name__ == "__main__":
    main()
