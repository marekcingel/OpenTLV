"""Append the gcovr coverage summary to the GitHub Actions step summary.

Reads coverage/summary.json and the COVERAGE_ARTIFACT_URL environment variable.
"""

import json
import os
from pathlib import Path


def main():
    data = json.loads(Path("coverage/summary.json").read_text(encoding="utf-8"))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("### Clang Debug unit and integration test coverage\n\n")
        summary.write("| Metric | Coverage | Covered / Total |\n| --- | ---: | ---: |\n")
        for label, metric in [("Lines", "line"), ("Branches", "branch")]:
            summary.write(
                f"| {label} | {data[metric + '_percent']}% | "
                f"{data[metric + '_covered']} / {data[metric + '_total']} |\n"
            )
        summary.write(f"\n[Download HTML report]({os.environ['COVERAGE_ARTIFACT_URL']})\n")


if __name__ == "__main__":
    main()
