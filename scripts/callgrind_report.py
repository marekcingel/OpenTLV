#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Read complete Callgrind profiles and report informational comparisons.

The parser follows https://valgrind.org/docs/manual/cl-format.html. A totals
footer is required for this workflow so an interrupted dump cannot be mistaken
for a successful measurement. Function costs are exclusive (self) instruction
counts, aggregated by symbol name across files and objects; inclusive call
edges are never counted again. The raw profiles retain the full call graph.
"""

import json
import math
from pathlib import Path
import re
import statistics


NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)\Z")
POSITION = re.compile(r"(?:\*|[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))\Z")
COMPRESSED_NAME = re.compile(r"\(([0-9]+)\)(?:\s+(.*))?\Z")
NAME_GROUPS = {
    "ob": "object", "cob": "object",
    "fl": "file", "fi": "file", "fe": "file", "cfi": "file", "cfl": "file",
    "fn": "function", "cfn": "function",
}


class ProfileError(ValueError):
    """A profile is incomplete or does not satisfy the supported format."""


def parse_profile(path):
    """Return complete-run and per-symbol self Ir, rejecting incomplete dumps.

    A single Callgrind part is supported, as emitted by the comparison driver.
    A larger summary is permitted by the format: its excess is reported as
    unattributed instructions, without inventing a corresponding function.
    """
    path = Path(path)
    content = path.read_text(encoding="utf-8")
    if not content.endswith("\n"):
        raise ProfileError(f"{path}: profile has no complete final line")
    events = None
    positions = ["line"]
    summary = None
    totals = None
    costs = None
    functions = {}
    names = {"object": {}, "file": {}, "function": {}}
    current_function = None
    pending_call = False
    body_started = False
    part_seen = False
    thread_seen = False

    def fail(line_number, message):
        raise ProfileError(f"{path}:{line_number}: {message}")

    def number(value, line_number):
        if not NUMBER.fullmatch(value):
            fail(line_number, f"invalid counter {value!r}")
        return int(value, 16 if value.lower().startswith("0x") else 10)

    def event_costs(values, line_number):
        if events is None:
            fail(line_number, "costs precede events declaration")
        if len(values) > len(events):
            fail(line_number, "more costs than declared events")
        return [number(value, line_number) for value in values] + [0] * (len(events) - len(values))

    def resolve_name(spec, value, line_number):
        if not value:
            fail(line_number, f"empty {spec} name")
        match = COMPRESSED_NAME.fullmatch(value)
        if match:
            identifier, name = match.groups()
            mapping = names[NAME_GROUPS[spec]]
            if name is not None:
                if not name or (identifier in mapping and mapping[identifier] != name):
                    fail(line_number, "invalid or conflicting compressed name")
                mapping[identifier] = name
            if identifier not in mapping:
                fail(line_number, f"undefined compressed {spec} name ({identifier})")
            return mapping[identifier]
        if re.match(r"\([0-9]", value):
            fail(line_number, "malformed compressed name")
        return value

    for line_number, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if totals is not None:
            fail(line_number, "data after totals footer (multiple parts are unsupported)")
        is_cost = line[0].isdigit() or line[0] in "+-*"
        if pending_call and not is_cost:
            fail(line_number, "calls association lacks its following cost line")
        if is_cost:
            if events is None or current_function is None:
                fail(line_number, "cost line lacks events or function declaration")
            fields = line.split()
            if len(fields) < len(positions):
                fail(line_number, "cost line lacks position columns")
            if not all(POSITION.fullmatch(value) for value in fields[:len(positions)]):
                fail(line_number, "invalid position column")
            values = event_costs(fields[len(positions):], line_number)
            body_started = True
            if pending_call:
                pending_call = False
                continue
            costs = [old + value for old, value in zip(costs, values)]
            instructions = values[events.index("Ir")]
            functions[current_function] = functions.get(current_function, 0) + instructions
            continue
        if "=" in line and re.match(r"^[a-z]+=", line):
            spec, value = line.split("=", 1)
            value = value.strip()
            if spec in NAME_GROUPS:
                name = resolve_name(spec, value, line_number)
                if spec == "fn":
                    current_function = name
            elif spec in ("calls", "jump", "jcnd"):
                fields = value.split()
                count_columns = 2 if spec == "jcnd" else 1
                if len(fields) != count_columns + len(positions):
                    fail(line_number, f"invalid {spec} association")
                for field in fields[:count_columns]:
                    number(field, line_number)
                if not all(POSITION.fullmatch(field) for field in fields[count_columns:]):
                    fail(line_number, f"invalid {spec} target position")
                pending_call = spec == "calls"
            else:
                fail(line_number, f"unsupported body specification {spec!r}")
            continue
        if ":" not in line:
            fail(line_number, "unrecognized profile line")
        key, value = line.split(":", 1)
        value = value.strip()
        if key == "events":
            if events is not None or body_started:
                fail(line_number, "duplicate events declaration or multiple parts")
            events = value.split()
            if len(events) != len(set(events)) or "Ir" not in events:
                fail(line_number, "events must declare Ir exactly once")
            costs = [0] * len(events)
        elif key == "positions":
            if body_started:
                fail(line_number, "positions changed after cost lines")
            positions = value.split()
            if not positions or positions != [item for item in ("instr", "bb", "line") if item in positions]:
                fail(line_number, "invalid positions declaration")
        elif key == "summary":
            if summary is not None or body_started:
                fail(line_number, "duplicate or misplaced summary")
            summary = (value.split(), line_number)
        elif key == "totals":
            if not value:
                fail(line_number, "empty totals footer")
            totals = event_costs(value.split(), line_number)
        elif key == "version":
            if value not in ("0", "1"):
                fail(line_number, f"unsupported format version {value!r}")
        elif key in ("part", "thread"):
            if body_started or (key == "part" and part_seen) or (key == "thread" and thread_seen):
                fail(line_number, "multiple profile parts or threads are unsupported")
            number(value, line_number)
            part_seen = part_seen or key == "part"
            thread_seen = thread_seen or key == "thread"
        # Other header metadata, including event descriptions, is non-numeric.

    if pending_call:
        raise ProfileError(f"{path}: incomplete calls association")
    if events is None or totals is None:
        raise ProfileError(f"{path}: missing events declaration or totals footer")
    if costs != totals:
        raise ProfileError(f"{path}: totals do not match the sum of self costs")
    summary_costs = event_costs(*summary) if summary is not None else totals
    if any(full < own for full, own in zip(summary_costs, totals)):
        raise ProfileError(f"{path}: summary is smaller than the sum of self costs")
    index = events.index("Ir")
    return {
        "instructions": summary_costs[index],
        "self_instructions": totals[index],
        "unattributed_instructions": summary_costs[index] - totals[index],
        "functions": dict(sorted(functions.items())),
    }


def _percent(baseline, candidate):
    return (candidate - baseline) * 100.0 / baseline if baseline else (0.0 if candidate == 0 else None)


def _nonnegative(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")


def _samples(values):
    values = list(values)
    if len(values) < 3:
        raise ValueError("native timing requires at least three samples for each revision")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or
           not math.isfinite(value) or value <= 0 for value in values):
        raise ValueError("native timing samples must be finite and positive")
    return values


def compare_workload(name, baseline_profile, candidate_profile, baseline_ns, candidate_ns,
                     threshold_percent=5, threshold_instructions=0, native_threshold_percent=5):
    """Compare identical workloads; warnings describe signals, never proof of slowdown.

    Both instruction thresholds must be exceeded to produce a warning. A
    positive count against a zero baseline has no defined percentage and is
    warned about when it exceeds the absolute threshold. Native CV above 5%
    marks noisy samples; lower CV is still not a claim of statistical confidence.
    """
    for value, label in ((threshold_percent, "instruction percentage threshold"),
                         (threshold_instructions, "instruction absolute threshold"),
                         (native_threshold_percent, "native percentage threshold")):
        _nonnegative(value, label)
    baseline_ns, candidate_ns = _samples(baseline_ns), _samples(candidate_ns)
    if len(baseline_ns) != len(candidate_ns):
        raise ValueError("baseline and candidate need the same number of native samples")
    baseline, candidate = baseline_profile["instructions"], candidate_profile["instructions"]
    for count in (baseline, candidate):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("instruction counts must be nonnegative integers")
    delta = candidate - baseline
    percent = _percent(baseline, candidate)
    warning = delta > threshold_instructions and (percent is None or percent > threshold_percent)
    baseline_median, candidate_median = statistics.median(baseline_ns), statistics.median(candidate_ns)
    native_percent = _percent(baseline_median, candidate_median)
    baseline_cv = statistics.stdev(baseline_ns) * 100 / statistics.mean(baseline_ns)
    candidate_cv = statistics.stdev(candidate_ns) * 100 / statistics.mean(candidate_ns)
    if max(baseline_cv, candidate_cv) > 5:
        signal = "noisy"
    elif native_percent > native_threshold_percent:
        signal = "higher_time"
    elif native_percent < -native_threshold_percent:
        signal = "lower_time"
    else:
        signal = "no_material_change"
    functions = []
    for function in sorted(set(baseline_profile["functions"]) | set(candidate_profile["functions"])):
        before = baseline_profile["functions"].get(function, 0)
        after = candidate_profile["functions"].get(function, 0)
        functions.append({"name": function, "baseline": before, "candidate": after,
                          "delta": after - before, "percent": _percent(before, after)})
    functions.sort(key=lambda item: (-abs(item["delta"]), item["name"]))
    assessments = {
        "noisy": "Native timings are noisy; repeat under stable conditions before drawing conclusions.",
        "higher_time": "Native median time also increased; investigate and reproduce before calling this a regression.",
        "lower_time": "Native median time decreased; the instruction count alone does not establish a slowdown.",
        "no_material_change": "Native median time did not cross the configured threshold; a slowdown is not established.",
    }
    return {
        "name": name,
        "instructions": {"baseline": baseline, "candidate": candidate, "delta": delta,
                         "percent": percent, "warning": warning,
                         "threshold_percent": threshold_percent,
                         "threshold_instructions": threshold_instructions,
                         "baseline_unattributed": baseline_profile.get("unattributed_instructions", 0),
                         "candidate_unattributed": candidate_profile.get("unattributed_instructions", 0)},
        "native": {"baseline_ns": baseline_ns, "candidate_ns": candidate_ns,
                   "baseline_median_ns": baseline_median, "candidate_median_ns": candidate_median,
                   "delta_ns": candidate_median - baseline_median,
                   "percent": native_percent, "baseline_cv_percent": baseline_cv,
                   "candidate_cv_percent": candidate_cv, "threshold_percent": native_threshold_percent,
                   "signal": signal},
        "functions": functions,
        "assessment": assessments[signal],
    }


def _cell(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("\r", " ").replace("\n", " ").replace("`", "&#96;")


def _percent_text(value):
    return "n/a (zero baseline)" if value is None else f"{value:+.2f}%"


def render_markdown(report, top_functions=10):
    """Render a portable summary; the JSON report retains every function delta."""
    if isinstance(top_functions, bool) or not isinstance(top_functions, int) or top_functions < 1:
        raise ValueError("top_functions must be a positive integer")
    metadata = report.get("metadata", {})
    sources = metadata.get("sources", {})
    lines = [
        "# Callgrind and native timing comparison", "",
        f"Baseline: `{_cell(report['baseline_sha'])}`  ",
        f"Candidate: `{_cell(report['candidate_sha'])}`", "",
        "Callgrind Ir warnings are informational. Instruction counts alone do not prove a performance regression. "
        "Native Release timings are a separate correlation signal, not timings measured under Valgrind.", "",
    ]
    for side in ("baseline", "candidate"):
        source = sources.get(side, {})
        if source.get("dirty"):
            lines.extend([f"**{side.capitalize()} contains uncommitted source changes. Its commit SHA alone "
                          "does not identify the measured code.**", ""])
    if sources:
        lines.extend(["| Source | Commit | Working tree | Source tree SHA-256 |",
                      "| --- | --- | --- | --- |"])
        for side in ("baseline", "candidate"):
            source = sources.get(side, {})
            lines.append(f"| {side.capitalize()} | {_cell(source.get('sha', 'unknown'))} | "
                         f"{'Modified' if source.get('dirty') else 'Clean'} | "
                         f"{_cell(source.get('tree_sha256', 'unknown'))} |")
        lines.extend(["", "The full source manifest and toolchain metadata are retained in metadata.json.", ""])
    if metadata:
        lines.extend(["## Measurement configuration", "", "| Setting | Value |", "| --- | --- |"])
        for key, value in sorted(metadata.items()):
            if key in ("sources", "binaries_sha256", "harness_sha256"):
                continue
            if isinstance(value, (dict, list, tuple)):
                value = json.dumps(value, sort_keys=True)
            lines.append(f"| {_cell(key)} | {_cell(value)} |")
        lines.append("")
    lines.extend([
        "## Instruction counts", "",
        "| Workload | Baseline Ir | Candidate Ir | Delta Ir | Change | Result |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ])
    for workload in report["workloads"]:
        result = workload["instructions"]
        lines.append(f"| {_cell(workload['name'])} | {result['baseline']:,} | {result['candidate']:,} | "
                     f"{result['delta']:+,} | {_percent_text(result['percent'])} | "
                     f"{'Warning: instruction increase' if result['warning'] else 'Within thresholds'} |")
    lines.extend([
        "", "## Native Release timing", "",
        "| Workload | Baseline median ns | Candidate median ns | Delta ns | Change | Baseline CV | Candidate CV | Signal |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for workload in report["workloads"]:
        result = workload["native"]
        lines.append(f"| {_cell(workload['name'])} | {result['baseline_median_ns']:,.0f} | "
                     f"{result['candidate_median_ns']:,.0f} | {result['delta_ns']:+,.0f} | {_percent_text(result['percent'])} | "
                     f"{result['baseline_cv_percent']:.2f}% | {result['candidate_cv_percent']:.2f}% | "
                     f"{_cell(result['signal'].replace('_', ' '))} |")
    lines.extend(["", "CV is sample standard deviation divided by mean. CV above 5% is marked noisy; "
                  "lower CV does not establish statistical confidence.", ""])
    for workload in report["workloads"]:
        counts, native = workload["instructions"], workload["native"]
        lines.extend([
            f"## {_cell(workload['name'])}", "", workload["assessment"], "",
            f"Instruction warning thresholds: more than {counts['threshold_percent']:g}% and more than "
            f"{counts['threshold_instructions']:g} Ir. Native change threshold: "
            f"{native['threshold_percent']:g}%; {len(native['baseline_ns'])} samples per revision.", "",
        ])
        iterations = metadata.get("native_iterations")
        if isinstance(iterations, int) and not isinstance(iterations, bool) and iterations > 0:
            lines.extend([f"Each native sample measures {iterations:,} iterations. Normalized median: "
                          f"{native['baseline_median_ns'] / iterations:,.2f} ns/iteration baseline, "
                          f"{native['candidate_median_ns'] / iterations:,.2f} ns/iteration candidate.", ""])
            input_bytes = workload.get("input_bytes")
            if isinstance(input_bytes, int) and not isinstance(input_bytes, bool) and input_bytes > 0:
                baseline_rate = input_bytes * iterations * 1e9 / native["baseline_median_ns"] / (1024 * 1024)
                candidate_rate = input_bytes * iterations * 1e9 / native["candidate_median_ns"] / (1024 * 1024)
                lines.extend([f"Input throughput ({input_bytes:,} bytes/iteration): "
                              f"{baseline_rate:,.2f} MiB/s baseline, {candidate_rate:,.2f} MiB/s candidate. "
                              "This measures workload input volume, not memory bandwidth.", ""])
        if counts["baseline_unattributed"] or counts["candidate_unattributed"]:
            lines.extend([f"Instructions without function attribution: {counts['baseline_unattributed']:,} "
                          f"baseline, {counts['candidate_unattributed']:,} candidate. These are included in "
                          "the run totals but cannot appear in the function table.", ""])
        lines.extend([
            f"Largest {top_functions} function changes by absolute self Ir delta. "
            "Symbols are aggregated across files and objects. Full function results are in the JSON report.", "",
            "| Function | Baseline self Ir | Candidate self Ir | Delta self Ir | Change |",
            "| --- | ---: | ---: | ---: | ---: |",
        ])
        for function in workload["functions"][:top_functions]:
            lines.append(f"| {_cell(function['name'])} | {function['baseline']:,} | {function['candidate']:,} | "
                         f"{function['delta']:+,} | {_percent_text(function['percent'])} |")
        lines.append("")
    return "\n".join(lines)
