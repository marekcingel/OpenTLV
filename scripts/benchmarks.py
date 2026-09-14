"""Local Google Benchmark workflow; paths are relative to the repository."""
import argparse
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import venv

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
RESULTS = ROOT / "benchmarks" / "results"


def run(command):
    print("Running: " + subprocess.list2cmdline([str(x) for x in command]), flush=True)
    subprocess.run([str(x) for x in command], cwd=ROOT, check=True)


def read_result(path):
    if not path.is_file():
        raise ValueError(f"Missing {path}. Run the benchmarks first; create a baseline with the Update baseline task.")
    result = json.loads(path.read_text(encoding="utf-8"))
    rows = result.get("benchmarks", [])
    if not rows or any(row.get("error_occurred") for row in rows):
        raise ValueError(f"No successful benchmark results in {path}")
    print(f"{path}: run date {result.get('context', {}).get('date', 'unknown')}", flush=True)
    return result


def build_and_run(extra):
    run(["cmake", "-S", ROOT, "-B", BUILD, "-DOPENTLV_BUILD_BENCHMARKS=ON", "-DCMAKE_BUILD_TYPE=Release"])
    run(["cmake", "--build", BUILD, "--config", "Release", "--target", "benchmark-tlv"])
    executable = (BUILD / "benchmarks" / "Release" / "executable-path.txt").read_text().strip()
    RESULTS.mkdir(parents=True, exist_ok=True)
    # Keep the last completed run intact until the new JSON has been validated.
    with tempfile.NamedTemporaryFile(dir=RESULTS, suffix=".json", delete=False) as stream:
        pending = Path(stream.name)
    try:
        run([executable, "--benchmark_repetitions=10", "--benchmark_report_aggregates_only=true",
             *extra, f"--benchmark_out={pending}", "--benchmark_out_format=json"])
        read_result(pending)
        pending.replace(RESULTS / "latest.json")
        print(f"Saved completed run: {RESULTS / 'latest.json'}", flush=True)
    finally:
        pending.unlink(missing_ok=True)


def compare(baseline, latest):
    read_result(baseline)
    read_result(latest)
    tools = BUILD / "_deps" / "googlebenchmark-src" / "tools"
    if not (tools / "compare.py").is_file():
        raise ValueError("Google Benchmark tools are missing. Run the Build and run task first.")
    environment = BUILD / "benchmark-tools-venv"
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        venv.EnvBuilder(with_pip=True).create(environment)
    cert_args = []
    if not any(os.environ.get(name) for name in ("PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")):
        # Older pip uses certifi alone. Export trusted system CAs without
        # disabling TLS verification or requiring a package download first.
        certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
        if certificates:
            bundle = environment / "system-ca.pem"
            bundle.write_text("".join(ssl.DER_cert_to_PEM_cert(cert) for cert in certificates), encoding="ascii")
            cert_args = ["--cert", bundle]
    run([python, "-m", "pip", "install", "--disable-pip-version-check", *cert_args,
         "-r", tools / "requirements.txt"])
    run([python, tools / "compare.py", "--display_aggregates_only", "benchmarks", baseline, latest])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "compare", "baseline"])
    parser.add_argument("--baseline", type=Path, default=RESULTS / "baseline.json")
    parser.add_argument("--latest", type=Path, default=RESULTS / "latest.json")
    parser.add_argument("--host-label", help="Public machine alias for baseline metadata (default: baseline filename stem)")
    args, extra = parser.parse_known_args()
    args.baseline = args.baseline.resolve()
    args.latest = args.latest.resolve()
    if args.action != "run" and extra:
        parser.error("Unexpected arguments: " + " ".join(extra))
    if args.action == "run":
        build_and_run(extra)
    elif args.action == "compare":
        compare(args.baseline, args.latest)
    else:
        result = read_result(args.latest)
        result.setdefault("context", {})["host_name"] = args.host_label or args.baseline.stem
        args.baseline.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline updated: {args.baseline}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Benchmark task failed: {error}", file=sys.stderr)
        sys.exit(1)
