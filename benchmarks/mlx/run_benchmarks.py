#!/usr/bin/env python3
"""Run pinned mlx-lm throughput trials and write reviewable JSON plus raw logs."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import platform
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from huggingface_hub import snapshot_download

TRIAL_RE = re.compile(
    r"^Trial\s+(?P<trial>\d+):\s+"
    r"prompt_tps=(?P<prompt>[0-9.]+),\s+"
    r"generation_tps=(?P<generation>[0-9.]+),\s+"
    r"peak_memory=(?P<memory>[0-9.]+)$",
    re.MULTILINE,
)

DEFAULT_CONFIG = Path(__file__).with_name("benchmark_config.json")
PACKAGE_NAMES = ("mlx", "mlx-lm", "lm-eval", "transformers", "datasets")


def quantile(values: list[float], probability: float) -> float:
    """Return the R-7 linear quantile, NumPy's default method."""
    if not values:
        raise ValueError("cannot calculate a quantile from an empty sequence")
    if not 0 <= probability <= 1:
        raise ValueError("probability must be between 0 and 1")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def summarize(values: list[float], *, include_max: bool = False) -> dict[str, float]:
    result = {
        "median": median(values),
        "p10": quantile(values, 0.10),
        "p95": quantile(values, 0.95),
    }
    if include_max:
        result["max"] = max(values)
    return result


def parse_benchmark_output(output: str, expected_trials: int | None = None) -> dict[str, Any]:
    trials = [
        {
            "trial": int(match.group("trial")),
            "promptTokensPerSecond": float(match.group("prompt")),
            "generationTokensPerSecond": float(match.group("generation")),
            "peakMemoryGb": float(match.group("memory")),
        }
        for match in TRIAL_RE.finditer(output)
    ]
    if not trials:
        raise ValueError("mlx_lm.benchmark output contained no trial rows")
    if expected_trials is not None and len(trials) != expected_trials:
        raise ValueError(f"expected {expected_trials} trials, found {len(trials)}")
    if [trial["trial"] for trial in trials] != list(range(1, len(trials) + 1)):
        raise ValueError("trial numbers are not contiguous from 1")

    prompt = [trial["promptTokensPerSecond"] for trial in trials]
    generation = [trial["generationTokensPerSecond"] for trial in trials]
    memory = [trial["peakMemoryGb"] for trial in trials]
    return {
        "trials": trials,
        "summary": {
            "promptTokensPerSecond": summarize(prompt),
            "generationTokensPerSecond": summarize(generation),
            "peakMemoryGb": summarize(memory, include_max=True),
        },
    }


def parse_quality_result(payload: dict[str, Any], task: str) -> dict[str, Any]:
    try:
        result = payload[task]
        return {
            "name": result["name"],
            "alias": result["alias"],
            "samples": int(result["sample_len"]),
            "metrics": {
                "accuracy": float(result["acc,none"]),
                "accuracyStandardError": float(result["acc_stderr,none"]),
                "lengthNormalizedAccuracy": float(result["acc_norm,none"]),
                "lengthNormalizedAccuracyStandardError": float(
                    result["acc_norm_stderr,none"]
                ),
            },
        }
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid mlx_lm.evaluate result for task {task!r}") from error


def command_output(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout.strip()


def package_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for package in PACKAGE_NAMES:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def sanitized_hardware() -> dict[str, Any]:
    if sys.platform != "darwin":
        raise RuntimeError("MLX Metal benchmarks require macOS on Apple Silicon")

    profiler = json.loads(
        command_output(["system_profiler", "SPHardwareDataType", "SPDisplaysDataType", "-json"])
    )
    hardware_rows = profiler.get("SPHardwareDataType") or []
    display_rows = profiler.get("SPDisplaysDataType") or []
    if not hardware_rows:
        raise RuntimeError("system_profiler returned no hardware overview")
    hardware = hardware_rows[0]
    display = next(
        (
            row
            for row in display_rows
            if row.get("sppci_device_type") == "spdisplays_gpu"
        ),
        display_rows[0] if display_rows else {},
    )
    gpu_cores = display.get("sppci_cores")
    os_version = command_output(["sw_vers", "-productVersion"])
    os_build = command_output(["sw_vers", "-buildVersion"])

    import mlx.core as mx

    device = mx.device_info()
    return {
        "machine": hardware.get("machine_name"),
        "modelIdentifier": hardware.get("machine_model"),
        "chip": hardware.get("chip_type"),
        "cpuTopology": hardware.get("number_processors"),
        "gpuCores": int(gpu_cores) if gpu_cores is not None else None,
        "unifiedMemory": hardware.get("physical_memory"),
        "macos": os_version,
        "macosBuild": os_build,
        "mlxDefaultDevice": str(mx.default_device()),
        "mlxDevice": {
            "name": device.get("device_name"),
            "architecture": device.get("architecture"),
            "memoryBytes": device.get("memory_size"),
            "recommendedWorkingSetBytes": device.get("max_recommended_working_set_size"),
        },
        "powerSource": command_output(["pmset", "-g", "ps"]).splitlines()[0],
        "thermalStatus": command_output(["pmset", "-g", "therm"]).splitlines(),
    }


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text())
    if config.get("schemaVersion") != "tasc-mlx-benchmark-config-v1":
        raise ValueError("unsupported benchmark config schema")
    if not config.get("models") or not config.get("scenarios"):
        raise ValueError("benchmark config requires models and scenarios")
    if int(config.get("numTrials", 0)) < 1:
        raise ValueError("benchmark config numTrials must be positive")
    return config


def select(items: list[dict[str, Any]], requested: list[str], kind: str) -> list[dict[str, Any]]:
    if not requested:
        return items
    by_key = {item["key"]: item for item in items}
    unknown = sorted(set(requested) - by_key.keys())
    if unknown:
        raise ValueError(f"unknown {kind} key(s): {', '.join(unknown)}")
    return [by_key[key] for key in requested]


def run(args: argparse.Namespace) -> Path:
    config = load_config(args.config)
    models = select(config["models"], args.model, "model")
    scenarios = select(config["scenarios"], args.scenario, "scenario")
    quality_config = config.get("qualityEvaluation")
    if not args.skip_quality and not quality_config:
        raise ValueError("benchmark config requires qualityEvaluation unless --skip-quality is used")
    output_dir = args.output.resolve()
    raw_dir = output_dir / "raw"
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    raw_dir.mkdir(parents=True)

    benchmark_executable = shlex.split(args.benchmark_command)
    evaluate_executable = shlex.split(args.evaluate_command)
    measured_at = datetime.now(timezone.utc).isoformat()
    environment = {
        "python": platform.python_version(),
        "packages": package_versions(),
        "hardware": sanitized_hardware(),
    }
    results: dict[str, Any] = {
        "schemaVersion": "tasc-mlx-throughput-results-v1",
        "suiteStartedAtUtc": measured_at,
        "runner": "benchmarks/mlx/run_benchmarks.py",
        "quantiles": "R-7 linear interpolation; median, p10, and p95 over timed trials",
        "warmup": "one built-in mlx_lm.benchmark warmup before timed trials",
        "environment": environment,
        "models": models,
        "runs": [],
    }
    quality_results: list[dict[str, Any]] = []

    for model in models:
        print(f"Downloading pinned snapshot {model['repoId']}@{model['revision']}...", flush=True)
        model_path = snapshot_download(model["repoId"], revision=model["revision"])
        for scenario in scenarios:
            raw_name = f"{model['key']}--{scenario['key']}.log"
            command = [
                *benchmark_executable,
                "--model",
                model_path,
                "--prompt-tokens",
                str(scenario["promptTokens"]),
                "--generation-tokens",
                str(scenario["generationTokens"]),
                "--batch-size",
                str(scenario["batchSize"]),
                "--num-trials",
                str(config["numTrials"]),
            ]
            print(f"Running {model['key']} / {scenario['key']}...", flush=True)
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            (raw_dir / raw_name).write_text(completed.stdout)
            if completed.returncode != 0:
                raise RuntimeError(
                    f"benchmark failed for {model['key']} / {scenario['key']}; see {raw_dir / raw_name}"
                )
            parsed = parse_benchmark_output(completed.stdout, config["numTrials"])
            results["runs"].append(
                {
                    "modelKey": model["key"],
                    "modelRevision": model["revision"],
                    "scenario": scenario,
                    "processIsolation": "fresh mlx_lm.benchmark process",
                    "rawLog": f"raw/{raw_name}",
                    **parsed,
                }
            )

        if args.skip_quality:
            continue

        task = quality_config["task"]
        raw_json_name = f"{model['key']}--{task}.json"
        quality_command = [
            *evaluate_executable,
            "--model",
            model_path,
            "--tasks",
            task,
            "--batch-size",
            str(quality_config["batchSize"]),
            "--num-shots",
            str(quality_config["numShots"]),
            "--seed",
            str(quality_config["seed"]),
        ]
        if quality_config.get("applyChatTemplate"):
            quality_command.append("--apply-chat-template")
        if quality_config.get("limit") is not None:
            quality_command.extend(["--limit", str(quality_config["limit"])])

        print(f"Running {model['key']} / {task} full quality eval...", flush=True)
        with tempfile.TemporaryDirectory(prefix="tasc-mlx-quality-") as quality_output:
            quality_command.extend(["--output-dir", quality_output])
            completed = subprocess.run(
                quality_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if completed.returncode != 0:
                failure_log = raw_dir / f"{model['key']}--{task}.failed.log"
                failure_log.write_text(completed.stdout)
                raise RuntimeError(
                    f"quality eval failed for {model['key']} / {task}; see {failure_log}"
                )
            output_files = [path for path in Path(quality_output).iterdir() if path.is_file()]
            if len(output_files) != 1:
                raise RuntimeError(
                    f"quality eval for {model['key']} / {task} produced "
                    f"{len(output_files)} result files; expected one"
                )
            raw_payload = json.loads(output_files[0].read_text())

        parsed_quality = parse_quality_result(raw_payload, task)
        (raw_dir / raw_json_name).write_text(json.dumps(raw_payload, indent=2) + "\n")
        quality_results.append(
            {
                "modelKey": model["key"],
                "repoId": model["repoId"],
                "modelRevision": model["revision"],
                **parsed_quality,
                "rawResult": f"raw/{raw_json_name}",
            }
        )

    result_path = output_dir / "throughput.json"
    result_path.write_text(json.dumps(results, indent=2) + "\n")
    print(f"Wrote {result_path}", flush=True)

    if not args.skip_quality:
        quality_path = output_dir / "quality.json"
        quality_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "tasc-mlx-quality-results-v1",
                    "suiteStartedAtUtc": measured_at,
                    "runner": "benchmarks/mlx/run_benchmarks.py",
                    "environment": environment,
                    "evaluation": quality_config,
                    "method": (
                        "Multiple-choice continuation log-likelihood through "
                        "mlx_lm.evaluate; acc_norm is length-normalized accuracy."
                    ),
                    "results": quality_results,
                },
                indent=2,
            )
            + "\n"
        )
        print(f"Wrote {quality_path}", flush=True)
    return result_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--benchmark-command",
        default="mlx_lm.benchmark",
        help="benchmark executable, optionally with fixed prefix arguments",
    )
    parser.add_argument(
        "--evaluate-command",
        default="mlx_lm.evaluate",
        help="quality-evaluation executable, optionally with fixed prefix arguments",
    )
    parser.add_argument(
        "--skip-quality",
        action="store_true",
        help="run only the throughput matrix",
    )
    parser.add_argument("--model", action="append", default=[], help="model key; repeat to select")
    parser.add_argument("--scenario", action="append", default=[], help="scenario key; repeat to select")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        run(parse_args())
    except (FileExistsError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
