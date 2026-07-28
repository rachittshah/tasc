#!/usr/bin/env python3
"""Run pinned mlx-lm throughput trials and write reviewable JSON plus raw logs."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import os
import platform
import re
import select
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Mapping, NamedTuple, Sequence

TRIAL_RE = re.compile(
    r"^Trial\s+(?P<trial>\d+):\s+"
    r"prompt_tps=(?P<prompt>[0-9.]+),\s+"
    r"generation_tps=(?P<generation>[0-9.]+),\s+"
    r"peak_memory=(?P<memory>[0-9.]+)$",
    re.MULTILINE,
)

DEFAULT_CONFIG = Path(__file__).with_name("benchmark_config.json")
PACKAGE_NAMES = ("mlx", "mlx-lm", "lm-eval", "transformers", "datasets")
SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
REPO_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}$"
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_CONFIG_BYTES = 1_048_576
MAX_PROCESS_OUTPUT_BYTES = 16 * 1_048_576
MAX_QUALITY_RESULT_BYTES = 64 * 1_048_576
MAX_COMMAND_PARTS = 128
MAX_COMMAND_PART_BYTES = 4_096
MAX_TIMEOUT_SECONDS = 86_400
MAX_MODELS = 16
MAX_SCENARIOS = 32
MAX_TRIALS = 100
MAX_SUITE_PROCESSES = 64
MAX_SUITE_TOKEN_POSITIONS = 100_000_000
MAX_SUITE_TIMEOUT_BUDGET_SECONDS = 7 * 24 * 60 * 60
DEFAULT_DOWNLOAD_TIMEOUT_SECONDS = 3_600
DEFAULT_BENCHMARK_TIMEOUT_SECONDS = 3_600
DEFAULT_EVALUATE_TIMEOUT_SECONDS = 21_600
METADATA_TIMEOUT_SECONDS = 30
ALLOWED_CHILD_ENVIRONMENT = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "HF_HOME",
    "HF_HUB_CACHE",
    "TRANSFORMERS_CACHE",
)


class BoundedCommandResult(NamedTuple):
    returncode: int
    output: str


class BoundedCommandFailure(RuntimeError):
    """A timeout/output-limit failure with bounded output for a local raw log."""

    def __init__(self, reason: str, output: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.output = output


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


def parse_benchmark_output(
    output: str,
    expected_trials: int | None = None,
) -> dict[str, Any]:
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


def finite_float(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite number")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"{label} must be a finite number")
    return parsed


def positive_integer(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < 1 or value > maximum:
        raise ValueError(f"{label} must be between 1 and {maximum}")
    return value


def parse_quality_result(payload: dict[str, Any], task: str) -> dict[str, Any]:
    try:
        result = payload[task]
        samples = positive_integer(result["sample_len"], "sample_len", 100_000_000)
        name = result["name"]
        alias = result["alias"]
        if not isinstance(name, str) or not name:
            raise ValueError("quality result name must be a non-empty string")
        if not isinstance(alias, str) or not alias:
            raise ValueError("quality result alias must be a non-empty string")
        return {
            "name": name,
            "alias": alias,
            "samples": samples,
            "metrics": {
                "accuracy": finite_float(result["acc,none"], "accuracy"),
                "accuracyStandardError": finite_float(
                    result["acc_stderr,none"],
                    "accuracy standard error",
                ),
                "lengthNormalizedAccuracy": finite_float(
                    result["acc_norm,none"],
                    "length-normalized accuracy",
                ),
                "lengthNormalizedAccuracyStandardError": finite_float(
                    result["acc_norm_stderr,none"],
                    "length-normalized accuracy standard error",
                ),
            },
        }
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            f"invalid mlx_lm.evaluate result for task {task!r}"
        ) from error


def reduced_environment(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source_environment = os.environ if source is None else source
    environment = {
        key: value
        for key in ALLOWED_CHILD_ENVIRONMENT
        if (value := source_environment.get(key)) is not None
        and len(value.encode("utf-8")) <= 8_192
    }
    environment.setdefault("PATH", os.defpath)
    environment.update(
        {
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
            "TOKENIZERS_PARALLELISM": "false",
        }
    )
    return environment


def validate_command(command: Sequence[str]) -> list[str]:
    if not command or len(command) > MAX_COMMAND_PARTS:
        raise ValueError(
            f"command must contain between 1 and {MAX_COMMAND_PARTS} arguments"
        )
    snapshot: list[str] = []
    for part in command:
        if not isinstance(part, str) or not part or "\0" in part:
            raise ValueError("command arguments must be non-empty strings without NUL")
        if len(part.encode("utf-8")) > MAX_COMMAND_PART_BYTES:
            raise ValueError(
                f"command arguments must be at most {MAX_COMMAND_PART_BYTES} bytes"
            )
        snapshot.append(part)
    return snapshot


def terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    leader_exit_observed: bool = False,
) -> None:
    try:
        if os.name == "posix":
            # The leader may have exited while a descendant still holds the
            # capture pipe. Its process group remains addressable by the
            # original leader PID and must still be terminated.
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin reports EPERM when the reserved process group contains only
        # the unreaped (zombie) leader. This is safe to accept only after an
        # exit event was observed without reaping; a timeout-path EPERM still
        # propagates so containment can never silently fail.
        if not (sys.platform == "darwin" and leader_exit_observed):
            raise
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def wait_for_macos_leader_exit_without_reaping(
    process: subprocess.Popen[bytes],
    deadline: float,
    output: bytearray,
) -> None:
    if not hasattr(select, "kqueue") or not hasattr(select, "kevent"):
        terminate_process_group(process)
        raise RuntimeError(
            "bounded macOS process cleanup requires kqueue process events"
        )

    # Some python.org 3.12 macOS builds expose kqueue/kevent but omit the
    # process-filter constants documented by CPython. These values are stable
    # Darwin ABI constants from <sys/event.h>; prefer the runtime exports when
    # present and use the XNU values only on macOS.
    def kqueue_constant(name: str, darwin_value: int) -> int:
        exported = getattr(select, name, None)
        if isinstance(exported, int):
            return exported
        if sys.platform == "darwin":
            return darwin_value
        terminate_process_group(process)
        raise RuntimeError(
            f"bounded macOS process cleanup requires select.{name}"
        )

    filter_proc = kqueue_constant("KQ_FILTER_PROC", -5)
    event_add = kqueue_constant("KQ_EV_ADD", 0x0001)
    event_enable = kqueue_constant("KQ_EV_ENABLE", 0x0004)
    event_oneshot = kqueue_constant("KQ_EV_ONESHOT", 0x0010)
    note_exit = kqueue_constant("KQ_NOTE_EXIT", 0x80000000)

    queue = select.kqueue()
    try:
        exit_event = select.kevent(
            process.pid,
            filter=filter_proc,
            flags=event_add | event_enable | event_oneshot,
            fflags=note_exit,
        )
        # Register while the leader is deliberately unreaped. NOTE_EXIT remains
        # observable for a zombie, so the PID continues to reserve its PGID.
        queue.control([exit_event], 0, 0)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_process_group(process)
                raise BoundedCommandFailure(
                    "command timed out before its leader exited",
                    output.decode("utf-8", errors="replace"),
                )
            try:
                events = queue.control(None, 1, remaining)
            except InterruptedError:
                continue
            if events:
                return
    finally:
        queue.close()


def reap_leader_after_group_shutdown(
    process: subprocess.Popen[bytes],
    deadline: float,
    output: bytearray,
) -> int:
    if os.name != "posix":
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            terminate_process_group(process)
            raise BoundedCommandFailure(
                "command timed out before its leader exited",
                output.decode("utf-8", errors="replace"),
            )
        try:
            return process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            terminate_process_group(process)
            raise BoundedCommandFailure(
                "command timed out before its leader exited",
                output.decode("utf-8", errors="replace"),
            ) from error

    if sys.platform == "darwin" and (
        not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT")
    ):
        # Python 3.12 does not expose waitid() on macOS. kqueue NOTE_EXIT
        # provides the same non-reaping observation needed to keep the
        # leader PID/PGID reserved until every descendant has been killed.
        wait_for_macos_leader_exit_without_reaping(
            process,
            deadline,
            output,
        )
        terminate_process_group(process, leader_exit_observed=True)
        return process.wait()

    if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        terminate_process_group(process)
        raise RuntimeError(
            "bounded POSIX process cleanup requires waitid with WNOWAIT"
        )

    wait_options = os.WEXITED | os.WNOHANG | os.WNOWAIT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            terminate_process_group(process)
            raise BoundedCommandFailure(
                "command timed out before its leader exited",
                output.decode("utf-8", errors="replace"),
            )
        status = os.waitid(os.P_PID, process.pid, wait_options)
        if status is not None:
            # The unreaped leader reserves both its PID and process-group ID.
            # Kill the group before poll()/wait() can release that identity.
            terminate_process_group(process, leader_exit_observed=True)
            return process.wait()
        time.sleep(min(0.01, remaining))


def run_bounded_command(
    command: Sequence[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int = MAX_PROCESS_OUTPUT_BYTES,
    environment: Mapping[str, str] | None = None,
) -> BoundedCommandResult:
    command_snapshot = validate_command(command)
    timeout = positive_integer(
        timeout_seconds,
        "command timeout",
        MAX_TIMEOUT_SECONDS,
    )
    limit = positive_integer(
        max_output_bytes,
        "command output limit",
        512 * 1_048_576,
    )
    process = subprocess.Popen(
        command_snapshot,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=dict(environment) if environment is not None else reduced_environment(),
        start_new_session=os.name == "posix",
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout
    pipe_open = True
    failure_reason: str | None = None
    try:
        while pipe_open:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure_reason = f"command timed out after {timeout} seconds"
                break
            events = selector.select(min(0.1, remaining))
            if not events:
                continue
            capacity = limit + 1 - len(output)
            chunk = os.read(process.stdout.fileno(), min(65_536, capacity))
            if not chunk:
                selector.unregister(process.stdout)
                pipe_open = False
                continue
            output.extend(chunk)
            if len(output) > limit:
                failure_reason = (
                    f"command output exceeded the {limit}-byte capture limit"
                )
                break

        if failure_reason is not None:
            terminate_process_group(process)
            raise BoundedCommandFailure(
                failure_reason,
                output[:limit].decode("utf-8", errors="replace"),
            )

        returncode = reap_leader_after_group_shutdown(
            process,
            deadline,
            output,
        )
        return BoundedCommandResult(
            returncode=returncode,
            output=output.decode("utf-8", errors="replace"),
        )
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            terminate_process_group(process)


def command_output(command: list[str]) -> str:
    result = run_bounded_command(
        command,
        timeout_seconds=METADATA_TIMEOUT_SECONDS,
        max_output_bytes=4 * 1_048_576,
    )
    if result.returncode != 0:
        raise RuntimeError("hardware metadata command failed")
    return result.output.strip()


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

    profiler = strict_json_loads(
        command_output(
            [
                "system_profiler",
                "SPHardwareDataType",
                "SPDisplaysDataType",
                "-json",
            ]
        ),
        "system_profiler output",
    )
    if not isinstance(profiler, dict):
        raise RuntimeError("system_profiler returned an invalid payload")
    hardware_rows = profiler.get("SPHardwareDataType") or []
    display_rows = profiler.get("SPDisplaysDataType") or []
    if (
        not isinstance(hardware_rows, list)
        or not hardware_rows
        or len(hardware_rows) > 128
        or not all(isinstance(row, dict) for row in hardware_rows)
        or not isinstance(display_rows, list)
        or len(display_rows) > 128
        or not all(isinstance(row, dict) for row in display_rows)
    ):
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

    # Imported only on the supported host so parser/validation tests stay
    # portable and Linux CI never needs the Metal-only package.
    import mlx.core as mx

    device = mx.device_info()
    power_lines = command_output(["pmset", "-g", "ps"]).splitlines()
    if not power_lines:
        raise RuntimeError("pmset returned no power-source metadata")
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
            "recommendedWorkingSetBytes": device.get(
                "max_recommended_working_set_size"
            ),
        },
        "powerSource": power_lines[0],
        "thermalStatus": command_output(["pmset", "-g", "therm"]).splitlines(),
    }


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r} is forbidden")
        result[key] = value
    return result


def strict_json_loads(payload: str | bytes, label: str) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as error:
        raise ValueError(f"{label} is not valid bounded JSON") from error


def read_bounded_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{path} must be a regular file")
        if before.st_size > maximum_bytes:
            raise ValueError(f"{path} exceeds the {maximum_bytes}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError(f"{path} exceeds the {maximum_bytes}-byte limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError(f"{path} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_safe_key(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_KEY_RE.fullmatch(value):
        raise ValueError(f"{label} must be a safe 1-96 character key")
    if value in {".", ".."}:
        raise ValueError(f"{label} cannot be a path segment")
    return value


def reject_unknown_keys(
    value: Mapping[str, Any],
    allowed: set[str],
    label: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(
            f"{label} contains unknown field(s): {', '.join(unknown)}"
        )


def optional_bounded_string(
    value: Mapping[str, Any],
    field: str,
    label: str,
    maximum_bytes: int,
) -> None:
    if field not in value:
        return
    candidate = value[field]
    if (
        not isinstance(candidate, str)
        or not candidate
        or len(candidate.encode("utf-8")) > maximum_bytes
    ):
        raise ValueError(
            f"{label}.{field} must be a non-empty string of at most "
            f"{maximum_bytes} bytes"
        )


def validate_config(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("benchmark config must be a JSON object")
    reject_unknown_keys(
        config,
        {
            "schemaVersion",
            "models",
            "scenarios",
            "qualityEvaluation",
            "numTrials",
        },
        "benchmark config",
    )
    if config.get("schemaVersion") != "tasc-mlx-benchmark-config-v1":
        raise ValueError("unsupported benchmark config schema")
    models = config.get("models")
    scenarios = config.get("scenarios")
    if (
        not isinstance(models, list)
        or not models
        or len(models) > MAX_MODELS
        or not isinstance(scenarios, list)
        or not scenarios
        or len(scenarios) > MAX_SCENARIOS
    ):
        raise ValueError(
            f"benchmark config requires 1-{MAX_MODELS} models and "
            f"1-{MAX_SCENARIOS} scenarios"
        )

    model_keys: set[str] = set()
    for index, model in enumerate(models):
        if not isinstance(model, dict):
            raise ValueError(f"models[{index}] must be an object")
        reject_unknown_keys(
            model,
            {
                "key",
                "repoId",
                "revision",
                "parameters",
                "released",
                "precision",
                "license",
                "releaseUrl",
                "modelUrl",
            },
            f"models[{index}]",
        )
        key = validate_safe_key(model.get("key"), f"models[{index}].key")
        if key in model_keys:
            raise ValueError(f"duplicate model key {key!r}")
        model_keys.add(key)
        repo_id = model.get("repoId")
        if (
            not isinstance(repo_id, str)
            or not REPO_ID_RE.fullmatch(repo_id)
            or ".." in repo_id
        ):
            raise ValueError(f"models[{index}].repoId must be owner/model")
        revision = model.get("revision")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            raise ValueError(
                f"models[{index}].revision must be a full lowercase 40-hex commit"
            )
        positive_integer(
            model.get("parameters"),
            f"models[{index}].parameters",
            10_000_000_000_000,
        )
        for field in ("released", "precision", "license"):
            optional_bounded_string(model, field, f"models[{index}]", 512)
        for field in ("releaseUrl", "modelUrl"):
            optional_bounded_string(model, field, f"models[{index}]", 2_048)
            if field in model and not model[field].startswith("https://"):
                raise ValueError(f"models[{index}].{field} must use HTTPS")

    scenario_keys: set[str] = set()
    token_positions_per_model = 0
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise ValueError(f"scenarios[{index}] must be an object")
        reject_unknown_keys(
            scenario,
            {
                "key",
                "promptTokens",
                "generationTokens",
                "batchSize",
            },
            f"scenarios[{index}]",
        )
        key = validate_safe_key(
            scenario.get("key"),
            f"scenarios[{index}].key",
        )
        if key in scenario_keys:
            raise ValueError(f"duplicate scenario key {key!r}")
        scenario_keys.add(key)
        prompt_tokens = positive_integer(
            scenario.get("promptTokens"),
            f"scenarios[{index}].promptTokens",
            262_144,
        )
        generation_tokens = positive_integer(
            scenario.get("generationTokens"),
            f"scenarios[{index}].generationTokens",
            262_144,
        )
        batch_size = positive_integer(
            scenario.get("batchSize"),
            f"scenarios[{index}].batchSize",
            256,
        )

        token_positions_per_model += (
            prompt_tokens + generation_tokens
        ) * batch_size

    num_trials = positive_integer(
        config.get("numTrials"),
        "numTrials",
        MAX_TRIALS,
    )
    process_count = len(models) * (
        len(scenarios) + (1 if config.get("qualityEvaluation") is not None else 0)
    )
    if process_count > MAX_SUITE_PROCESSES:
        raise ValueError(
            "benchmark config exceeds the bounded process-count work budget"
        )
    suite_token_positions = (
        len(models) * token_positions_per_model * num_trials
    )
    if suite_token_positions > MAX_SUITE_TOKEN_POSITIONS:
        raise ValueError(
            "benchmark config exceeds the bounded token-position work budget"
        )
    quality = config.get("qualityEvaluation")
    if quality is not None:
        if not isinstance(quality, dict):
            raise ValueError("qualityEvaluation must be an object")
        reject_unknown_keys(
            quality,
            {
                "task",
                "split",
                "numShots",
                "batchSize",
                "seed",
                "applyChatTemplate",
                "limit",
            },
            "qualityEvaluation",
        )
        validate_safe_key(quality.get("task"), "qualityEvaluation.task")
        if "split" in quality:
            validate_safe_key(
                quality.get("split"),
                "qualityEvaluation.split",
            )
        positive_integer(
            quality.get("batchSize"),
            "qualityEvaluation.batchSize",
            256,
        )
        shots = quality.get("numShots")
        if (
            isinstance(shots, bool)
            or not isinstance(shots, int)
            or shots < 0
            or shots > 1_000
        ):
            raise ValueError(
                "qualityEvaluation.numShots must be between 0 and 1000"
            )
        seed = quality.get("seed")
        if (
            isinstance(seed, bool)
            or not isinstance(seed, int)
            or abs(seed) > 9_007_199_254_740_991
        ):
            raise ValueError(
                "qualityEvaluation.seed must be an I-JSON integer"
            )
        limit = quality.get("limit")
        if limit is not None:
            positive_integer(limit, "qualityEvaluation.limit", 100_000_000)
        if not isinstance(quality.get("applyChatTemplate"), bool):
            raise ValueError(
                "qualityEvaluation.applyChatTemplate must be boolean"
            )
    return config


def load_config(path: Path) -> dict[str, Any]:
    payload = read_bounded_file(path.resolve(strict=True), MAX_CONFIG_BYTES)
    return validate_config(strict_json_loads(payload, "benchmark config"))


def select(
    items: list[dict[str, Any]],
    requested: list[str],
    kind: str,
) -> list[dict[str, Any]]:
    if not requested:
        return items
    if len(requested) != len(set(requested)):
        raise ValueError(f"duplicate requested {kind} key")
    for key in requested:
        validate_safe_key(key, f"requested {kind} key")
    by_key = {item["key"]: item for item in items}
    unknown = sorted(set(requested) - by_key.keys())
    if unknown:
        raise ValueError(f"unknown {kind} key(s): {', '.join(unknown)}")
    return [by_key[key] for key in requested]


def parse_command(value: str, label: str) -> list[str]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 32_768:
        raise ValueError(f"{label} must be a bounded command string")
    try:
        return validate_command(shlex.split(value))
    except ValueError as error:
        raise ValueError(f"invalid {label}: {error}") from error


def assert_contained(parent: Path, child: Path) -> None:
    try:
        child.relative_to(parent)
    except ValueError as error:
        raise ValueError(f"path {child} escapes trusted directory {parent}") from error


def create_output_directory(path: Path) -> tuple[Path, tuple[int, int]]:
    output = path.resolve(strict=False)
    parent = output.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"output parent is not a directory: {parent}")
    assert_contained(parent, output)
    try:
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as error:
        raise FileExistsError(f"output directory already exists: {output}") from error
    stats = output.lstat()
    if not stat.S_ISDIR(stats.st_mode) or stat.S_ISLNK(stats.st_mode):
        raise RuntimeError("new output path is not a trusted directory")
    return output, (stats.st_dev, stats.st_ino)


def cleanup_owned_output(path: Path, identity: tuple[int, int]) -> None:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
        ):
            raise RuntimeError(
                "refusing to clean an output path whose identity changed"
            )

        # Walk relative to the already-opened directory. If the pathname is
        # swapped concurrently, deletion stays on the exact inode we created.
        for _, directories, files, directory_descriptor in os.fwalk(
            ".",
            topdown=False,
            follow_symlinks=False,
            dir_fd=descriptor,
        ):
            for name in files:
                os.unlink(name, dir_fd=directory_descriptor)
            for name in directories:
                member = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(member.st_mode):
                    os.unlink(name, dir_fd=directory_descriptor)
                else:
                    os.rmdir(name, dir_fd=directory_descriptor)

        # Intentionally retain the empty root reservation. POSIX/macOS has no
        # atomic "rmdir only if this inode" operation; removing the pathname
        # after an identity check would reintroduce a check/delete race against
        # a replacement directory.
    finally:
        os.close(descriptor)


def write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing benchmark evidence")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_exclusive(path: Path, payload: Any) -> None:
    write_exclusive(
        path,
        (json.dumps(payload, indent=2, allow_nan=False) + "\n").encode("utf-8"),
    )


def download_environment() -> dict[str, str]:
    environment = reduced_environment()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ):
        value = os.environ.get(key)
        if value is not None and len(value.encode("utf-8")) <= 8_192:
            environment[key] = value
    environment["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    return environment


def download_model_snapshot(
    repo_id: str,
    revision: str,
    *,
    timeout_seconds: int,
) -> Path:
    # Run the optional Hugging Face integration in a bounded child. Parser and
    # validation tests remain portable, credentials are not inherited, and a
    # stalled network transfer cannot hold the suite forever.
    program = (
        "from huggingface_hub import snapshot_download\n"
        "import json\n"
        "import sys\n"
        "path = snapshot_download("
        "sys.argv[1], revision=sys.argv[2], repo_type='model', token=False)\n"
        "print(json.dumps({'path': path}, separators=(',', ':')))\n"
    )
    result = run_bounded_command(
        [sys.executable, "-c", program, repo_id, revision],
        timeout_seconds=timeout_seconds,
        max_output_bytes=1_048_576,
        environment=download_environment(),
    )
    if result.returncode != 0:
        raise RuntimeError("pinned model snapshot download failed")
    lines = [line for line in result.output.splitlines() if line]
    if not lines:
        raise RuntimeError("snapshot downloader returned no local path")
    payload = strict_json_loads(lines[-1], "snapshot downloader result")
    if (
        not isinstance(payload, dict)
        or set(payload) != {"path"}
        or not isinstance(payload["path"], str)
        or not payload["path"]
    ):
        raise RuntimeError("snapshot downloader returned an invalid local path")
    snapshot = Path(payload["path"]).resolve(strict=True)
    if not snapshot.is_dir():
        raise RuntimeError("downloaded model snapshot is not a directory")
    return snapshot


def quality_result_file(directory: Path) -> Path:
    only_path: str | None = None
    only_is_file = False
    with os.scandir(directory) as entries:
        for entry in entries:
            if only_path is not None:
                raise RuntimeError(
                    "quality eval must produce exactly one regular result file"
                )
            only_path = entry.path
            only_is_file = entry.is_file(follow_symlinks=False)
    if only_path is None or not only_is_file:
        raise RuntimeError(
            "quality eval must produce exactly one regular result file"
        )
    result = Path(only_path).resolve(strict=True)
    assert_contained(directory.resolve(strict=True), result)
    return result


def run(args: argparse.Namespace) -> Path:
    config = load_config(args.config)
    models = select(config["models"], args.model, "model")
    scenarios = select(config["scenarios"], args.scenario, "scenario")
    quality_config = config.get("qualityEvaluation")
    if not args.skip_quality and not quality_config:
        raise ValueError(
            "benchmark config requires qualityEvaluation unless "
            "--skip-quality is used"
        )
    benchmark_executable = parse_command(
        args.benchmark_command,
        "benchmark command",
    )
    evaluate_executable = parse_command(
        args.evaluate_command,
        "evaluate command",
    )
    benchmark_timeout = positive_integer(
        args.benchmark_timeout_seconds,
        "benchmark timeout",
        MAX_TIMEOUT_SECONDS,
    )
    evaluate_timeout = positive_integer(
        args.evaluate_timeout_seconds,
        "evaluate timeout",
        MAX_TIMEOUT_SECONDS,
    )
    download_timeout = positive_integer(
        args.download_timeout_seconds,
        "download timeout",
        MAX_TIMEOUT_SECONDS,
    )
    benchmark_processes = len(models) * len(scenarios)
    quality_processes = 0 if args.skip_quality else len(models)
    suite_timeout_budget = (
        len(models) * download_timeout
        + benchmark_processes * benchmark_timeout
        + quality_processes * evaluate_timeout
    )
    if suite_timeout_budget > MAX_SUITE_TIMEOUT_BUDGET_SECONDS:
        raise ValueError(
            "selected matrix and deadlines exceed the whole-suite time budget"
        )

    output_dir, output_identity = create_output_directory(args.output)
    try:
        raw_dir = output_dir / "raw"
        assert_contained(output_dir, raw_dir)
        raw_dir.mkdir(mode=0o700, parents=False, exist_ok=False)

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
            "quantiles": (
                "R-7 linear interpolation; median, p10, and p95 "
                "over timed trials"
            ),
            "warmup": "one built-in mlx_lm.benchmark warmup before timed trials",
            "environment": environment,
            "models": models,
            "runs": [],
        }
        quality_results: list[dict[str, Any]] = []
        child_environment = reduced_environment()

        for model in models:
            print(
                f"Downloading pinned snapshot "
                f"{model['repoId']}@{model['revision']}...",
                flush=True,
            )
            model_path = download_model_snapshot(
                model["repoId"],
                model["revision"],
                timeout_seconds=download_timeout,
            )
            for scenario in scenarios:
                raw_name = f"{model['key']}--{scenario['key']}.log"
                raw_path = raw_dir / raw_name
                assert_contained(raw_dir, raw_path)
                command = [
                    *benchmark_executable,
                    "--model",
                    str(model_path),
                    "--prompt-tokens",
                    str(scenario["promptTokens"]),
                    "--generation-tokens",
                    str(scenario["generationTokens"]),
                    "--batch-size",
                    str(scenario["batchSize"]),
                    "--num-trials",
                    str(config["numTrials"]),
                ]
                print(
                    f"Running {model['key']} / {scenario['key']}...",
                    flush=True,
                )
                try:
                    completed = run_bounded_command(
                        command,
                        timeout_seconds=benchmark_timeout,
                        environment=child_environment,
                    )
                except BoundedCommandFailure as error:
                    write_exclusive(raw_path, error.output.encode("utf-8"))
                    raise RuntimeError(
                        f"benchmark {error.reason} for {model['key']} / "
                        f"{scenario['key']}; see {raw_path}"
                    ) from error
                write_exclusive(raw_path, completed.output.encode("utf-8"))
                if completed.returncode != 0:
                    raise RuntimeError(
                        f"benchmark failed for {model['key']} / "
                        f"{scenario['key']}; see {raw_path}"
                    )
                parsed = parse_benchmark_output(
                    completed.output,
                    config["numTrials"],
                )
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
            raw_json_path = raw_dir / raw_json_name
            assert_contained(raw_dir, raw_json_path)
            quality_command = [
                *evaluate_executable,
                "--model",
                str(model_path),
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
                quality_command.extend(
                    ["--limit", str(quality_config["limit"])]
                )

            print(
                f"Running {model['key']} / {task} full quality eval...",
                flush=True,
            )
            with tempfile.TemporaryDirectory(
                prefix="tasc-mlx-quality-"
            ) as quality_output:
                quality_directory = Path(quality_output).resolve(strict=True)
                quality_command.extend(
                    ["--output-dir", str(quality_directory)]
                )
                try:
                    completed = run_bounded_command(
                        quality_command,
                        timeout_seconds=evaluate_timeout,
                        environment=child_environment,
                    )
                except BoundedCommandFailure as error:
                    failure_log = raw_dir / (
                        f"{model['key']}--{task}.failed.log"
                    )
                    write_exclusive(
                        failure_log,
                        error.output.encode("utf-8"),
                    )
                    raise RuntimeError(
                        f"quality eval {error.reason} for {model['key']} / "
                        f"{task}; see {failure_log}"
                    ) from error
                if completed.returncode != 0:
                    failure_log = raw_dir / (
                        f"{model['key']}--{task}.failed.log"
                    )
                    write_exclusive(
                        failure_log,
                        completed.output.encode("utf-8"),
                    )
                    raise RuntimeError(
                        f"quality eval failed for {model['key']} / "
                        f"{task}; see {failure_log}"
                    )
                output_file = quality_result_file(quality_directory)
                raw_payload = strict_json_loads(
                    read_bounded_file(
                        output_file,
                        MAX_QUALITY_RESULT_BYTES,
                    ),
                    "quality result",
                )
                if not isinstance(raw_payload, dict):
                    raise ValueError("quality result must be a JSON object")

            parsed_quality = parse_quality_result(raw_payload, task)
            write_json_exclusive(raw_json_path, raw_payload)
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
        write_json_exclusive(result_path, results)
        print(f"Wrote {result_path}", flush=True)

        if not args.skip_quality:
            quality_path = output_dir / "quality.json"
            write_json_exclusive(
                quality_path,
                {
                    "schemaVersion": "tasc-mlx-quality-results-v1",
                    "suiteStartedAtUtc": measured_at,
                    "runner": "benchmarks/mlx/run_benchmarks.py",
                    "environment": environment,
                    "evaluation": quality_config,
                    "method": (
                        "Multiple-choice continuation log-likelihood through "
                        "mlx_lm.evaluate; acc_norm is length-normalized "
                        "accuracy."
                    ),
                    "results": quality_results,
                },
            )
            print(f"Wrote {quality_path}", flush=True)
        return result_path
    except BaseException as error:
        try:
            cleanup_owned_output(output_dir, output_identity)
        except Exception as cleanup_error:
            raise RuntimeError(
                "benchmark failed and its output could not be cleaned safely"
            ) from ExceptionGroup(
                "benchmark failure plus cleanup failure",
                [error, cleanup_error],
            )
        raise


def timeout_argument(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer") from error
    try:
        return positive_integer(parsed, "timeout", MAX_TIMEOUT_SECONDS)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
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
        "--download-timeout-seconds",
        type=timeout_argument,
        default=DEFAULT_DOWNLOAD_TIMEOUT_SECONDS,
        help="hard timeout for each pinned model download",
    )
    parser.add_argument(
        "--benchmark-timeout-seconds",
        type=timeout_argument,
        default=DEFAULT_BENCHMARK_TIMEOUT_SECONDS,
        help="hard timeout for each throughput process",
    )
    parser.add_argument(
        "--evaluate-timeout-seconds",
        type=timeout_argument,
        default=DEFAULT_EVALUATE_TIMEOUT_SECONDS,
        help="hard timeout for each quality-evaluation process",
    )
    parser.add_argument(
        "--skip-quality",
        action="store_true",
        help="run only the throughput matrix",
    )
    parser.add_argument(
        "--model",
        action="append",
        default=[],
        help="model key; repeat to select",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="scenario key; repeat to select",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    try:
        run(parse_args())
    except (
        FileExistsError,
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except Exception:
        print("error: benchmark runner failed unexpectedly", file=sys.stderr)
        raise SystemExit(1) from None
