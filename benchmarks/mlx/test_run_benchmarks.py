import argparse
import importlib.util
import json
import os
import shlex
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("run_benchmarks.py")
SPEC = importlib.util.spec_from_file_location("run_benchmarks", MODULE_PATH)
assert SPEC and SPEC.loader
run_benchmarks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_benchmarks)


def valid_config() -> dict:
    return {
        "schemaVersion": "tasc-mlx-benchmark-config-v1",
        "models": [
            {
                "key": "fixture-model",
                "repoId": "FixtureOrg/Fixture-Model",
                "revision": "a" * 40,
                "parameters": 1,
            }
        ],
        "scenarios": [
            {
                "key": "fixture-scenario",
                "promptTokens": 8,
                "generationTokens": 4,
                "batchSize": 1,
            }
        ],
        "qualityEvaluation": {
            "task": "fixture_task",
            "numShots": 0,
            "batchSize": 1,
            "seed": 7,
            "applyChatTemplate": False,
            "limit": None,
        },
        "numTrials": 1,
    }


def namespace(
    config: Path,
    output: Path,
    benchmark_command: str,
    evaluate_command: str,
    *,
    skip_quality: bool = False,
) -> argparse.Namespace:
    return argparse.Namespace(
        config=config,
        output=output,
        benchmark_command=benchmark_command,
        evaluate_command=evaluate_command,
        download_timeout_seconds=5,
        benchmark_timeout_seconds=5,
        evaluate_timeout_seconds=5,
        skip_quality=skip_quality,
        model=[],
        scenario=[],
    )


class ParseBenchmarkOutputTest(unittest.TestCase):
    def test_parses_trials_and_r7_summary(self) -> None:
        output = """
Running warmup..
Timing with prompt_tokens=128, generation_tokens=256, batch_size=1.
Trial 1:  prompt_tps=100.000, generation_tps=10.000, peak_memory=1.000
Trial 2:  prompt_tps=200.000, generation_tps=20.000, peak_memory=1.500
Trial 3:  prompt_tps=300.000, generation_tps=30.000, peak_memory=2.000
Averages: prompt_tps=200.000, generation_tps=20.000, peak_memory=1.500
"""
        parsed = run_benchmarks.parse_benchmark_output(output, expected_trials=3)

        self.assertEqual(len(parsed["trials"]), 3)
        self.assertEqual(parsed["summary"]["promptTokensPerSecond"]["median"], 200.0)
        self.assertEqual(parsed["summary"]["promptTokensPerSecond"]["p10"], 120.0)
        self.assertEqual(parsed["summary"]["generationTokensPerSecond"]["p95"], 29.0)
        self.assertEqual(parsed["summary"]["peakMemoryGb"]["max"], 2.0)

    def test_rejects_missing_trial(self) -> None:
        output = """
Trial 1:  prompt_tps=100.000, generation_tps=10.000, peak_memory=1.000
Trial 3:  prompt_tps=300.000, generation_tps=30.000, peak_memory=2.000
"""
        with self.assertRaisesRegex(ValueError, "contiguous"):
            run_benchmarks.parse_benchmark_output(output)

    def test_rejects_unexpected_trial_count(self) -> None:
        output = "Trial 1:  prompt_tps=100.000, generation_tps=10.000, peak_memory=1.000"
        with self.assertRaisesRegex(ValueError, "expected 2 trials"):
            run_benchmarks.parse_benchmark_output(output, expected_trials=2)

    def test_parses_quality_result(self) -> None:
        payload = {
            "arc_challenge": {
                "name": "arc_challenge",
                "alias": "ARC Challenge",
                "sample_len": 1172,
                "acc,none": 0.30,
                "acc_stderr,none": 0.01,
                "acc_norm,none": 0.35,
                "acc_norm_stderr,none": 0.02,
            }
        }

        parsed = run_benchmarks.parse_quality_result(payload, "arc_challenge")

        self.assertEqual(parsed["samples"], 1172)
        self.assertEqual(parsed["metrics"]["accuracy"], 0.30)
        self.assertEqual(parsed["metrics"]["lengthNormalizedAccuracy"], 0.35)

    def test_rejects_incomplete_quality_result(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid mlx_lm.evaluate"):
            run_benchmarks.parse_quality_result(
                {"arc_challenge": {"sample_len": 1172}},
                "arc_challenge",
            )

    def test_rejects_non_finite_quality_metrics(self) -> None:
        payload = {
            "arc_challenge": {
                "name": "arc_challenge",
                "alias": "ARC Challenge",
                "sample_len": 1172,
                "acc,none": float("nan"),
                "acc_stderr,none": 0.01,
                "acc_norm,none": 0.35,
                "acc_norm_stderr,none": 0.02,
            }
        }
        with self.assertRaisesRegex(ValueError, "invalid mlx_lm.evaluate"):
            run_benchmarks.parse_quality_result(payload, "arc_challenge")


class ConfigValidationTest(unittest.TestCase):
    def test_accepts_full_commit_pins_and_rejects_unsafe_or_duplicate_keys(self) -> None:
        validated = run_benchmarks.validate_config(valid_config())
        self.assertEqual(validated["models"][0]["revision"], "a" * 40)

        short_revision = valid_config()
        short_revision["models"][0]["revision"] = "main"
        with self.assertRaisesRegex(ValueError, "full lowercase 40-hex"):
            run_benchmarks.validate_config(short_revision)

        unsafe_key = valid_config()
        unsafe_key["scenarios"][0]["key"] = "../escape"
        with self.assertRaisesRegex(ValueError, "safe"):
            run_benchmarks.validate_config(unsafe_key)

        duplicate = valid_config()
        duplicate["models"].append(dict(duplicate["models"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate model key"):
            run_benchmarks.validate_config(duplicate)

    def test_rejects_unknown_fields_and_unbounded_compute(self) -> None:
        unknown = valid_config()
        unknown["surprise"] = True
        with self.assertRaisesRegex(ValueError, "unknown field"):
            run_benchmarks.validate_config(unknown)

        excessive_shots = valid_config()
        excessive_shots["qualityEvaluation"]["numShots"] = 10**1_000
        with self.assertRaisesRegex(ValueError, "between 0 and 1000"):
            run_benchmarks.validate_config(excessive_shots)

        excessive_compute = valid_config()
        excessive_compute["numTrials"] = run_benchmarks.MAX_TRIALS
        excessive_compute["scenarios"][0].update(
            {
                "promptTokens": 262_144,
                "generationTokens": 262_144,
                "batchSize": 256,
            }
        )
        with self.assertRaisesRegex(ValueError, "token-position"):
            run_benchmarks.validate_config(excessive_compute)

    def test_load_config_is_bounded_strict_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            oversized = directory / "oversized.json"
            oversized.write_bytes(
                b" " * (run_benchmarks.MAX_CONFIG_BYTES + 1)
            )
            with self.assertRaisesRegex(ValueError, "byte limit"):
                run_benchmarks.load_config(oversized)

            duplicate = directory / "duplicate.json"
            duplicate.write_text(
                '{"schemaVersion":"tasc-mlx-benchmark-config-v1",'
                '"schemaVersion":"tasc-mlx-benchmark-config-v1"}'
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                run_benchmarks.load_config(duplicate)

    def test_rejects_duplicate_selection(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate requested"):
            run_benchmarks.select(
                valid_config()["models"],
                ["fixture-model", "fixture-model"],
                "model",
            )


class ReproducibleEnvironmentTest(unittest.TestCase):
    def test_source_builds_use_the_separate_hash_locked_bootstrap(self) -> None:
        directory = Path(__file__).parent
        runtime_lock = (
            directory / "requirements.lock"
        ).read_text()
        build_lock = (
            directory / "build-requirements.lock"
        ).read_text()
        documentation = (directory / "README.md").read_text()

        for requirement in (
            "rouge-score==0.1.2",
            "sqlitedict==2.1.0",
            "word2number==1.1",
        ):
            self.assertIn(requirement, runtime_lock)
        for requirement in (
            "packaging==26.2",
            "setuptools==83.0.0",
            "wheel==0.46.3",
        ):
            self.assertIn(requirement, build_lock)
        self.assertGreaterEqual(
            build_lock.count("--hash=sha256:"),
            6,
        )
        self.assertIn("--no-build-isolation", documentation)
        self.assertIn(
            "-r benchmarks/mlx/build-requirements.lock",
            documentation,
        )


class BoundedProcessTest(unittest.TestCase):
    def test_darwin_accepts_zombie_only_group_eperm_after_exit_event(
        self,
    ) -> None:
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        with (
            mock.patch.object(run_benchmarks.sys, "platform", "darwin"),
            mock.patch.object(
                run_benchmarks.os,
                "killpg",
                side_effect=PermissionError,
            ),
        ):
            run_benchmarks.terminate_process_group(
                process,
                leader_exit_observed=True,
            )

        process.wait.assert_not_called()

    def test_darwin_does_not_hide_timeout_path_eperm(self) -> None:
        with (
            mock.patch.object(run_benchmarks.sys, "platform", "darwin"),
            mock.patch.object(
                run_benchmarks.os,
                "killpg",
                side_effect=PermissionError,
            ),
            self.assertRaises(PermissionError),
        ):
            run_benchmarks.terminate_process_group(mock.Mock(pid=1234))

    def test_fails_closed_without_nonreaping_waitid(self) -> None:
        process = mock.Mock(pid=1234)
        with (
            mock.patch.object(run_benchmarks.os, "waitid", None),
            mock.patch.object(run_benchmarks.os, "WNOWAIT", None),
            mock.patch.object(
                run_benchmarks,
                "terminate_process_group",
            ) as terminate,
            self.assertRaisesRegex(RuntimeError, "waitid with WNOWAIT"),
        ):
            run_benchmarks.reap_leader_after_group_shutdown(
                process,
                time.monotonic() + 1,
                bytearray(),
            )

        terminate.assert_called_once_with(process)

    def test_excludes_unrelated_environment_and_captures_success(self) -> None:
        environment = run_benchmarks.reduced_environment(
            {
                "PATH": os.defpath,
                "TOP_SECRET": "must-not-cross",
            }
        )
        result = run_benchmarks.run_bounded_command(
            [
                sys.executable,
                "-c",
                "import os; print(os.getenv('TOP_SECRET', 'absent'))",
            ],
            timeout_seconds=5,
            max_output_bytes=128,
            environment=environment,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.output.strip(), "absent")

    def test_kills_processes_that_timeout_or_exceed_output_limit(self) -> None:
        with self.assertRaisesRegex(
            run_benchmarks.BoundedCommandFailure,
            "timed out",
        ) as timeout:
            run_benchmarks.run_bounded_command(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout_seconds=1,
                max_output_bytes=128,
            )
        self.assertEqual(timeout.exception.output, "")

        with self.assertRaisesRegex(
            run_benchmarks.BoundedCommandFailure,
            "capture limit",
        ) as overflow:
            run_benchmarks.run_bounded_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 10000); sys.stdout.flush()",
                ],
                timeout_seconds=5,
                max_output_bytes=100,
            )
        self.assertLessEqual(
            len(overflow.exception.output.encode("utf-8")),
            100,
        )

    def test_kills_a_descendant_after_its_process_group_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "descendant-survived"
            descendant = (
                "import pathlib,sys,time;"
                "time.sleep(2);"
                "pathlib.Path(sys.argv[1]).write_text('alive')"
            )
            leader = (
                "import subprocess,sys;"
                "subprocess.Popen([sys.executable,'-c',"
                f"{descendant!r},sys.argv[1]])"
            )
            with self.assertRaisesRegex(
                run_benchmarks.BoundedCommandFailure,
                "timed out",
            ):
                run_benchmarks.run_bounded_command(
                    [sys.executable, "-c", leader, str(marker)],
                    timeout_seconds=1,
                    max_output_bytes=128,
                )
            time.sleep(1.5)
            self.assertFalse(marker.exists())

    def test_successful_leader_cannot_leave_a_quiet_descendant_running(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "quiet-descendant-survived"
            descendant = (
                "import pathlib,sys,time;"
                "time.sleep(1);"
                "pathlib.Path(sys.argv[1]).write_text('alive')"
            )
            leader = (
                "import subprocess,sys;"
                "subprocess.Popen("
                "[sys.executable,'-c',"
                f"{descendant!r},sys.argv[1]],"
                "stdin=subprocess.DEVNULL,"
                "stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL)"
            )
            result = run_benchmarks.run_bounded_command(
                [sys.executable, "-c", leader, str(marker)],
                timeout_seconds=5,
                max_output_bytes=128,
            )
            self.assertEqual(result.returncode, 0)
            time.sleep(1.5)
            self.assertFalse(marker.exists())


class SecureWorkflowTest(unittest.TestCase):
    def write_fixture_files(self, directory: Path) -> tuple[Path, Path]:
        config_path = directory / "config.json"
        config_path.write_text(json.dumps(valid_config()))
        executable = directory / "fake_mlx.py"
        executable.write_text(
            """
import json
import os
import sys

mode = sys.argv[1]
if mode == "benchmark":
    print("Trial 1:  prompt_tps=10.000, generation_tps=5.000, peak_memory=1.000")
elif mode == "evaluate":
    output = sys.argv[sys.argv.index("--output-dir") + 1]
    task = sys.argv[sys.argv.index("--tasks") + 1]
    payload = {
        task: {
            "name": task,
            "alias": "Fixture",
            "sample_len": 2,
            "acc,none": 0.5,
            "acc_stderr,none": 0.1,
            "acc_norm,none": 0.6,
            "acc_norm_stderr,none": 0.2,
        }
    }
    with open(os.path.join(output, "result.json"), "x", encoding="utf-8") as handle:
        json.dump(payload, handle)
else:
    raise SystemExit(2)
"""
        )
        return config_path, executable

    def test_publishes_one_complete_exclusive_result_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config_path, executable = self.write_fixture_files(directory)
            model_path = directory / "model"
            model_path.mkdir()
            output = directory / "result"
            python = shlex.quote(sys.executable)
            script = shlex.quote(str(executable))
            args = namespace(
                config_path,
                output,
                f"{python} {script} benchmark",
                f"{python} {script} evaluate",
            )
            with (
                mock.patch.object(
                    run_benchmarks,
                    "download_model_snapshot",
                    return_value=model_path,
                ),
                mock.patch.object(
                    run_benchmarks,
                    "sanitized_hardware",
                    return_value={"fixture": True},
                ),
                mock.patch.object(
                    run_benchmarks,
                    "package_versions",
                    return_value={"fixture": "1"},
                ),
            ):
                result = run_benchmarks.run(args)

            self.assertEqual(result, output / "throughput.json")
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["quality.json", "raw", "throughput.json"],
            )
            throughput = json.loads(result.read_text())
            self.assertEqual(len(throughput["runs"]), 1)
            self.assertEqual(
                throughput["runs"][0]["modelRevision"],
                "a" * 40,
            )
            quality = json.loads((output / "quality.json").read_text())
            self.assertEqual(
                quality["results"][0]["metrics"]["accuracy"],
                0.5,
            )
            self.assertEqual(
                stat_mode(output),
                0o700,
            )
            self.assertTrue(
                all(
                    stat_mode(path) == 0o600
                    for path in output.rglob("*")
                    if path.is_file()
                )
            )

    def test_rejects_the_whole_suite_deadline_before_files_or_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = valid_config()
            template = config["models"][0]
            config["models"] = [
                {**template, "key": f"fixture-model-{index}"}
                for index in range(3)
            ]
            config_path = directory / "config.json"
            config_path.write_text(json.dumps(config))
            output = directory / "never-created"
            args = namespace(
                config_path,
                output,
                sys.executable,
                sys.executable,
            )
            args.download_timeout_seconds = run_benchmarks.MAX_TIMEOUT_SECONDS
            args.benchmark_timeout_seconds = run_benchmarks.MAX_TIMEOUT_SECONDS
            args.evaluate_timeout_seconds = run_benchmarks.MAX_TIMEOUT_SECONDS
            with mock.patch.object(
                run_benchmarks,
                "download_model_snapshot",
            ) as download:
                with self.assertRaisesRegex(ValueError, "whole-suite"):
                    run_benchmarks.run(args)
            download.assert_not_called()
            self.assertFalse(output.exists())

    def test_cleans_owned_partial_output_and_preserves_a_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config_path, executable = self.write_fixture_files(directory)
            failing = directory / "fail.py"
            failing.write_text("raise SystemExit(3)\n")
            model_path = directory / "model"
            model_path.mkdir()
            output = directory / "partial"
            python = shlex.quote(sys.executable)
            command = f"{python} {shlex.quote(str(failing))}"
            args = namespace(
                config_path,
                output,
                command,
                f"{python} {shlex.quote(str(executable))} evaluate",
                skip_quality=True,
            )
            with (
                mock.patch.object(
                    run_benchmarks,
                    "download_model_snapshot",
                    return_value=model_path,
                ),
                mock.patch.object(
                    run_benchmarks,
                    "sanitized_hardware",
                    return_value={},
                ),
                mock.patch.object(
                    run_benchmarks,
                    "package_versions",
                    return_value={},
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "benchmark failed"):
                    run_benchmarks.run(args)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])

            output.rmdir()
            output.mkdir()
            marker = output / "user-owned.txt"
            marker.write_text("preserve")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                run_benchmarks.run(args)
            self.assertEqual(marker.read_text(), "preserve")

    def test_cleanup_fd_clears_only_owned_contents_and_retains_the_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output, identity = run_benchmarks.create_output_directory(
                parent / "result"
            )
            (output / "owned.txt").write_text("owned")
            renamed_owned = parent / "renamed-owned"
            real_fwalk = os.fwalk

            def swap_then_walk(*args, **kwargs):
                output.rename(renamed_owned)
                output.mkdir()
                (output / "replacement.txt").write_text("preserve")
                return real_fwalk(*args, **kwargs)

            with mock.patch.object(
                run_benchmarks.os,
                "fwalk",
                side_effect=swap_then_walk,
            ):
                run_benchmarks.cleanup_owned_output(output, identity)

            self.assertEqual(
                (output / "replacement.txt").read_text(),
                "preserve",
            )
            self.assertTrue(renamed_owned.is_dir())
            self.assertEqual(list(renamed_owned.iterdir()), [])

            stable_output, stable_identity = (
                run_benchmarks.create_output_directory(parent / "stable")
            )
            (stable_output / "partial.txt").write_text("partial")
            run_benchmarks.cleanup_owned_output(
                stable_output,
                stable_identity,
            )
            self.assertTrue(stable_output.is_dir())
            self.assertEqual(list(stable_output.iterdir()), [])


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
