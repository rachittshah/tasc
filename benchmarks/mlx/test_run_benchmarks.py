import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("run_benchmarks.py")
SPEC = importlib.util.spec_from_file_location("run_benchmarks", MODULE_PATH)
assert SPEC and SPEC.loader
run_benchmarks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_benchmarks)


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


if __name__ == "__main__":
    unittest.main()
