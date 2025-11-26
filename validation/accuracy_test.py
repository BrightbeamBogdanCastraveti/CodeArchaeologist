"""
Accuracy Test Suite

Measures detector accuracy on known vulnerable/safe code samples.

Metrics:
- True Positive Rate (TPR): % of real vulns detected
- False Positive Rate (FPR): % of safe code flagged
- Precision: % of detections that are real vulns
- F1 Score: Harmonic mean of precision and recall

Target: TPR >90%, FPR <5%, Precision >95%
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass
from analysis_engine.core.scanner import Scanner


@dataclass
class TestCase:
    """A single test case with known vulnerability status."""
    name: str
    code: str
    should_detect: bool  # True if code is vulnerable
    expected_detectors: List[str]  # Which detectors should fire
    description: str


# SQL Injection test cases
SQL_INJECTION_CASES = [
    TestCase(
        name="sql_injection_fstring",
        code="""
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
""",
        should_detect=True,
        expected_detectors=['sql_injection'],
        description="SQL injection via f-string"
    ),

    TestCase(
        name="sql_safe_parameterized",
        code="""
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe parameterized query"
    ),

    TestCase(
        name="sql_safe_orm",
        code="""
def get_user(user_id):
    return User.objects.filter(id=user_id).first()
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe ORM usage"
    ),
]

# Missing error handling test cases
MISSING_ERROR_HANDLING_CASES = [
    TestCase(
        name="missing_try_catch",
        code="""
def read_config():
    file = open('config.json')
    config = json.load(file)
    return config
""",
        should_detect=True,
        expected_detectors=['missing_error_handling'],
        description="File I/O without try/except"
    ),

    TestCase(
        name="has_try_catch",
        code="""
def read_config():
    try:
        file = open('config.json')
        config = json.load(file)
        return config
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Config error: {e}")
        return {}
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper error handling"
    ),
]

# Missing validation test cases
MISSING_VALIDATION_CASES = [
    TestCase(
        name="no_validation",
        code="""
def set_price(price):
    product.price = price
    product.save()
""",
        should_detect=True,
        expected_detectors=['missing_validation'],
        description="No validation on price parameter"
    ),

    TestCase(
        name="has_validation",
        code="""
def set_price(price):
    if not isinstance(price, (int, float)):
        raise TypeError("Price must be numeric")
    if price < 0:
        raise ValueError("Price must be positive")
    product.price = price
    product.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper price validation"
    ),
]

# Combine all test cases
ALL_TEST_CASES = (
    SQL_INJECTION_CASES +
    MISSING_ERROR_HANDLING_CASES +
    MISSING_VALIDATION_CASES
)


@dataclass
class AccuracyMetrics:
    """Accuracy metrics for detector performance."""
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def tpr(self) -> float:
        """True Positive Rate (Recall)"""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def fpr(self) -> float:
        """False Positive Rate"""
        if self.false_positives + self.true_negatives == 0:
            return 0.0
        return self.false_positives / (self.false_positives + self.true_negatives)

    @property
    def precision(self) -> float:
        """Precision"""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def f1_score(self) -> float:
        """F1 Score"""
        if self.precision + self.tpr == 0:
            return 0.0
        return 2 * (self.precision * self.tpr) / (self.precision + self.tpr)


class AccuracyTester:
    """Test detector accuracy on known test cases."""

    def __init__(self):
        self.scanner = Scanner(enable_fp_filter=True)

    def run_tests(self) -> Tuple[AccuracyMetrics, List[Dict]]:
        """Run all test cases and calculate metrics."""
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        failed_tests = []

        for test_case in ALL_TEST_CASES:
            # Scan the test code
            findings = self.scan_file_content(
                test_case.code,
                f'test_{test_case.name}.py'
            )

            # Check if any expected detectors fired
            detected = any(
                f.get('detector') in test_case.expected_detectors
                for f in findings
            )

            # Calculate TP/FP/TN/FN
            if test_case.should_detect:
                if detected:
                    true_positives += 1
                else:
                    false_negatives += 1
                    failed_tests.append({
                        'test': test_case.name,
                        'type': 'FALSE_NEGATIVE',
                        'description': test_case.description,
                        'expected': test_case.expected_detectors,
                        'got': []
                    })
            else:
                if detected:
                    false_positives += 1
                    failed_tests.append({
                        'test': test_case.name,
                        'type': 'FALSE_POSITIVE',
                        'description': test_case.description,
                        'expected': [],
                        'got': [f.get('detector') for f in findings]
                    })
                else:
                    true_negatives += 1

        metrics = AccuracyMetrics(
            true_positives=true_positives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            false_negatives=false_negatives
        )

        return metrics, failed_tests

    def scan_file_content(self, content: str, file_path: str) -> List[Dict]:
        """Helper to scan code content directly."""
        # Write to temp file and scan
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            findings = self.scanner.scan_file(temp_path, verbose=False)
            return findings
        finally:
            os.unlink(temp_path)


def run_accuracy_tests():
    """Run accuracy tests and print results."""
    print("DETECTOR ACCURACY TEST SUITE")
    print("=" * 70)
    print()

    tester = AccuracyTester()
    metrics, failed_tests = tester.run_tests()

    print(f"Test cases: {len(ALL_TEST_CASES)}")
    print()

    print("CONFUSION MATRIX:")
    print("-" * 70)
    print(f"  True Positives:  {metrics.true_positives}")
    print(f"  False Positives: {metrics.false_positives}")
    print(f"  True Negatives:  {metrics.true_negatives}")
    print(f"  False Negatives: {metrics.false_negatives}")
    print()

    print("METRICS:")
    print("-" * 70)
    print(f"  TPR (Recall):    {metrics.tpr:.1%}")
    print(f"  FPR:             {metrics.fpr:.1%}")
    print(f"  Precision:       {metrics.precision:.1%}")
    print(f"  F1 Score:        {metrics.f1_score:.3f}")
    print()

    # Evaluate against targets
    tpr_pass = metrics.tpr >= 0.90
    fpr_pass = metrics.fpr <= 0.05
    precision_pass = metrics.precision >= 0.95

    print("TARGET EVALUATION:")
    print("-" * 70)
    print(f"  TPR ≥90%:        {'✅ PASS' if tpr_pass else '❌ FAIL'} ({metrics.tpr:.1%})")
    print(f"  FPR ≤5%:         {'✅ PASS' if fpr_pass else '❌ FAIL'} ({metrics.fpr:.1%})")
    print(f"  Precision ≥95%:  {'✅ PASS' if precision_pass else '❌ FAIL'} ({metrics.precision:.1%})")
    print()

    if failed_tests:
        print(f"FAILED TESTS ({len(failed_tests)}):")
        print("-" * 70)
        for fail in failed_tests:
            print(f"  ❌ {fail['test']}: {fail['type']}")
            print(f"     {fail['description']}")
            print(f"     Expected: {fail['expected']}")
            print(f"     Got: {fail['got']}")
            print()

    overall_pass = tpr_pass and fpr_pass and precision_pass
    if overall_pass:
        print("✅ ALL TARGETS MET - Detectors are production-ready!")
    else:
        print("⚠️  SOME TARGETS MISSED - Needs improvement")

    return metrics, failed_tests


if __name__ == '__main__':
    run_accuracy_tests()
