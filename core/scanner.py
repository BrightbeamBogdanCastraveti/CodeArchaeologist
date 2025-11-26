"""
Core Scanner - Orchestrates all detectors

This is the brain that coordinates all vulnerability detectors.
Updated to actually RUN the detectors and produce real results.
"""

import os
import time
import sys
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from fnmatch import fnmatch

# Import false positive filter
try:
    from analysis_engine.core.false_positive_filter import FalsePositiveFilter
except ImportError:
    from core.false_positive_filter import FalsePositiveFilter

# Import all available detectors
try:
    from analysis_engine.detectors.sql_injection import SQLInjectionDetector
    from analysis_engine.detectors.ssrf import SSRFDetector
    from analysis_engine.detectors.email_injection import EmailInjectionDetector
    from analysis_engine.detectors.xxe import XXEDetector
    from analysis_engine.detectors.file_upload import FileUploadDetector
    from analysis_engine.detectors.command_injection import CommandInjectionDetector
    from analysis_engine.detectors.path_traversal import PathTraversalDetector
    from analysis_engine.detectors.info_exposure import InfoExposureDetector
    from analysis_engine.detectors.crypto_failures import CryptoFailuresDetector
    from analysis_engine.detectors.deserialization import DeserializationDetector
    from analysis_engine.detectors.csrf import CSRFDetector
    from analysis_engine.detectors.security_misconfiguration import SecurityMisconfigurationDetector
    from analysis_engine.detectors.prompt_injection import PromptInjectionDetector
    from analysis_engine.detectors.insecure_output import InsecureOutputDetector
    from analysis_engine.detectors.excessive_agency import ExcessiveAgencyDetector
    from analysis_engine.detectors.data_leakage import DataLeakageDetector
    from analysis_engine.detectors.unbounded_consumption import UnboundedConsumptionDetector
    from analysis_engine.detectors.training_poisoning import TrainingPoisoningDetector
    from analysis_engine.detectors.model_dos import ModelDoSDetector
    from analysis_engine.detectors.supply_chain import SupplyChainDetector
    from analysis_engine.detectors.overreliance import OverrelianceDetector
    from analysis_engine.detectors.model_theft import ModelTheftDetector
except ImportError:
    from detectors.sql_injection import SQLInjectionDetector
    from detectors.ssrf import SSRFDetector
    from detectors.email_injection import EmailInjectionDetector
    from detectors.xxe import XXEDetector
    from detectors.file_upload import FileUploadDetector
    from detectors.command_injection import CommandInjectionDetector
    from detectors.path_traversal import PathTraversalDetector
    from detectors.info_exposure import InfoExposureDetector
    from detectors.crypto_failures import CryptoFailuresDetector
    from detectors.deserialization import DeserializationDetector
    from detectors.csrf import CSRFDetector
    from detectors.security_misconfiguration import SecurityMisconfigurationDetector
    from detectors.prompt_injection import PromptInjectionDetector
    from detectors.insecure_output import InsecureOutputDetector
    from detectors.excessive_agency import ExcessiveAgencyDetector
    from detectors.data_leakage import DataLeakageDetector
    from detectors.unbounded_consumption import UnboundedConsumptionDetector
    from detectors.training_poisoning import TrainingPoisoningDetector
    from detectors.model_dos import ModelDoSDetector
    from detectors.supply_chain import SupplyChainDetector
    from detectors.overreliance import OverrelianceDetector
    from detectors.model_theft import ModelTheftDetector

# Vibe Coding Intelligence detectors
try:
    from analysis_engine.detectors.missing_error_handling import MissingErrorHandlingDetector
    from analysis_engine.detectors.ai_signature_detector import AISignatureDetector
    from analysis_engine.detectors.missing_validation import MissingValidationDetector
    from analysis_engine.detectors.generic_patterns import GenericPatternsDetector
    from analysis_engine.detectors.copy_paste_detector import CopyPasteDetector
except ImportError:
    from detectors.missing_error_handling import MissingErrorHandlingDetector
    from detectors.ai_signature_detector import AISignatureDetector
    from detectors.missing_validation import MissingValidationDetector
    from detectors.generic_patterns import GenericPatternsDetector
    from detectors.copy_paste_detector import CopyPasteDetector

# Try to import other detectors (may not have all methods yet)
try:
    from analysis_engine.detectors.race_conditions import RaceConditionDetector
except:
    try:
        from detectors.race_conditions import RaceConditionDetector
    except:
        RaceConditionDetector = None

try:
    from analysis_engine.detectors.xss import XSSDetector
except:
    try:
        from detectors.xss import XSSDetector
    except:
        XSSDetector = None

try:
    from analysis_engine.detectors.secrets import SecretsDetector
except:
    try:
        from detectors.secrets import SecretsDetector
    except:
        SecretsDetector = None

try:
    from analysis_engine.detectors.auth_bypass import AuthBypassDetector
except:
    try:
        from detectors.auth_bypass import AuthBypassDetector
    except:
        AuthBypassDetector = None


@dataclass
class ScanResults:
    """Results from a complete scan"""
    project_path: str
    scan_duration: float
    files_scanned: int
    lines_scanned: int
    findings: List[Dict] = field(default_factory=list)
    false_positives_filtered: int = 0
    filter_stats: Dict = field(default_factory=dict)

    @property
    def total_issues(self) -> int:
        return len(self.findings)

    @property
    def blocker_count(self) -> int:
        return len([f for f in self.findings if f.get('severity') == 'BLOCKER'])

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.get('severity') == 'CRITICAL'])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.get('severity') == 'HIGH'])

    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.get('severity') == 'MEDIUM'])

    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.get('severity') == 'LOW'])

    @property
    def average_confidence(self) -> float:
        if not self.findings:
            return 0.0
        return sum(f.get('confidence', 0) for f in self.findings) / len(self.findings)

    @property
    def vibe_debt_score(self) -> int:
        """
        Calculate vibe debt score (0-100)
        Higher = more vibe debt = worse
        """
        score = 0
        score += self.blocker_count * 20
        score += self.critical_count * 10
        score += self.high_count * 5
        score += self.medium_count * 2
        score += self.low_count * 1

        return min(score, 100)


class Scanner:
    """
    Main scanning orchestrator.

    Coordinates all detectors and produces comprehensive results.
    """

    def __init__(self, enable_fp_filter: bool = True, confidence_threshold: int = 65):
        # Initialize all available detectors
        self.detectors = {}

        # Initialize false positive filter
        self.fp_filter = FalsePositiveFilter() if enable_fp_filter else None

        # Confidence threshold - only report issues above this confidence
        self.confidence_threshold = confidence_threshold

        # Always available (research-backed)
        self.detectors['sql_injection'] = SQLInjectionDetector()
        self.detectors['ssrf'] = SSRFDetector()
        self.detectors['email_injection'] = EmailInjectionDetector()
        self.detectors['xxe'] = XXEDetector()
        self.detectors['file_upload'] = FileUploadDetector()
        self.detectors['command_injection'] = CommandInjectionDetector()
        self.detectors['path_traversal'] = PathTraversalDetector()
        self.detectors['info_exposure'] = InfoExposureDetector()
        self.detectors['crypto_failures'] = CryptoFailuresDetector()
        self.detectors['deserialization'] = DeserializationDetector()
        self.detectors['csrf'] = CSRFDetector()
        self.detectors['security_misconfiguration'] = SecurityMisconfigurationDetector()
        self.detectors['prompt_injection'] = PromptInjectionDetector()
        self.detectors['insecure_output'] = InsecureOutputDetector()
        self.detectors['excessive_agency'] = ExcessiveAgencyDetector()
        self.detectors['data_leakage'] = DataLeakageDetector()
        self.detectors['unbounded_consumption'] = UnboundedConsumptionDetector()
        self.detectors['training_poisoning'] = TrainingPoisoningDetector()
        self.detectors['model_dos'] = ModelDoSDetector()
        self.detectors['supply_chain'] = SupplyChainDetector()
        self.detectors['overreliance'] = OverrelianceDetector()
        self.detectors['model_theft'] = ModelTheftDetector()

        # Vibe Coding Intelligence
        self.detectors['missing_error_handling'] = MissingErrorHandlingDetector()
        self.detectors['ai_signature'] = AISignatureDetector()
        self.detectors['missing_validation'] = MissingValidationDetector()
        self.detectors['generic_patterns'] = GenericPatternsDetector()
        self.detectors['copy_paste'] = CopyPasteDetector()

        # Add others if available
        if RaceConditionDetector:
            self.detectors['race_conditions'] = RaceConditionDetector()
        if XSSDetector:
            self.detectors['xss'] = XSSDetector()
        if SecretsDetector:
            self.detectors['secrets'] = SecretsDetector()
        if AuthBypassDetector:
            self.detectors['auth_bypass'] = AuthBypassDetector()

        # Exclude patterns - directories
        self.exclude_dirs = {
            'venv', 'env', '.venv', 'node_modules',
            '__pycache__', '.git', 'dist', 'build', 'out',
            '.pytest_cache', '.mypy_cache', 'htmlcov',
            'site-packages', 'eggs', '.tox',
            'tests', 'test', '__tests__', '.idea', 'migrations',
            '.aider.tags.cache.v4', '.benchmarks', '.scannerwork',
            '.webpack', '.next', '.nuxt', 'coverage',
            'vendor', 'bower_components', 'jspm_packages',
            '.cache', '.parcel-cache', '.turbo'
        }

        # Exclude patterns - filenames
        self.exclude_patterns = {
            'test_*.py', 'tests_*.py', '*_test.py', '*_tests.py', 'conftest.py',
            'test-*.py', 'test-*.js', 'test-*.ts', 'test-*.jsx', 'test-*.tsx',
            '*-test.py', '*-test.js', '*-test.ts', '*-test.jsx', '*-test.tsx',
            'locustfile*.py', '*_audit.py', '*_scan.py',
            'setup.py',
            '*.test.js', '*.test.jsx', '*.test.ts', '*.test.tsx',
            '*.spec.js', '*.spec.jsx', '*.spec.ts', '*.spec.tsx',
            'jest.config.*', 'vitest.config.*', 'karma.conf.*',
            '*.mock.js', '*.mock.ts', '*.stub.js', '*.stub.ts'
        }

        self.scannable_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx',
            '.html', '.vue', '.java', '.go',
            '.rb', '.php', '.cs'
        }

    def scan_project(self, project_path: str,
                     verbose: bool = False) -> ScanResults:
        """
        Scan an entire project directory.

        Args:
            project_path: Path to project root
            verbose: Print progress during scan

        Returns:
            ScanResults with all findings
        """
        start_time = time.time()
        project_path = Path(project_path).resolve()

        if not project_path.exists():
            raise FileNotFoundError(f"Project path not found: {project_path}")

        if verbose:
            print(f"🔍 Scanning: {project_path}")
            print(f"📊 Detectors active: {len(self.detectors)}")
            print(f"   Available: {', '.join(self.detectors.keys())}")
            print()

        # Collect all scannable files
        files_to_scan = self._collect_files(project_path)

        if verbose:
            print(f"📁 Found {len(files_to_scan)} files to scan")
            print()

        # Scan each file
        all_findings = []
        lines_scanned = 0

        for i, file_path in enumerate(files_to_scan, 1):
            if verbose and i % 10 == 0:
                print(f"   Progress: {i}/{len(files_to_scan)} files...")

            try:
                file_findings, line_count = self._scan_file(file_path, verbose)

                # Filter by confidence threshold
                high_confidence = [
                    f for f in file_findings
                    if f.get('confidence', 100) >= self.confidence_threshold
                ]
                all_findings.extend(high_confidence)
                lines_scanned += line_count
            except Exception as e:
                if verbose:
                    print(f"   ⚠️  Error scanning {file_path.name}: {e}")
                continue

        duration = time.time() - start_time

        # Get false positive filter stats
        fp_stats = {}
        fp_filtered = 0
        if self.fp_filter:
            fp_stats = self.fp_filter.get_filter_stats()
            fp_filtered = sum(fp_stats.values())

        # Create results
        results = ScanResults(
            project_path=str(project_path),
            scan_duration=duration,
            files_scanned=len(files_to_scan),
            lines_scanned=lines_scanned,
            findings=all_findings,
            false_positives_filtered=fp_filtered,
            filter_stats=fp_stats
        )

        if verbose:
            print()
            print("✅ Scan complete!")
            print(f"   Duration: {duration:.2f}s")
            print(f"   Files: {len(files_to_scan)}")
            print(f"   Lines: {lines_scanned:,}")
            print(f"   Issues: {results.total_issues}")
            print()

        return results

    def _collect_files(self, project_path: Path) -> List[Path]:
        """
        Recursively collect all scannable files - PRODUCTION CODE ONLY.
        Excludes test files, migrations, and other non-production code.
        Uses path-aware exclusion to avoid false positives.
        """
        files = []
        project_path = Path(project_path)

        for root, dirs, filenames in os.walk(project_path):
            # Remove excluded directories in-place
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]

            for filename in filenames:
                file_path = Path(root) / filename

                # Must have scannable extension
                if file_path.suffix not in self.scannable_extensions:
                    continue

                # Use path-aware exclusion (not just filename)
                if self._should_exclude_file(file_path, project_path):
                    continue

                files.append(file_path)

        return files

    def _should_exclude_file(self, file_path: Path, project_root: Path) -> bool:
        """
        Path-aware exclusion logic to reduce false positives.

        Returns True if file should be excluded from scanning.

        Key improvements:
        - Checks full path context, not just filename
        - Whitelists config/settings/* files
        - Properly excludes test files in test directories
        """
        try:
            relative_path = file_path.relative_to(project_root)
        except ValueError:
            # File is outside project root, exclude it
            return True

        path_parts = relative_path.parts
        filename = file_path.name

        # 1. WHITELIST: config/settings/* are always production code
        #    Files like config/settings/test.py are settings, not tests!
        if len(path_parts) >= 2 and path_parts[-2] == 'settings':
            return False

        # 2. Check if file is in a test directory (by path)
        test_dirs = {'tests', 'test', '__tests__', 'cypress', 'e2e'}
        if any(part in test_dirs for part in path_parts):
            return True

        # 3. Exclude test file patterns
        for pattern in self.exclude_patterns:
            if fnmatch(filename, pattern):
                return True

        return False

    def _scan_file(self, file_path: Path, verbose: bool = False) -> tuple:
        """
        Scan a single file with all detectors.

        Returns:
            (findings, line_count)
        """
        # Read file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            if verbose:
                print(f"   ⚠️  Cannot read {file_path.name}: {e}")
            return [], 0

        line_count = content.count('\n') + 1
        findings = []

        # Run each detector
        for detector_name, detector in self.detectors.items():
            try:
                detector_findings = detector.detect(content, str(file_path))

                # Convert findings to dict format if needed
                for finding in detector_findings:
                    if hasattr(finding, '__dict__'):
                        # It's a dataclass, convert to dict
                        finding_dict = {
                            'detector': detector_name,
                            'line': finding.line,
                            'column': finding.column,
                            'severity': finding.severity,
                            'confidence': finding.confidence,
                            'message': finding.description,
                            'code_snippet': finding.code_snippet,
                            'file': str(file_path),
                            'cwe_id': getattr(finding, 'cwe_id', ''),
                            'owasp_category': getattr(finding, 'owasp_category', ''),
                        }
                        findings.append(finding_dict)
                    else:
                        # Already a dict
                        finding['detector'] = detector_name
                        finding['file'] = str(file_path)
                        findings.append(finding)

            except Exception as e:
                # Detector crashed - log but continue
                if verbose:
                    print(f"   ⚠️  Detector {detector_name} failed on {file_path.name}: {e}")
                continue

        # Apply false positive filtering
        if self.fp_filter:
            findings = self.fp_filter.filter_findings(findings, content, str(file_path))

        return findings, line_count

    def scan_file(self, file_path: str, verbose: bool = False) -> List[Dict]:
        """
        Scan a single file (convenience method).

        Returns list of findings.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        findings, _ = self._scan_file(file_path, verbose)
        return findings
