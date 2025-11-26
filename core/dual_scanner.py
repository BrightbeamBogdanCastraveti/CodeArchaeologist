"""
Dual Engine Scanner

Orchestrates both scanning engines:
- Engine 1: Pattern-based detection (fast, precise)
- Engine 2: AI-powered detection (deep, contextual)

Supports 3 modes:
1. FAST: Engine 1 only (pattern-based, fast)
2. DEEP: Engine 2 only (AI-powered, thorough)
3. VERIFY: Both engines (comprehensive, high-confidence)
"""

import time
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

# Import Engine 1 (pattern-based)
try:
    from analysis_engine.core.scanner import Scanner, ScanResults
except ImportError:
    from core.scanner import Scanner, ScanResults

# Import Engine 2 (AI-powered)
try:
    from analysis_engine.ai.ai_scanner import AIScanner, AIFinding
except ImportError:
    from ai.ai_scanner import AIScanner, AIFinding


class ScanMode(Enum):
    """Scanning modes"""
    FAST = "fast"      # Engine 1 only (pattern-based)
    DEEP = "deep"      # Engine 2 only (AI-powered)
    VERIFY = "verify"  # Both engines (merged results)


@dataclass
class DualScanResults:
    """Results from dual engine scan"""
    project_path: str
    scan_mode: ScanMode
    scan_duration: float
    files_scanned: int
    lines_scanned: int

    # Findings from each engine
    engine1_findings: List[Dict] = field(default_factory=list)
    engine2_findings: List[Dict] = field(default_factory=list)
    merged_findings: List[Dict] = field(default_factory=list)

    # Statistics
    engine1_only: int = 0  # Found by Engine 1 only
    engine2_only: int = 0  # Found by Engine 2 only
    both_engines: int = 0  # Found by both (high confidence)

    @property
    def total_issues(self) -> int:
        return len(self.merged_findings)

    @property
    def blocker_count(self) -> int:
        return len([f for f in self.merged_findings if f.get('severity') == 'BLOCKER'])

    @property
    def critical_count(self) -> int:
        return len([f for f in self.merged_findings if f.get('severity') == 'CRITICAL'])

    @property
    def high_count(self) -> int:
        return len([f for f in self.merged_findings if f.get('severity') == 'HIGH'])

    @property
    def vibe_debt_score(self) -> int:
        """Calculate vibe debt score (0-100)"""
        score = 0
        score += self.blocker_count * 20
        score += self.critical_count * 10
        score += self.high_count * 5
        return min(score, 100)


class DualScanner:
    """
    Dual Engine Scanner

    Orchestrates both scanning engines and provides flexible scanning modes.
    """

    def __init__(self, openai_api_key: Optional[str] = None):
        print("🔧 Initializing Dual Engine Scanner...")

        # Initialize Engine 1 (pattern-based)
        print("   Engine 1: Pattern-based detector")
        self.engine1 = Scanner(enable_fp_filter=True)

        # Initialize Engine 2 (AI-powered)
        print("   Engine 2: AI-powered detector")
        self.engine2 = AIScanner(openai_api_key=openai_api_key)

        print("✅ Dual Scanner ready")

    def scan_project(
        self,
        project_path: str,
        mode: ScanMode = ScanMode.VERIFY,
        verbose: bool = False
    ) -> DualScanResults:
        """
        Scan project with dual engine

        Args:
            project_path: Path to project
            mode: Scanning mode (FAST/DEEP/VERIFY)
            verbose: Print progress

        Returns:
            DualScanResults with findings from both engines
        """
        start_time = time.time()
        project_path = Path(project_path).resolve()

        if verbose:
            print(f"\n{'='*70}")
            print(f"DUAL ENGINE SCAN")
            print(f"{'='*70}")
            print(f"Project: {project_path}")
            print(f"Mode: {mode.value.upper()}")
            print(f"{'='*70}\n")

        # Run engines based on mode
        engine1_results = None
        engine2_findings = []

        if mode == ScanMode.FAST:
            # Engine 1 only
            if verbose:
                print("🚀 Running Engine 1 (pattern-based)...")
            engine1_results = self.engine1.scan_project(str(project_path), verbose=verbose)

        elif mode == ScanMode.DEEP:
            # Engine 2 only
            if verbose:
                print("🤖 Running Engine 2 (AI-powered)...")
            engine2_findings = self._scan_project_with_ai(project_path, verbose)

        elif mode == ScanMode.VERIFY:
            # Both engines
            if verbose:
                print("🚀 Running Engine 1 (pattern-based)...")
            engine1_results = self.engine1.scan_project(str(project_path), verbose=verbose)

            if verbose:
                print("\n🤖 Running Engine 2 (AI-powered)...")
            engine2_findings = self._scan_project_with_ai(project_path, verbose)

        # Merge findings
        merged_findings, stats = self._merge_findings(
            engine1_results.findings if engine1_results else [],
            engine2_findings,
            verbose
        )

        duration = time.time() - start_time

        # Create results
        results = DualScanResults(
            project_path=str(project_path),
            scan_mode=mode,
            scan_duration=duration,
            files_scanned=engine1_results.files_scanned if engine1_results else len(self._collect_files(project_path)),
            lines_scanned=engine1_results.lines_scanned if engine1_results else 0,
            engine1_findings=engine1_results.findings if engine1_results else [],
            engine2_findings=[self._ai_finding_to_dict(f) for f in engine2_findings],
            merged_findings=merged_findings,
            engine1_only=stats['engine1_only'],
            engine2_only=stats['engine2_only'],
            both_engines=stats['both_engines']
        )

        if verbose:
            self._print_summary(results)

        return results

    def _scan_project_with_ai(
        self,
        project_path: Path,
        verbose: bool = False
    ) -> List[AIFinding]:
        """Scan project with AI engine"""
        findings = []

        # Collect scannable files
        files = self._collect_files(project_path)

        if verbose:
            print(f"   Found {len(files)} files to scan with AI")

        # Scan each file with AI
        for i, file_path in enumerate(files, 1):
            if verbose:
                print(f"   Scanning {i}/{len(files)}: {file_path.name}")

            try:
                file_findings = self.engine2.scan_file(str(file_path))
                findings.extend(file_findings)
            except Exception as e:
                if verbose:
                    print(f"   ⚠️  Error: {e}")

        return findings

    def _collect_files(self, project_path: Path) -> List[Path]:
        """Collect scannable files - PRODUCTION CODE ONLY"""
        files = []

        # Exclude these directories completely
        exclude_dirs = {
            'venv', 'env', '.venv', 'node_modules', '__pycache__', '.git',
            'tests', 'test', '.pytest_cache', '.tox', 'htmlcov',
            '.aider.tags.cache.v4', '.benchmarks', '.scannerwork', '.idea',
            'migrations',  # Django migrations aren't security-relevant
            'cypress', 'e2e', '__tests__',  # Test directories
            'dist', 'build', '.next', 'out', 'coverage',  # Build artifacts
            '.vercel', '.netlify', '.cache'  # Deployment/cache directories
        }

        # Exclude these file patterns
        exclude_patterns = {
            # Python tests
            'test_*.py', '*_test.py', 'conftest.py',
            'locustfile*.py', '*_audit.py', '*_scan.py',
            'setup.py',
            # Frontend tests
            '*.test.js', '*.test.jsx', '*.test.ts', '*.test.tsx',
            '*.spec.js', '*.spec.jsx', '*.spec.ts', '*.spec.tsx',
            '*.cy.js', '*.cy.ts', '*.cy.jsx', '*.cy.tsx',  # Cypress tests
            # Config files
            '*.config.js', '*.config.ts', '*.config.mjs', '*.config.cjs',
            'eslint.*', 'prettier.*', 'tailwind.*', 'vite.*',
            'playwright.*', 'postcss.*', 'jest.*', 'vitest.*',
            'tsconfig.*', 'jsconfig.*', 'babel.*', 'webpack.*',
            # Build artifacts and minified files
            '*.min.js', '*.min.css', 'index-*.js', 'vendor-*.js',
            # Development-only files
            'test-*.js', 'test-*.ts', 'mock*.js', 'mock*.ts',
            'check_*.py', '*.development.*'
        }

        scannable_extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java'}

        # Convert patterns to fnmatch format
        import fnmatch

        for item in project_path.rglob('*'):
            if not item.is_file() or item.suffix not in scannable_extensions:
                continue

            # Use path-aware exclusion instead of simple filename matching
            if self._should_exclude_file(item, project_path):
                continue

            # Additional: Prefer backend/ directory if it exists
            # This helps focus on Django apps
            if (project_path / 'backend').exists():
                # If backend exists and file is not in backend, skip root-level test files
                if 'backend' not in str(item.relative_to(project_path)):
                    # Skip files at root level that look like tests/scripts
                    if item.parent == project_path:
                        continue

            files.append(item)

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
        import fnmatch

        try:
            relative_path = file_path.relative_to(project_root)
        except ValueError:
            # File is outside project root, exclude it
            return True

        path_parts = relative_path.parts
        filename = file_path.name

        # Exclude patterns from _collect_files
        exclude_dirs = {
            'venv', 'env', '.venv', 'node_modules', '__pycache__', '.git',
            'tests', 'test', '.pytest_cache', '.tox', 'htmlcov',
            '.aider.tags.cache.v4', '.benchmarks', '.scannerwork', '.idea',
            'migrations', 'cypress', 'e2e', '__tests__',
            'dist', 'build', '.next', 'out', 'coverage',
            '.vercel', '.netlify', '.cache'
        }

        exclude_patterns = {
            'test_*.py', 'tests_*.py', '*_test.py', '*_tests.py', 'conftest.py',
            'locustfile*.py', '*_audit.py', '*_scan.py',
            'setup.py',
            '*.test.js', '*.test.jsx', '*.test.ts', '*.test.tsx',
            '*.spec.js', '*.spec.jsx', '*.spec.ts', '*.spec.tsx',
            '*.cy.js', '*.cy.ts', '*.cy.jsx', '*.cy.tsx',
            '*.config.js', '*.config.ts', '*.config.mjs', '*.config.cjs',
            'eslint.*', 'prettier.*', 'tailwind.*', 'vite.*',
            'playwright.*', 'postcss.*', 'jest.*', 'vitest.*',
            'tsconfig.*', 'jsconfig.*', 'babel.*', 'webpack.*',
            '*.min.js', '*.min.css', 'index-*.js', 'vendor-*.js',
            'test-*.js', 'test-*.ts', 'mock*.js', 'mock*.ts',
            'check_*.py', '*.development.*'
        }

        # 1. WHITELIST: config/settings/* are always production code
        #    Files like config/settings/test.py are settings, not tests!
        if len(path_parts) >= 2 and path_parts[-2] == 'settings':
            return False

        # 2. Check if file is in a test directory (by path)
        if any(part in exclude_dirs for part in path_parts):
            return True

        # 3. Exclude test file patterns
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True

        return False

    def _merge_findings(
        self,
        engine1_findings: List[Dict],
        engine2_findings: List[AIFinding],
        verbose: bool = False
    ) -> tuple:
        """
        Merge findings from both engines

        Returns:
            (merged_findings, stats)
        """
        if verbose:
            print(f"\n🔄 Merging findings...")
            print(f"   Engine 1: {len(engine1_findings)} findings")
            print(f"   Engine 2: {len(engine2_findings)} findings")

        merged = []
        engine1_only = 0
        engine2_only = 0
        both_engines = 0

        # Convert Engine 2 findings to same format
        engine2_dicts = [self._ai_finding_to_dict(f) for f in engine2_findings]

        # Add all Engine 1 findings
        for finding in engine1_findings:
            finding['detected_by'] = 'Engine 1 (Pattern)'
            merged.append(finding)
            engine1_only += 1

        # Add Engine 2 findings
        for finding in engine2_dicts:
            # Check if similar finding exists from Engine 1
            similar = self._find_similar_finding(finding, merged)

            if similar:
                # Both engines found it - increase confidence
                similar['detected_by'] = 'Both Engines'
                similar['confidence'] = min(1.0, similar.get('confidence', 0.5) + 0.3)
                similar['ai_context'] = finding.get('why_ai_generates_this', '')
                both_engines += 1
                engine1_only -= 1  # Was counted as engine1_only
            else:
                # Engine 2 only
                finding['detected_by'] = 'Engine 2 (AI)'
                merged.append(finding)
                engine2_only += 1

        if verbose:
            print(f"   ✅ Merged: {len(merged)} total findings")
            print(f"   Engine 1 only: {engine1_only}")
            print(f"   Engine 2 only: {engine2_only}")
            print(f"   Both engines: {both_engines}")

        stats = {
            'engine1_only': engine1_only,
            'engine2_only': engine2_only,
            'both_engines': both_engines
        }

        return merged, stats

    def _find_similar_finding(
        self,
        finding: Dict,
        existing_findings: List[Dict]
    ) -> Optional[Dict]:
        """Find similar finding in existing list"""
        for existing in existing_findings:
            # Check if same file and similar line number
            if (existing.get('file') == finding.get('file') and
                abs(existing.get('line', 0) - finding.get('line', 0)) <= 2 and
                existing.get('rule_id') == finding.get('rule_id')):
                return existing

        return None

    def _ai_finding_to_dict(self, finding: AIFinding) -> Dict:
        """Convert AI finding to dict format matching Engine 1"""
        return {
            'file': finding.file_path,
            'line': finding.line_number,
            'rule_id': finding.vulnerability_type,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'message': finding.message,
            'code': finding.vulnerable_code,
            'why_ai_generates_this': finding.why_ai_generates_this,
            'training_pattern_id': finding.training_pattern_id,
            'fix': finding.suggested_fix,
            'cwe': finding.cwe
        }

    def _print_summary(self, results: DualScanResults):
        """Print scan summary"""
        print(f"\n{'='*70}")
        print(f"SCAN COMPLETE")
        print(f"{'='*70}")
        print(f"Mode: {results.scan_mode.value.upper()}")
        print(f"Duration: {results.scan_duration:.2f}s")
        print(f"Files: {results.files_scanned}")
        print()
        print(f"FINDINGS:")
        print(f"  Total: {results.total_issues}")
        print(f"  Blocker: {results.blocker_count}")
        print(f"  Critical: {results.critical_count}")
        print(f"  High: {results.high_count}")
        print()
        print(f"DETECTION:")
        print(f"  Engine 1 only: {results.engine1_only}")
        print(f"  Engine 2 only: {results.engine2_only}")
        print(f"  Both engines: {results.both_engines} (high confidence)")
        print()
        print(f"VIBE DEBT SCORE: {results.vibe_debt_score}/100")
        print(f"{'='*70}")


def main():
    """Test Dual Scanner"""
    import os

    print("""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║                    DUAL ENGINE SCANNER                             ║
║                                                                    ║
║  Engine 1: Pattern-based (fast, precise)                          ║
║  Engine 2: AI-powered (deep, contextual)                          ║
║                                                                    ║
║  Modes:                                                            ║
║  - FAST: Engine 1 only (quick scan)                               ║
║  - DEEP: Engine 2 only (AI analysis)                              ║
║  - VERIFY: Both engines (high confidence)                         ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
    """)

    # Initialize scanner
    scanner = DualScanner()

    # Create test project
    test_dir = Path('/tmp/test_project')
    test_dir.mkdir(exist_ok=True)

    # Create vulnerable test file
    test_file = test_dir / 'app.py'
    test_file.write_text('''
def login(username, password):
    """Login user"""
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def get_user(user_id):
    """Get user"""
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return db.execute(query)
''')

    print(f"✅ Created test project: {test_dir}")
    print()

    # Test each mode
    for mode in [ScanMode.FAST, ScanMode.DEEP, ScanMode.VERIFY]:
        print(f"\n{'#'*70}")
        print(f"# Testing Mode: {mode.value.upper()}")
        print(f"{'#'*70}")

        results = scanner.scan_project(
            str(test_dir),
            mode=mode,
            verbose=True
        )

        # Show sample findings
        if results.total_issues > 0:
            print(f"\nSample Finding:")
            finding = results.merged_findings[0]
            print(f"  File: {Path(finding.get('file', 'unknown')).name}")
            print(f"  Line: {finding.get('line', 'N/A')}")
            print(f"  Type: {finding.get('rule_id', finding.get('type', 'unknown'))}")
            print(f"  Severity: {finding.get('severity', 'N/A')}")
            print(f"  Detected by: {finding.get('detected_by', 'Unknown')}")
            if finding.get('why_ai_generates_this'):
                print(f"  AI Context: {finding['why_ai_generates_this'][:100]}...")

        print(f"\n{'#'*70}\n")

    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    print(f"🗑️  Cleaned up test project")


if __name__ == '__main__':
    main()
