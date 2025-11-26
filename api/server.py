"""
FastAPI Server for Code Archaeologist

Provides HTTP API endpoints for the desktop app to trigger scans
and retrieve results.
"""

import sys
import os
from pathlib import Path

# Setup Python path for both local development AND PyInstaller bundle
# This MUST come before any local imports
_this_file = Path(__file__).resolve()
_analysis_engine_dir = _this_file.parent.parent  # analysis_engine folder
_project_root = _analysis_engine_dir.parent  # code-archaeologist folder

# Add paths for imports to work in both environments
sys.path.insert(0, str(_analysis_engine_dir))  # For: from core.xxx
sys.path.insert(0, str(_project_root))  # For: from analysis_engine.xxx

# Handle PyInstaller bundle
if getattr(sys, 'frozen', False):
    # Running in PyInstaller bundle
    _bundle_dir = Path(sys._MEIPASS)
    sys.path.insert(0, str(_bundle_dir))
    # Create fake analysis_engine reference
    sys.path.insert(0, str(_bundle_dir.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import asyncio
from datetime import datetime
import uuid

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = _project_root / '.env'
load_dotenv(dotenv_path=env_path)

# Debug: Verify API key is loaded
api_key = os.environ.get('OPENAI_API_KEY')
if api_key:
    print(f"✅ OpenAI API key loaded: {api_key[:20]}...{api_key[-4:]}")
else:
    print(f"❌ OpenAI API key NOT loaded from {env_path}")
    print(f"   .env file exists: {env_path.exists()}")

from core.dual_scanner import DualScanner, ScanMode

app = FastAPI(title="Code Archaeologist API", version="1.0.0")

# Enable CORS for Electron app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify Electron app origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Models
# ============================================================================

class ScanRequest(BaseModel):
    project_path: str
    mode: str = "FAST"  # FAST, DEEP, VERIFY (or legacy: quick, full, security, vibe)
    include_tests: bool = True
    include_dependencies: bool = False
    openai_api_key: Optional[str] = None  # API key from Settings


class Issue(BaseModel):
    id: str
    type: str
    severity: str
    title: str
    description: str
    file_path: str
    line: Optional[int] = None
    column: Optional[int] = None
    confidence: float
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    fix_suggestion: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    vibe_debt_score: float
    production_ready_score: float
    findings: List[Issue]
    scan_timestamp: str
    scan_duration: float
    files_scanned: int


# In-memory storage for scan results (use Redis in production)
scan_results_cache = {}

# Initialize dual scanner once
dual_scanner = DualScanner()


# ============================================================================
# Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Code Archaeologist API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/scan", response_model=ScanResult)
async def start_scan(request: ScanRequest):
    """
    Start a dual engine code analysis scan

    Modes:
    - FAST: Engine 1 only (pattern-based, instant)
    - DEEP: Engine 2 only (AI-powered, thorough)
    - VERIFY: Both engines (highest confidence)
    """
    try:
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Validate project path
        project_path = Path(request.project_path)
        if not project_path.exists():
            raise HTTPException(status_code=400, detail="Project path does not exist")

        if not project_path.is_dir():
            raise HTTPException(status_code=400, detail="Project path must be a directory")

        # Map mode string to enum
        mode_map = {
            "FAST": ScanMode.FAST,
            "DEEP": ScanMode.DEEP,
            "VERIFY": ScanMode.VERIFY,
            # Legacy modes
            "quick": ScanMode.FAST,
            "full": ScanMode.VERIFY,
            "security": ScanMode.FAST,
            "vibe": ScanMode.FAST,
        }

        scan_mode = mode_map.get(request.mode.upper(), ScanMode.FAST)

        print(f"\n{'='*70}")
        print(f"📡 API: Scan request received")
        print(f"   Project: {request.project_path}")
        print(f"   Mode: {request.mode} → {scan_mode.value}")
        print(f"   API Key: {'Provided' if request.openai_api_key else 'Not provided (using env)'}")
        print(f"{'='*70}\n")

        # Set API key from request if provided
        if request.openai_api_key:
            os.environ['OPENAI_API_KEY'] = request.openai_api_key

        # Run dual engine scan
        results = dual_scanner.scan_project(
            str(project_path),
            mode=scan_mode,
            verbose=True
        )

        # Convert findings to Issue format
        issues = []
        for finding in results.merged_findings:  # Show all findings
            issues.append(Issue(
                id=finding.get('id', str(uuid.uuid4())),
                type=finding.get('rule_id', finding.get('type', 'SECURITY')),
                severity=finding.get('severity', 'MEDIUM'),
                title=finding.get('message', 'Untitled Issue'),
                description=finding.get('message', ''),
                file_path=finding.get('file', ''),
                line=finding.get('line'),
                column=finding.get('column'),
                confidence=finding.get('confidence', 0.8),
                owasp_category=finding.get('owasp_category'),
                cwe_id=finding.get('cwe'),
                fix_suggestion=finding.get('fix', ''),
            ))

        # Calculate production readiness (threshold-based, less aggressive)
        critical_count = len([f for f in results.merged_findings if f.get('severity') == 'CRITICAL'])
        blocker_count = len([f for f in results.merged_findings if f.get('severity') == 'BLOCKER'])

        # Projects with < 10 critical issues can still be 50%+ ready
        if critical_count < 10:
            base_score = 70
        else:
            base_score = 30

        production_ready_score = max(0, min(100, base_score - (blocker_count * 20) - (critical_count * 2)))

        # Create result
        result = ScanResult(
            scan_id=scan_id,
            vibe_debt_score=float(results.vibe_debt_score),
            production_ready_score=float(production_ready_score),
            findings=issues,
            scan_timestamp=start_time.isoformat(),
            scan_duration=results.scan_duration,
            files_scanned=results.files_scanned,
        )

        # Cache result
        scan_results_cache[scan_id] = result

        print(f"\n✅ Scan complete - returning {len(issues)} issues\n")

        return result

    except Exception as e:
        print(f"\n❌ Scan failed: {e}\n")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan_results(scan_id: str):
    """
    Retrieve scan results by ID
    """
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail="Scan results not found")

    return scan_results_cache[scan_id]


@app.delete("/api/scan/{scan_id}")
async def delete_scan_results(scan_id: str):
    """
    Delete scan results
    """
    if scan_id in scan_results_cache:
        del scan_results_cache[scan_id]
        return {"status": "deleted"}

    raise HTTPException(status_code=404, detail="Scan results not found")


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "server:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
