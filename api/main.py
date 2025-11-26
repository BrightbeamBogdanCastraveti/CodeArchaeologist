"""
Module: main.py
Author: Claude AI + Human Reviewer (Bogdan)
Purpose: Main FastAPI application for code analysis engine
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.security.security_analyzer import SecurityAnalyzer
from analyzers.architecture.architecture_analyzer import ArchitectureAnalyzer
from analyzers.testing.test_analyzer import TestAnalyzer
from analyzers.vibe_debt.vibe_debt_analyzer import VibeDebtAnalyzer

app = FastAPI(
    title="Code Archaeologist API",
    description="Turn AI-generated chaos into production-ready code",
    version="0.1.0"
)

# CORS middleware for Electron app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class AnalysisRequest(BaseModel):
    repo_path: str
    analysis_types: Optional[List[str]] = ["all"]

class Issue(BaseModel):
    id: str
    type: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    auto_fix_available: bool
    why_ai_did_this: Optional[str] = None
    why_its_wrong: Optional[str] = None
    how_to_prevent: Optional[str] = None

class AnalysisResult(BaseModel):
    repo_path: str
    vibe_debt_score: int
    readiness_score: int
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    issues: List[Issue]
    analysis_time: float

@app.get("/")
async def root():
    return {
        "name": "Code Archaeologist API",
        "version": "0.1.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_codebase(request: AnalysisRequest):
    """
    Analyze a codebase for security issues, architecture violations,
    testing gaps, and vibe debt.
    """
    import time
    start_time = time.time()

    if not os.path.exists(request.repo_path):
        raise HTTPException(status_code=404, detail="Repository path not found")

    try:
        all_issues = []

        # Run security analysis
        if "all" in request.analysis_types or "security" in request.analysis_types:
            security_analyzer = SecurityAnalyzer(request.repo_path)
            security_issues = security_analyzer.analyze()
            all_issues.extend(security_issues)

        # Run architecture analysis
        if "all" in request.analysis_types or "architecture" in request.analysis_types:
            arch_analyzer = ArchitectureAnalyzer(request.repo_path)
            arch_issues = arch_analyzer.analyze()
            all_issues.extend(arch_issues)

        # Run testing analysis
        if "all" in request.analysis_types or "testing" in request.analysis_types:
            test_analyzer = TestAnalyzer(request.repo_path)
            test_issues = test_analyzer.analyze()
            all_issues.extend(test_issues)

        # Run vibe debt analysis
        if "all" in request.analysis_types or "vibe_debt" in request.analysis_types:
            vibe_analyzer = VibeDebtAnalyzer(request.repo_path)
            vibe_issues = vibe_analyzer.analyze()
            all_issues.extend(vibe_issues)

        # Calculate scores
        critical_count = len([i for i in all_issues if i.get("severity") == "critical"])
        high_count = len([i for i in all_issues if i.get("severity") == "high"])
        medium_count = len([i for i in all_issues if i.get("severity") == "medium"])
        low_count = len([i for i in all_issues if i.get("severity") == "low"])

        # Readiness score calculation
        # Start at 100%, deduct points for issues
        readiness_score = 100
        readiness_score -= critical_count * 15  # -15% per critical
        readiness_score -= high_count * 5       # -5% per high
        readiness_score -= medium_count * 2     # -2% per medium
        readiness_score -= low_count * 0.5      # -0.5% per low
        readiness_score = max(0, readiness_score)

        # Vibe debt score (inverse of readiness)
        vibe_debt_score = 100 - readiness_score

        analysis_time = time.time() - start_time

        return AnalysisResult(
            repo_path=request.repo_path,
            vibe_debt_score=int(vibe_debt_score),
            readiness_score=int(readiness_score),
            total_issues=len(all_issues),
            critical_issues=critical_count,
            high_issues=high_count,
            medium_issues=medium_count,
            low_issues=low_count,
            issues=all_issues,
            analysis_time=analysis_time
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/fix-suggestion")
async def generate_fix_suggestion(issue: Issue):
    """
    Generate AI-powered fix suggestion for a specific issue.
    """
    # This would call Claude API in production
    return {
        "issue_id": issue.id,
        "original_code": "// Original code here",
        "fixed_code": "// Fixed code here",
        "explanation": "Fix explanation",
        "reasoning": "Why this fix matters",
        "test_cases": []
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
