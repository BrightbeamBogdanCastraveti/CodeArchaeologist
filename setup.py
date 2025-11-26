"""
Module: setup.py
Purpose: Package configuration for Code Archaeologist analysis engine.
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="code-archaeologist-engine",
    version="0.1.0",
    author="Code Archaeologist Team",
    description="Analysis engine for detecting and fixing issues in AI-generated code",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/code-archaeologist",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.27.0",
        "pydantic>=2.5.3",
        "bandit>=1.7.6",
        "semgrep>=1.55.0",
        "anthropic>=0.18.1",
        "sqlalchemy>=2.0.25",
        "click>=8.1.7",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.4",
            "pytest-cov>=4.1.0",
            "black>=24.1.1",
            "isort>=5.13.2",
            "ruff>=0.1.14",
            "mypy>=1.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "code-arch=cli.main:cli",
        ],
    },
)
