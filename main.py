"""
SecureGuard - Desktop Security Agent
Main Root Entry Point

Usage:
    python main.py                  # Launches the Centralized Desktop Dashboard (GUI)
    python main.py --gui            # Explicitly launches Desktop Dashboard (GUI)
    python main.py <folder>         # Runs Static Configuration Risk Auditor (CLI)
    python main.py <folder> --watch # Runs Real-Time File Monitoring Agent (CLI)
"""

from __future__ import annotations
import sys
from pathlib import Path

# Ensure project root is always in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import main

if __name__ == "__main__":
    raise SystemExit(main())
