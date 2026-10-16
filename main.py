"""
SecureGuard - Desktop Security Agent - Main Entry Point
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is always in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load local development settings before importing application modules.
try:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass # Production builds can run without python-dotenv.


from app.main import main

if __name__ == "__main__":
    raise SystemExit(main())
