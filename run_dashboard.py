"""
SecureGuard Desktop Security Agent - GUI Launcher
Run this script to start the desktop management dashboard.
Usage: python run_dashboard.py
"""

import sys
from pathlib import Path

# Ensure the project root is on sys.path.
ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Load local environment configuration in development when python-dotenv is installed.
# The packaged application must also work without this optional development dependency.
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(ROOT / ".env")

from PySide6.QtWidgets import QApplication
from app.gui.main_window import MainWindow


def main() -> None:
    app = QApplication.instance()

    if app is None:
        app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
