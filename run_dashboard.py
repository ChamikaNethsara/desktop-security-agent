"""
SecureGuard Desktop Security Agent - GUI Launcher
Run this script to start the desktop management dashboard.
Usage: python -m run_dashboard
"""

import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.paths import resource_path

# Load local environment configuration in development when python-dotenv
# is installed. The packaged application must also work without this
# optional development dependency.
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv is not None:
    # Do not load a development .env file in the packaged application.
    if not getattr(sys, "frozen", False):
        load_dotenv(ROOT / ".env")

from app.gui.main_window import MainWindow


def main() -> None:
    app = QApplication.instance()

    if app is None:
        app = QApplication(sys.argv)

    # Use the project's shared resource-path helper.
    icon_path = resource_path("resources", "security_agent.ico")
    app_icon = QIcon(str(icon_path))

    if app_icon.isNull():
        print(f"WARNING: Application icon could not be loaded: {icon_path}")
    else:
        app.setWindowIcon(app_icon)

    window = MainWindow()

    if not app_icon.isNull():
        window.setWindowIcon(app_icon)

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
