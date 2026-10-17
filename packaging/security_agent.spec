# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


# ---------------------------------------------------------------------------
# -- Resolve paths independently of the current working directory.
# ---------------------------------------------------------------------------

SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent

ENTRY_SCRIPT = PROJECT_ROOT / "run_dashboard.py"
RESOURCE_DIR = PROJECT_ROOT / "resources"
ICON_PATH = RESOURCE_DIR / "security_agent.ico"
CONFIG_DIR = PROJECT_ROOT / "config"

if not ENTRY_SCRIPT.is_file():
    raise FileNotFoundError(
        f"Application entry point was not found: {ENTRY_SCRIPT}"
    )

if not ICON_PATH.is_file():
    raise FileNotFoundError(
        f"Application icon was not found: {ICON_PATH}"
    )

# Allow PyInstaller's hook utilities to discover local project packages.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# -- Include runtime data files.
# ---------------------------------------------------------------------------

DATAS = []

if CONFIG_DIR.is_dir():
    for source in sorted(CONFIG_DIR.rglob("*")):
        if source.is_file() and source.suffix.lower() in {".yaml", ".yml"}:
            relative_parent = source.relative_to(CONFIG_DIR).parent
            destination = Path("config") / relative_parent

            DATAS.append((str(source), destination.as_posix()))


# Include application resources, including the icon, for runtime use.
# The icon is also embedded into the Windows executable below.
if RESOURCE_DIR.is_dir():
    for source in sorted(RESOURCE_DIR.rglob("*")):
        if source.is_file():
            relative_parent = source.relative_to(RESOURCE_DIR).parent
            destination = Path("resources") / relative_parent

            DATAS.append((str(source), destination.as_posix()))


# ---------------------------------------------------------------------------
# -- Collect local package submodules.
# ---------------------------------------------------------------------------


PACKAGE_CANDIDATES = (
    "app",
    "app.gui",
    "scanner",
    "config",
    "auditor",
    "masking",
    "storage",
)

HIDDEN_IMPORTS = []

for package in PACKAGE_CANDIDATES:
    package_path = PROJECT_ROOT.joinpath(*package.split("."))

    # Collect only packages that have an __init__.py file.
    if (package_path / "__init__.py").is_file():
        HIDDEN_IMPORTS.extend(collect_submodules(package))

HIDDEN_IMPORTS = list(dict.fromkeys(HIDDEN_IMPORTS))



# ---------------------------------------------------------------------------
# -- Analyze the application.
# ---------------------------------------------------------------------------

a = Analysis(
    [str(ENTRY_SCRIPT)],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)


# ---------------------------------------------------------------------------
# -- Create the Python module archive.
# ---------------------------------------------------------------------------

pyz = PYZ(a.pure)


# ---------------------------------------------------------------------------
# -- Build the Windows executable.
# ---------------------------------------------------------------------------

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecurityAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON_PATH),
)


# ---------------------------------------------------------------------------
# -- Collect the onedir distribution.
# ---------------------------------------------------------------------------

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SecurityAgent",
)
