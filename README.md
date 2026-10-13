# Desktop Security Agent

[![Python 3.13.15](https://img.shields.io/badge/Python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![PySide6](https://img.shields.io/badge/GUI-PySide6-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://doc.qt.io/qtforpython-6/)
[![pytest](https://img.shields.io/badge/Testing-pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Release](https://img.shields.io/badge/Release-v1.0.0-orange?style=for-the-badge)](#current-status)


**A local-first Windows desktop security agent for detecting hardcoded secrets, protecting sensitive configuration values, and assessing project configuration risks.**

[Components](#the-four-components) · [Technology Stack](#technology-stack) · [Development](#development) · [Team](#team)


---
---

## The Four Components

The Desktop Security Agent is designed around four components that work together to help developers identify, isolate, and remediate security weaknesses in local projects.

### 01 · Real-Time Configuration & Secret Scanner

**Status:** In development

Continuously monitors user-selected project directories and scans eligible configuration files for potential exposed credentials.

- **File monitoring:** Uses `watchdog` and an initial scan to detect existing and newly modified eligible files.
- **Supported files:** `.env`, `Dockerfile`, `*.json`, `*.yaml`, `*.yml`, and `settings.*`.
- **Secret detection:** Combines provider-specific patterns, generic detection, contextual indicators, and Shannon entropy analysis.
- **Finding analysis:** Assigns detection confidence, type, severity, location, and a fingerprint.
- **Duplicate suppression:** Uses fingerprints to avoid repeatedly recording the same finding.

### 02 · Secret Masking & Encrypted Storage Engine

**Status:** In development

Designed to isolate detected secrets and reduce the risk of accidentally committing credentials to version control.

- Redacts detected secret values from eligible configuration files.
- Stores protected secret values locally using AES-256 encryption.
- Replaces hardcoded values with environment-variable placeholders where supported.
- Keeps secret storage on the local machine.

### 03 · Static Configuration Risk Auditor

**Status:** In development

Designed to inspect project configuration files for security weaknesses and calculate a project-level Security Risk Score out of 100.

- Identifies potential issues involving unencrypted HTTP, excessive privileges, and exposed port bindings.
- Analyses Dockerfiles and supported JSON, YAML, and settings files.
- Applies configurable security rules to identify misconfigurations.
- Produces risk findings to help developers prioritise remediation.

### 04 · Centralized Desktop Management Dashboard

**Status:** In development.

Provides the desktop interface for managing scans, reviewing findings, and presenting project security information.

- PySide6-based Windows desktop interface.
- Planned real-time alerts and secret-isolation event history.
- Planned project risk scorecards and risk summaries.
- Planned detailed PDF audit reports with export functionality.

---
---


## Development

### Requirements

- **Python 3.13.15** — version used for development and testing.
- **Git** — required to clone the repository and manage source code.
- **Windows** — required to build and test the Windows application and installer.
- **Inno Setup 7.1.0** — required to compile the Windows installer.
- **pip** — used to install the project's Python dependencies. A compatible version is included with standard Python installations.

The application uses the dependencies listed in `requirements.txt`. Additional dependencies for testing and packaging are listed in `requirements-dev.txt`.

### Setup

Follow these steps to clone the repository, create a Python virtual environment, and install the project dependencies on Windows.

### 1. Clone the repository

Open either **PowerShell** or **Git Bash** and run:

```bash
git clone https://github.com/ChamikaNethsara/desktop-security-agent.git
```

### 2. Check your Python installation

Make sure Python 3.13.15 is installed.

```bash
python --version
```
If the `python` command is not recognised, install Python and ensure it is available on your system's PATH.

### 3. Create a virtual environment

From the project root, run:

```bash
python -m venv .venv
```

This creates a `.venv` directory to keep the project's Python packages separate from your system-wide Python installation.

### 4. Activate the virtual environment

Choose the instructions for your terminal.

*PowerShell*

```powershell
.\.venv\Scripts\Activate.ps1
```

*Git Bash*

```bash
source .venv/Scripts/activate
```

After activation, your terminal prompt should normally display `(.venv)`.

### 5. Install the dependencies

With the virtual environment activated, install the development and build dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

This installs the runtime dependencies from `requirements.txt`, together with the testing and packaging tools listed in `requirements-dev.txt`.

### 6. Run the application
The application supports two execution modes:

- **Static Configuration Risk Auditor (default):** Scans a target project directories for configuration security issues.
- **Real-Time Desktop Security Agent (`--watch`):** Monitors a target project directories for file changes and processes detected events.

Run the commands below from the project root with your virtual environment activated.

#### Option 1 — Run the Configuration Risk Auditor

Scan a project directory and display the audit report.

*PowerShell:*

```powershell
python -m app.main "C:\path\to\target-project"
```

*Git Bash:*

```bash
python -m app.main "/c/path/to/target-project"
```

#### Option 2 — Run the Real-Time Security Agent

Start continuous monitoring of a target project directory.

*PowerShell:*

```powershell
python -m app.main "C:\path\to\target-project" --watch
```

*Git Bash:*

```bash
python -m app.main "/c/path/to/target-project" --watch
```

The agent will display its running status and monitor the specified directory. Press `Ctrl+C` to stop monitoring.


### 7. Run the tests

To execute the automated test suite, run:

```bash
python -m pytest
```

Pytest will discover and run the project's tests and display the results in the terminal.


## Technology Stack

| Category | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.13.15 | Application logic and security analysis |
| **Desktop GUI** | PySide6 | Native desktop interface |
| **File Monitoring** | `watchdog` | Detect filesystem changes in monitored project folders |
| **Configuration Parsing** | PyYAML, Python `json` | Read supported YAML and JSON configuration files |
| **Pattern Matching** | Python `re` | Identify potential secrets using detection patterns |
| **Entropy Analysis** | Python `math` | Calculate Shannon entropy to help assess secret-like values |
| **Fingerprinting** | Python `hashlib` | Generate fingerprints for finding identification and deduplication |
| **Concurrency** | `queue`, worker threads | Process filesystem events and background scanning tasks |
| **Local Storage** | SQLite | Persist application findings and event data locally |
| **Testing** | pytest | Run automated tests |
| **Application Packaging** | PyInstaller | Bundle the Python application into a Windows executable |
| **Installer** | Inno Setup | Build the Windows setup executable |

---
---

## Team

| Component | Developer |
|-----------|-----------|
| 1. Real-Time Configuration & Secret Scanner | Nethsara M.W.C.G |
| 2. Secret Masking & Encrypted Storage Engine | Senanayaka S.M.V.K |
| 3. Static Configuration Risk Auditor | De Silva M.C.U |
| 4. Centralized Desktop Management Dashboard | Rathnayaka N.A.N |

---
---