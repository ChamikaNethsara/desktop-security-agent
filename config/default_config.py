from pathlib import Path

# -- File monitoring
DEFAULT_MONITORED_DIRECTORIES: list[Path] = []

# -- File scanning limits
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# -- Event processing
DEBOUNCE_DELAY_SECONDS = 0.35 # Delay before queuing the file
MAX_QUEUE_SIZE = 1000 # Maximum number of paths


# -- File filtering
INCLUDED_FILENAMES = {
    ".env",
    "dockerfile",
}

INCLUDED_EXTENSIONS = {
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".config",
}

INCLUDED_NAME_PATTERNS = {
    "settings",
    "config",
}


# -- Directory exclusions
EXCLUDED_DIRECTORIES = {
    ".git",
    ".svn",
    ".hg",

    "node_modules",

    "venv",
    ".venv",

    "__pycache__",

    "build",
    "dist",

    ".idea",
    ".vscode",
}