from pathlib import Path

# -- File monitoring
DEFAULT_MONITORED_DIRECTORIES: list[Path] = []

# -- File scanning limits
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# -- Event processing
DEBOUNCE_DELAY_SECONDS = 0.35 # Delay before queuing the file
MAX_QUEUE_SIZE = 1000 # Maximum number of paths