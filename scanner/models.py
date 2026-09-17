from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class SecretCategory(str, Enum):
    """
    Broad classification of a detected secret.
    """
    
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    DATABASE_CREDENTIAL = "database_credential"
    AUTHENTICATION_TOKEN = "authentication_token"
    GENERIC_SECRET = "generic_secret"


class SecretSeverity(str, Enum):
    """
    Severity assigned to a secret type.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """
    Immutable definition of a secret-detection rule.
    """

    pattern_id: str
    name: str
    category: SecretCategory
    regex: str
    severity: SecretSeverity
    base_confidence: float
    provider: str | None = None
    entropy_required: bool = False
    context_required: bool = False
    description: str = ""
    enabled: bool = True

    # Validate the rule definition when it is created.
    def __post_init__(self) -> None:
        if not self.pattern_id.strip():
            raise ValueError("pattern_id cannot be empty.")

        if not self.name.strip():
            raise ValueError("name cannot be empty.")

        if not self.regex.strip():
            raise ValueError("regex cannot be empty.")

        if not 0.0 <= self.base_confidence <= 1.0:
            raise ValueError("base_confidence must be between 0.0 and 1.0.")


class ConfidenceLevel(str, Enum):
    """
    Human-readable confidence classification.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ConfidenceScore:
    """
    Result produced by the confidence scoring engine.
    """

    confidence: float
    level: ConfidenceLevel

    regex_score: float
    context_score: float
    entropy_score: float

    is_placeholder: bool
    is_comment: bool

    severity: SecretSeverity

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0.")

        if not 0.0 <= self.regex_score <= 1.0:
            raise ValueError("regex_score must be between 0.0 and 1.0.")

        if not 0.0 <= self.context_score <= 1.0:
            raise ValueError("context_score must be between 0.0 and 1.0.")

        if not 0.0 <= self.entropy_score <= 1.0:
            raise ValueError("entropy_score must be between 0.0 and 1.0.")


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """
    Normalized representation of a detected secret.
    """

    file_path: Path
    line_number: int

    pattern_id: str
    pattern_name: str

    category: SecretCategory
    severity: SecretSeverity

    confidence: float
    confidence_level: ConfidenceLevel

    regex_score: float
    context_score: float
    entropy_score: float

    is_placeholder: bool
    is_comment: bool

    description: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Temporary hash used only for fingerprint generation.
    secret_hash: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.pattern_id.strip():
            raise ValueError("pattern_id cannot be empty.")

        if not self.pattern_name.strip():
            raise ValueError("pattern_name cannot be empty.")

        if self.line_number < 1:
            raise ValueError("line_number must be greater than or equal to 1.")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0.")

        if not 0.0 <= self.regex_score <= 1.0:
            raise ValueError("regex_score must be between 0.0 and 1.0.")

        if not 0.0 <= self.context_score <= 1.0:
            raise ValueError("context_score must be between 0.0 and 1.0.")

        if not 0.0 <= self.entropy_score <= 1.0:
            raise ValueError("entropy_score must be between 0.0 and 1.0.")

        if not self.file_path:
            raise ValueError("file_path cannot be empty.")