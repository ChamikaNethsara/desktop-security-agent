from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


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