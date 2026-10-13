
from __future__ import annotations

import logging
from pathlib import Path

from config.default_config import DEBOUNCE_DELAY_SECONDS
from config.rule_loader import RuleLoader

from scanner.debouncer import EventDebouncer
from scanner.event_queue import ScanEventQueue
from scanner.scan_config import FileScanConfig
from scanner.file_filter import FileEligibilityFilter
from scanner.initial_scanner import InitialProjectScanner
from scanner.file_reader import FileReadStatus, SecureFileReader
from scanner.watcher import FileWatcher
from scanner.patterns import (
    PatternRegistry,
    create_default_pattern_registry,
)

from scanner.detector import RegexDetectionEngine
from scanner.context import ContextDetectionEngine
from scanner.entropy import EntropyEngine
from scanner.scorer import ConfidenceScoringEngine
from scanner.models import SecretFinding
from scanner.fingerprint import FindingFingerprintGenerator
from scanner.deduplicator import FindingDeduplicator

from storage.event_store import SQLiteEventStore

# Component 2 — Secret Masking & Encrypted Storage
from storage.database import SecretDatabase, FindingInput, FindingStatus
from storage.masker import preview_mask, apply_mask, rollback
from storage.encryption import encrypt_secret, decrypt_secret

# Static Configuration Risk Auditor
from auditor import ConfigurationAuditor


logger = logging.getLogger(__name__)


class SecurityAgentApplication:
    """
    Coordinates the Desktop Security Agent.

    Includes:
    - File monitoring
    - Real-time secret detection
    - Confidence scoring
    - Secret finding storage
    - Static configuration risk auditing
    """

    def __init__(self, monitored_directories: list[Path]) -> None:

        self._monitored_directories = {
            directory.expanduser().resolve()
            for directory in monitored_directories
        }

        if not self._monitored_directories:
            raise ValueError(
                "At least one monitored directory is required."
            )

        self._event_queue = ScanEventQueue()

        application_root = Path(__file__).resolve().parent.parent

        # --------------------------------------------------
        # Configuration
        # --------------------------------------------------

        config_directory = application_root / "config"

        pattern_rules_path = (
            config_directory / "pattern_rules.yaml"
        )

        file_rules_path = (
            config_directory / "file_rules.yaml"
        )

        self._file_scan_config = (
            RuleLoader(file_rules_path).load_file_rules()
        )

        # --------------------------------------------------
        # File filtering and initial scanning
        # --------------------------------------------------

        self._file_filter = FileEligibilityFilter(
            monitored_directories=self._monitored_directories,
            scan_config=self._file_scan_config,
        )

        self._initial_scanner = InitialProjectScanner(
            monitored_directories=self._monitored_directories,
            file_filter=self._file_filter,
            event_queue=self._event_queue,
        )

        # --------------------------------------------------
        # File monitoring
        # --------------------------------------------------

        self._file_reader = SecureFileReader()

        self._debouncer = EventDebouncer(
            callback=self._handle_debounced_event,
            delay_seconds=DEBOUNCE_DELAY_SECONDS,
        )

        self._watcher = FileWatcher(
            on_file_event=self._handle_file_event
        )

        for directory in self._monitored_directories:
            self._watcher.add_directory(directory)

        # --------------------------------------------------
        # Secret detection pipeline
        # --------------------------------------------------

        self._pattern_registry: PatternRegistry = (
            create_default_pattern_registry(
                rules_path=pattern_rules_path
            )
        )

        self._detector = RegexDetectionEngine(
            pattern_registry=self._pattern_registry
        )

        self._context_detector = ContextDetectionEngine()

        self._entropy_engine = EntropyEngine()

        self._scorer = ConfidenceScoringEngine()

        self._deduplicator = FindingDeduplicator()

        # --------------------------------------------------
        # SQLite event storage
        # --------------------------------------------------

        database_path = (
            application_root / "data" / "security_agent.db"
        )

        database_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self._event_store = SQLiteEventStore(
            database_path=database_path
        )

        # Component 2 — encrypted findings / isolated secrets DB
        component2_db_path = (
            application_root / "data" / "adsa_secrets.db"
        )
        self._secret_db = SecretDatabase(
            db_path=str(component2_db_path)
        )

        # --------------------------------------------------
        # Static Configuration Risk Auditor
        # --------------------------------------------------

        self._configuration_auditor = ConfigurationAuditor()

        logger.info(
            "Static Configuration Risk Auditor initialized "
            "with %d rules.",
            len(self._configuration_auditor.engine.rules),
        )

    # ------------------------------------------------------
    # File watcher callbacks
    # ------------------------------------------------------

    def _handle_file_event(self, path: Path) -> None:

        self._debouncer.submit(path)

    def _handle_debounced_event(self, path: Path) -> None:

        if not self._file_filter.is_eligible(path):

            logger.debug(
                "File is not eligible for scanning: %s",
                path,
            )

            return

        self._event_queue.put(path)

    # ------------------------------------------------------
    # Process one queued file
    # ------------------------------------------------------

    def process_next_file(self) -> None:

        path = self._event_queue.get()

        try:

            result = self._file_reader.read(path)

            if result.status is not FileReadStatus.SUCCESS:

                logger.debug(
                    "File could not be processed: %s (%s)",
                    path,
                    result.status.value,
                )

                return

            logger.info(
                "Eligible file read successfully: "
                "%s (%d bytes, %s)",
                path,
                result.size_bytes,
                result.encoding,
            )

            # ----------------------------------------------
            # Existing secret detection
            # ----------------------------------------------

            regex_matches = self._detector.detect(
                content=result.content,
                file_path=result.path,
            )

            logger.info(
                "Regex scan completed: %s (%d matches)",
                result.path,
                len(regex_matches),
            )

            for regex_match in regex_matches:

                context_result = self._context_detector.detect(
                    content=result.content,
                    regex_match=regex_match,
                )

                candidate_value = (
                    context_result.candidate_value
                )

                entropy_result = (
                    self._entropy_engine.calculate(
                        candidate_value
                    )
                )

                secret_hash = (
                    FindingFingerprintGenerator.hash_secret(
                        candidate_value
                    )
                )

                pattern = self._pattern_registry.get(
                    regex_match.pattern_id
                )

                confidence_result = self._scorer.score(
                    pattern=pattern,
                    context_result=context_result,
                    entropy_result=entropy_result,
                )

                finding = SecretFinding(
                    file_path=result.path,
                    line_number=regex_match.line_number,
                    pattern_id=pattern.definition.pattern_id,
                    pattern_name=pattern.definition.name,
                    category=pattern.definition.category,
                    severity=confidence_result.severity,
                    confidence=confidence_result.confidence,
                    confidence_level=confidence_result.level,
                    regex_score=confidence_result.regex_score,
                    context_score=confidence_result.context_score,
                    entropy_score=confidence_result.entropy_score,
                    is_placeholder=confidence_result.is_placeholder,
                    is_comment=confidence_result.is_comment,
                    description=pattern.definition.description,
                    secret_hash=secret_hash,
                )

                if self._deduplicator.is_duplicate(
                    finding
                ):

                    logger.debug(
                        "Duplicate finding suppressed: "
                        "%s | line=%d",
                        finding.pattern_id,
                        finding.line_number,
                    )

                    continue

                fingerprint = self._event_store.save(
                    finding
                )

                # Component 2: persist finding metadata (no raw secret in DB)
                try:
                    from datetime import datetime, timezone

                    finding_input = FindingInput(
                        file_path=str(finding.file_path),
                        line_number=finding.line_number,
                        pattern_id=finding.pattern_id,
                        pattern_name=finding.pattern_name,
                        category=finding.category,
                        severity=(
                            finding.severity.value
                            if hasattr(finding.severity, "value")
                            else str(finding.severity)
                        ),
                        confidence=float(finding.confidence),
                        confidence_level=(
                            finding.confidence_level.value
                            if hasattr(finding.confidence_level, "value")
                            else str(finding.confidence_level)
                        ),
                        regex_score=float(finding.regex_score),
                        context_score=float(finding.context_score),
                        entropy_score=float(finding.entropy_score),
                        is_placeholder=bool(finding.is_placeholder),
                        is_comment=bool(finding.is_comment),
                        detected_at=datetime.now(timezone.utc).isoformat(),
                    )
                    self._secret_db.upsert_finding(finding_input)
                except Exception:
                    logger.exception(
                        "Component 2 finding persistence failed for %s",
                        finding.file_path,
                    )

                logger.info(
                    "Secret finding persisted: "
                    "%s | line=%d | "
                    "confidence=%.2f | "
                    "level=%s | severity=%s | "
                    "fingerprint=%s",
                    finding.pattern_id,
                    finding.line_number,
                    finding.confidence,
                    finding.confidence_level.value,
                    finding.severity.value,
                    fingerprint,
                )

            # ----------------------------------------------
            # Static Configuration Risk Auditor
            # Runs once per file, outside the secret loop
            # ----------------------------------------------

            try:

                audit_findings = (
                    self._configuration_auditor.audit_file(
                        result.path
                    )
                )

                logger.info(
                    "Configuration audit completed: "
                    "%s (%d findings)",
                    result.path,
                    len(audit_findings),
                )

                for audit_finding in audit_findings:

                    logger.info(
                        "Configuration risk: "
                        "%s | severity=%s | file=%s",
                        audit_finding.rule_id,
                        audit_finding.severity,
                        result.path,
                    )

            except Exception:

                logger.exception(
                    "Configuration audit failed for %s",
                    result.path,
                )

        finally:

            self._event_queue.task_done()

    # ------------------------------------------------------
    # Start application
    # ------------------------------------------------------

    def start(self) -> None:

        logger.info(
            "Starting Desktop Security Agent..."
        )

        self._watcher.start()

        self._initial_scanner.scan()

        logger.info(
            "Desktop Security Agent started."
        )

    # ------------------------------------------------------
    # Stop application
    # ------------------------------------------------------

    def stop(self) -> None:

        logger.info(
            "Stopping Desktop Security Agent..."
        )

        self._debouncer.shutdown()

        self._watcher.stop()

        self._event_store.close()
        self._secret_db.close()
        
        logger.info(
            "Desktop Security Agent stopped."
        )

    # ------------------------------------------------------
    # Properties
    # ------------------------------------------------------

    @property
    def event_queue(self) -> ScanEventQueue:
        return self._event_queue

    @property
    def pattern_registry(self) -> PatternRegistry:
        return self._pattern_registry

    @property
    def detector(self) -> RegexDetectionEngine:
        return self._detector

    @property
    def context_detector(self) -> ContextDetectionEngine:
        return self._context_detector

    @property
    def entropy_engine(self) -> EntropyEngine:
        return self._entropy_engine

    @property
    def scorer(self) -> ConfidenceScoringEngine:
        return self._scorer

    @property
    def deduplicator(self) -> FindingDeduplicator:
        return self._deduplicator

    @property
    def event_store(self) -> SQLiteEventStore:
        return self._event_store

    @property
    def initial_scanner(self) -> InitialProjectScanner:
        return self._initial_scanner

    @property
    def file_scan_config(self) -> FileScanConfig:
        return self._file_scan_config

    @property
    def configuration_auditor(self) -> ConfigurationAuditor:
        return self._configuration_auditor

    @property
    def secret_db(self) -> SecretDatabase:
        return self._secret_db