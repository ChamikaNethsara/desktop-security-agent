from __future__ import annotations

import logging
from pathlib import Path

from config.default_config import (DEBOUNCE_DELAY_SECONDS)
from scanner.debouncer import EventDebouncer
from scanner.event_queue import ScanEventQueue
from scanner.file_filter import FileEligibilityFilter
from scanner.initial_scanner import InitialProjectScanner
from scanner.file_reader import (FileReadStatus, SecureFileReader)
from scanner.watcher import FileWatcher
from scanner.patterns import (PatternRegistry, create_default_pattern_registry)

from scanner.detector import RegexDetectionEngine
from scanner.context import ContextDetectionEngine
from scanner.entropy import EntropyEngine
from scanner.scorer import ConfidenceScoringEngine
from scanner.models import SecretFinding
from scanner.deduplicator import FindingDeduplicator
from storage.event_store import SQLiteEventStore

logger = logging.getLogger(__name__)


class SecurityAgentApplication:
    """
    Coordinates the first six stages of the security agent.
    """

    def __init__(self, monitored_directories: list[Path]) -> None:
        self._monitored_directories = {
            directory.expanduser().resolve()
            for directory in monitored_directories
        }

        if not self._monitored_directories:
            raise ValueError("At least one monitored directory is required.")

        self._event_queue = ScanEventQueue()
        self._file_filter = FileEligibilityFilter(monitored_directories=self._monitored_directories)
        self._initial_scanner = InitialProjectScanner(
            monitored_directories=self._monitored_directories,
            file_filter=self._file_filter,
            event_queue=self._event_queue
        )
        self._file_reader = SecureFileReader()
        self._debouncer = EventDebouncer(callback=self._handle_debounced_event, delay_seconds=DEBOUNCE_DELAY_SECONDS)
        self._watcher = FileWatcher(on_file_event=self._handle_file_event)

        for directory in self._monitored_directories:
            self._watcher.add_directory(directory)

        rules_path = Path("config/rules.yaml")
        self._pattern_registry: PatternRegistry = (create_default_pattern_registry(rules_path=rules_path))
        self._detector = RegexDetectionEngine(pattern_registry=self._pattern_registry)
        self._context_detector = ContextDetectionEngine()
        self._entropy_engine = EntropyEngine()
        self._scorer = ConfidenceScoringEngine()
        self._deduplicator = FindingDeduplicator()

        database_path = Path("data/security_agent.db")
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._event_store = SQLiteEventStore(database_path=database_path)


    # Called by the filesystem watcher and passes the event to the debounce layer.
    def _handle_file_event(self, path: Path) -> None:
        self._debouncer.submit(path)


    # Called after the debounce period and queues the path only if it is eligible for scanning.
    def _handle_debounced_event(self, path: Path) -> None:
        if not self._file_filter.is_eligible(path):
            logger.debug("File is not eligible for scanning: %s", path)
            return
        
        self._event_queue.put(path)


    # Process one file from the queue
    def process_next_file(self) -> None:
        path = self._event_queue.get()

        try:
            result = self._file_reader.read(path)

            if result.status is not FileReadStatus.SUCCESS:
                logger.debug("File could not be processed: %s (%s)", path, result.status.value)
                return

            logger.info(
                "Eligible file read successfully: %s (%d bytes, %s)",
                path,
                result.size_bytes,
                result.encoding
            )

            regex_matches = self._detector.detect(content=result.content, file_path=result.path)

            logger.info(
                "Regex scan completed: %s (%d matches)",
                result.path,
                len(regex_matches),
            )

            for regex_match in regex_matches:
                context_result = self._context_detector.detect(content=result.content, regex_match=regex_match)
                entropy_result = self._entropy_engine.calculate(context_result.candidate_value)
                pattern = self._pattern_registry.get(regex_match.pattern_id)

                confidence_result = self._scorer.score(
                    pattern=pattern,
                    context_result=context_result,
                    entropy_result=entropy_result,
                )

                '''
                logger.info(
                    "Detection assessment: %s | line=%d | "
                    "confidence=%.2f | level=%s | severity=%s | "
                    "regex=%.2f | context=%.2f | entropy=%.2f | "
                    "placeholder=%s | comment=%s",
                    regex_match.pattern_id,
                    regex_match.line_number,
                    confidence_result.confidence,
                    confidence_result.level.value,
                    confidence_result.severity.value,
                    confidence_result.regex_score,
                    confidence_result.context_score,
                    confidence_result.entropy_score,
                    confidence_result.is_placeholder,
                    confidence_result.is_comment,
                )
                '''

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
                )

                if self._deduplicator.is_duplicate(finding):
                    logger.debug(
                        "Duplicate finding suppressed: %s | line=%d",
                        finding.pattern_id,
                        finding.line_number,
                    )
                    continue

                fingerprint = self._event_store.save(finding)

                logger.info(
                    "Secret finding persisted: %s | line=%d | "
                    "confidence=%.2f | level=%s | severity=%s | "
                    "fingerprint=%s",
                    finding.pattern_id,
                    finding.line_number,
                    finding.confidence,
                    finding.confidence_level.value,
                    finding.severity.value,
                    fingerprint,
                )

        finally:
            self._event_queue.task_done()


    def start(self) -> None:
        logger.info("Starting Desktop Security Agent...")

        self._watcher.start()
        self._initial_scanner.scan()

        logger.info("Desktop Security Agent started.")


    def stop(self) -> None:
        logger.info("Stopping Desktop Security Agent...")

        self._debouncer.shutdown()
        self._watcher.stop()
        self._event_store.close()

        logger.info("Desktop Security Agent stopped.")


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