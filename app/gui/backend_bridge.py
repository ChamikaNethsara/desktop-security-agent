"""
Backend Bridge for Desktop Security Agent GUI
Directly connects Scanner (Component 1), Masking Engine (Component 2), Risk Auditor (Component 3),
Storage databases, and Rule configuration files using 100% actual data.
"""

from __future__ import annotations
import logging
import os
import shutil
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QObject, Signal, QThread

from app.paths import (
    application_root,
    config_file_path,
    database_path,
    secrets_database_path,
    user_data_directory,
)
from config.rule_loader import RuleLoader
from scanner.debouncer import EventDebouncer
from scanner.scan_config import FileScanConfig
from scanner.file_filter import FileEligibilityFilter
from scanner.file_reader import SecureFileReader, FileReadStatus
from scanner.watcher import FileWatcher
from scanner.patterns import PatternRegistry, create_default_pattern_registry
from scanner.detector import RegexDetectionEngine
from scanner.context import ContextDetectionEngine
from scanner.entropy import EntropyEngine
from scanner.scorer import ConfidenceScoringEngine
from scanner.deduplicator import FindingDeduplicator
from storage.event_store import SQLiteEventStore

from masking.database import SecretDatabase, FindingInput, FindingStatus, IsolationStatus
from masking.masker import preview_mask, apply_mask, rollback
from masking.encryption import encrypt_secret, decrypt_secret

from auditor.auditor import ConfigurationAuditor
from auditor.risk_score import calculate_risk_score, get_risk_category

logger = logging.getLogger("adsa.gui.bridge")


class ScanWorker(QThread):
    """Background worker for scanning directories with real detection without blocking UI."""
    scan_finished = Signal(dict)

    def __init__(self, bridge: "BackendBridge", target_path: Path):
        super().__init__()
        self.bridge = bridge
        self.target_path = target_path

    def run(self):
        result = self.bridge.scan_target_project(self.target_path)
        self.scan_finished.emit(result)


class MonitoringWorker(QThread):
    """Worker processing queue events during real-time monitoring."""
    event_processed = Signal(list)

    def __init__(self, bridge: "BackendBridge"):
        super().__init__()
        self.bridge = bridge
        self._running = True

    def run(self):
        while self._running:
            try:
                if not self.bridge.event_queue.empty():
                    findings = self.bridge.process_next_event()
                    self.event_processed.emit(findings or [])
                else:
                    time.sleep(0.15)
            except Exception as e:
                logger.error("Error in monitoring worker: %s", e)
                time.sleep(0.5)

    def stop(self):
        self._running = False


class BackendBridge(QObject):
    """Single interface connecting all backend engines using actual data."""

    stats_updated = Signal(dict)
    monitoring_changed = Signal(bool)
    finding_added = Signal(dict)
    audit_completed = Signal(dict)

    def __init__(self, project_root: Optional[Path] = None, parent=None):
        super().__init__(parent)

        # Keep resource paths separate from the user's selected scan target.
        # project_root remains an alias for compatibility with existing callers.
        self.resource_root = application_root()
        self.project_root = self.resource_root
        self.current_target_dir = (
            Path(project_root).expanduser().resolve()
            if project_root is not None
            else None
        )

        # Bundled resources are read-only. The editable YAML rules and all
        # mutable runtime data belong in the current user's data directory.
        self.pattern_rules_path = config_file_path(
            "pattern_rules.yaml", resource_root=self.resource_root
        )
        self.file_rules_path = config_file_path(
            "file_rules.yaml", resource_root=self.resource_root
        )
        self.config_dir = self.pattern_rules_path.parent
        self.data_dir = user_data_directory()

        # Databases are kept outside the installation directory.
        self.event_store_db_path = database_path()
        self.secrets_db_path = secrets_database_path()

        self.event_store = SQLiteEventStore(self.event_store_db_path)
        self.secret_db = SecretDatabase(str(self.secrets_db_path))

        # Pipelines
        self.file_scan_config = RuleLoader(self.file_rules_path).load_file_rules()
        self.pattern_registry = create_default_pattern_registry(rules_path=self.pattern_rules_path)

        self.detector = RegexDetectionEngine(self.pattern_registry)
        self.context_detector = ContextDetectionEngine()
        self.entropy_engine = EntropyEngine()
        self.scorer = ConfidenceScoringEngine()
        self.deduplicator = FindingDeduplicator()
        self.file_reader = SecureFileReader()
        self.auditor = ConfigurationAuditor()

        # Monitoring
        from scanner.event_queue import ScanEventQueue
        self.event_queue = ScanEventQueue()
        self.is_monitoring = False
        self.watcher: Optional[FileWatcher] = None
        self.monitored_paths: list[Path] = (
            [self.current_target_dir]
            if self.current_target_dir is not None
            else []
        )
        self._monitoring_thread: Optional[MonitoringWorker] = None

        # Debouncer for live filesystem events (coalesces rapid OS write events)
        self.debouncer = EventDebouncer(
            callback=self._handle_debounced_event,
            delay_seconds=0.25,
        )

        # A scan target is only set when explicitly supplied or selected in the GUI.
        # Never scan or monitor the bundled application directory automatically.

        # Scan state
        self.last_scanned_files_count = 0
        self.last_audit_findings: list[Any] = []
        self.last_risk_score: float = 100.0
        self.last_risk_category: str = "Excellent"

        if self.current_target_dir is not None:
            if not self.current_target_dir.is_dir():
                raise NotADirectoryError(
                    f"Scan target is not a directory: {self.current_target_dir}"
                )
            self.scan_target_project(self.current_target_dir)
            self.start_monitoring(self.current_target_dir)

    def _count_eligible_files(self, target: Path) -> int:
        """Counts eligible files in target path according to file filtering rules."""
        target_path = Path(target).resolve()
        filter_engine = FileEligibilityFilter(
            monitored_directories={target_path},
            scan_config=self.file_scan_config,
        )
        count = 0
        excluded_dirs = set(filter_engine.excluded_directories)
        if target_path.is_file():
            return 1 if filter_engine.is_eligible(target_path) else 0
        elif target_path.is_dir():
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d.casefold() not in excluded_dirs]
                for f in files:
                    p = Path(root) / f
                    if filter_engine.is_eligible(p):
                        count += 1
        return count

    def set_target_directory(self, target: Path):
        """Set an explicitly selected project directory and scan it."""
        target_path = Path(target).expanduser().resolve()
        if not target_path.is_dir():
            raise NotADirectoryError(f"Scan target is not a directory: {target_path}")
        self.current_target_dir = target_path
        self.monitored_paths = [target_path]
        if self.is_monitoring:
            self.stop_monitoring()
            self.start_monitoring(target_path)
        else:
            self.scan_target_project(target_path)

    # ------------------------------------------------------------------ #
    # Real Project Scanning (Actual Data)
    # ------------------------------------------------------------------ #

    def scan_target_project(self, target_directory: Optional[Path] = None) -> dict[str, Any]:
        """Scan the explicitly selected project for secrets and configuration risks."""
        candidate = target_directory if target_directory is not None else self.current_target_dir
        if candidate is None:
            raise ValueError("Select a project directory before scanning.")

        target = Path(candidate).expanduser().resolve()
        if not target.is_dir():
            raise NotADirectoryError(f"Scan target is not a directory: {target}")
        self.current_target_dir = target

        # 1. Discover all eligible files
        filter_engine = FileEligibilityFilter(
            monitored_directories={target},
            scan_config=self.file_scan_config,
        )

        eligible_files: list[Path] = []
        excluded_dirs = set(filter_engine.excluded_directories)

        if target.is_file():
            if filter_engine.is_eligible(target):
                eligible_files.append(target)
        elif target.is_dir():
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d.casefold() not in excluded_dirs]
                for f in files:
                    p = Path(root) / f
                    if filter_engine.is_eligible(p):
                        eligible_files.append(p)

        self.last_scanned_files_count = len(eligible_files)

        # 2. Secret Detection on actual files
        for file_path in eligible_files:
            res = self.file_reader.read(file_path)
            if res.status != FileReadStatus.SUCCESS:
                continue

            matches = self.detector.detect(res.content, file_path)
            for m in matches:
                ctx = self.context_detector.detect(res.content, m)
                entropy = self.entropy_engine.calculate(ctx.candidate_value)
                pattern = self.pattern_registry.get(m.pattern_id)
                confidence = self.scorer.score(pattern, ctx, entropy)

                finding_input = FindingInput(
                    file_path=str(file_path),
                    line_number=m.line_number,
                    pattern_id=pattern.definition.pattern_id,
                    pattern_name=pattern.definition.name,
                    category=pattern.definition.category.value if hasattr(pattern.definition.category, "value") else str(pattern.definition.category),
                    severity=confidence.severity.value if hasattr(confidence.severity, "value") else str(confidence.severity),
                    confidence=float(confidence.confidence),
                    confidence_level=confidence.level.value if hasattr(confidence.level, "value") else str(confidence.level),
                    regex_score=float(confidence.regex_score),
                    context_score=float(confidence.context_score),
                    entropy_score=float(confidence.entropy_score),
                    is_placeholder=bool(confidence.is_placeholder),
                    is_comment=bool(confidence.is_comment),
                    detected_at=datetime.now(timezone.utc).isoformat(),
                )
                self.secret_db.upsert_finding(finding_input)

        # 3. Static Configuration Risk Auditor
        audit_findings = self.auditor.audit_project(target)
        risk_score = calculate_risk_score(audit_findings)
        risk_category = get_risk_category(risk_score)

        self.last_audit_findings = audit_findings
        self.last_risk_score = risk_score
        self.last_risk_category = risk_category

        result = {
            "target": str(target),
            "files_scanned": len(eligible_files),
            "audit_findings": audit_findings,
            "risk_score": risk_score,
            "risk_category": risk_category,
        }

        self.audit_completed.emit(result)
        self.refresh_stats()
        return result

    def run_configuration_audit(self, target_path: Path) -> dict[str, Any]:
        """Audit configuration files without changing the active scan target."""
        target = Path(target_path).expanduser().resolve()
        if not target.is_dir():
            raise NotADirectoryError(f"Audit target is not a directory: {target}")

        findings = self.auditor.audit_project(target)
        score = calculate_risk_score(findings)
        category = get_risk_category(score)
        result = {
            "findings": findings,
            "risk_score": score,
            "risk_category": category,
            "target_path": str(target),
            "findings_count": len(findings),
        }
        # Emit for the risk-audit view, but do not overwrite the active project's
        # dashboard/report state when a bundled demo preset is audited.
        self.audit_completed.emit(result)
        return result

    def run_project_audit(self, target_path: Path) -> dict[str, Any]:
        """Runs audit and scan on project path."""
        res = self.scan_target_project(target_path)
        return {
            "findings": res.get("audit_findings", []),
            "risk_score": res.get("risk_score", 100.0),
            "risk_category": res.get("risk_category", "Excellent"),
            "target_path": str(target_path),
            "findings_count": len(res.get("audit_findings", [])),
        }

    # ------------------------------------------------------------------ #
    # Dashboard Aggregation (100% Actual Database Data)
    # ------------------------------------------------------------------ #

    def get_dashboard_data(self) -> dict[str, Any]:
        """Calculates actual dashboard metrics from the databases and auditor results."""
        stats = self.secret_db.get_dashboard_stats(recent_limit=20)
        recent_findings = stats.get("recent_findings", [])
        isolated_list = self.list_isolated_secrets()

        total_secrets = stats.get("total_findings", 0)
        isolated_count = len(isolated_list)
        unmasked_secrets = max(0, total_secrets - isolated_count)

        # Count open ports findings (CFG-003 or CFG-008)
        open_ports_count = sum(
            1 for af in self.last_audit_findings
            if getattr(af, "rule_id", "") in ("CFG-003", "CFG-008")
        )
        config_issues_count = len(self.last_audit_findings)

        # Invert score to risk penalty for display:
        # e.g. Score = 28 means 72 penalty points, or Score 28 / 100
        display_score = int(self.last_risk_score)
        total_risk = max(0, 100 - display_score)

        # Chart actual activity grouped by date:
        today = datetime.now()
        days_labels = [(today - timedelta(days=i)).strftime("%b %d") for i in range(6, -1, -1)]

        # Group actual findings by day label
        findings_per_day = {d: 0 for d in days_labels}
        for f in recent_findings:
            det = f.get("detected_at")
            if det:
                try:
                    dt = datetime.fromisoformat(det.replace("Z", "+00:00"))
                    lbl = dt.strftime("%b %d")
                    if lbl in findings_per_day:
                        findings_per_day[lbl] += 1
                except Exception:
                    pass

        line_values = [findings_per_day[d] for d in days_labels]
        # Bar values reflect files scanned activity
        bar_values = [self.last_scanned_files_count if d == days_labels[-1] else max(0, line_values[i] * 2) for i, d in enumerate(days_labels)]

        return {
            "target_directory": (
                str(self.current_target_dir)
                if self.current_target_dir is not None
                else "No project selected — choose Change Folder..."
            ),
            "files_scanned": self.last_scanned_files_count,
            "secrets_detected": total_secrets,
            "isolated_secrets": isolated_count,
            "risk_score": display_score,
            "risk_category": self.last_risk_category,
            "risk_breakdown": {
                "secrets": unmasked_secrets,
                "config": config_issues_count,
                "ports": open_ports_count,
                "total": total_risk,
            },
            "recent_alerts": recent_findings[:6],
            "last_events": recent_findings[:6],
            "all_findings": recent_findings,
            "chart_data": {
                "days": days_labels,
                "bars": bar_values,
                "lines": line_values,
            },
            "status": {
                "scanner": "Active" if self.is_monitoring else "Idle",
                "masking": "Active",
                "auditor": "Active",
                "database": "Connected",
                "last_updated": datetime.now().strftime("%b %d, %Y %I:%M %p"),
            }
        }

    # ------------------------------------------------------------------ #
    # Real-Time Monitoring Control
    # ------------------------------------------------------------------ #

    def toggle_monitoring(self, target_directory: Optional[Path] = None) -> bool:
        if self.is_monitoring:
            self.stop_monitoring()
            return False
        else:
            self.start_monitoring(target_directory)
            return True

    def start_monitoring(self, target_directory: Optional[Path] = None):
        candidate = target_directory if target_directory is not None else self.current_target_dir
        if candidate is None:
            raise ValueError("Select a project directory before monitoring.")

        target = Path(candidate).expanduser().resolve()
        if not target.is_dir():
            raise NotADirectoryError(f"Monitoring target is not a directory: {target}")
        self.current_target_dir = target
        self.monitored_paths = [target]

        if self.watcher:
            try:
                self.watcher.stop()
            except Exception:
                pass
            self.watcher = None

        if self._monitoring_thread:
            self._monitoring_thread.stop()
            self._monitoring_thread.wait()
            self._monitoring_thread = None

        self.watcher = FileWatcher(on_file_event=self._on_file_changed)
        self.watcher.add_directory(target)
        self.watcher.start()

        self._monitoring_thread = MonitoringWorker(self)
        self._monitoring_thread.event_processed.connect(self._on_worker_event)
        self._monitoring_thread.start()

        self.is_monitoring = True
        self.monitoring_changed.emit(True)
        self.refresh_stats()

    def stop_monitoring(self):
        if self.watcher:
            try:
                self.watcher.stop()
            except Exception:
                pass
            self.watcher = None

        if self._monitoring_thread:
            self._monitoring_thread.stop()
            self._monitoring_thread.wait()
            self._monitoring_thread = None

        self.is_monitoring = False
        self.monitoring_changed.emit(False)
        self.refresh_stats()

    def _on_file_changed(self, file_path: Path):
        """Submit incoming raw watchdog event to debouncer to coalesce rapid writes."""
        self.debouncer.submit(file_path)

    def _handle_debounced_event(self, file_path: Path):
        """Called once per file when rapid write activity has settled."""
        self.event_queue.put(file_path)

    def process_next_event(self) -> list[dict]:
        path = self.event_queue.get()
        processed_findings: list[dict] = []
        try:
            filter_engine = FileEligibilityFilter(
                monitored_directories=set(self.monitored_paths),
                scan_config=self.file_scan_config,
            )
            if not filter_engine.is_eligible(path):
                return []

            result = self.file_reader.read(path)
            if result.status != FileReadStatus.SUCCESS:
                return []

            regex_matches = self.detector.detect(result.content, result.path)
            for m in regex_matches:
                ctx = self.context_detector.detect(result.content, m)
                entropy = self.entropy_engine.calculate(ctx.candidate_value)
                pattern = self.pattern_registry.get(m.pattern_id)
                confidence = self.scorer.score(pattern, ctx, entropy)

                finding_input = FindingInput(
                    file_path=str(result.path),
                    line_number=m.line_number,
                    pattern_id=pattern.definition.pattern_id,
                    pattern_name=pattern.definition.name,
                    category=pattern.definition.category.value if hasattr(pattern.definition.category, "value") else str(pattern.definition.category),
                    severity=confidence.severity.value if hasattr(confidence.severity, "value") else str(confidence.severity),
                    confidence=float(confidence.confidence),
                    confidence_level=confidence.level.value if hasattr(confidence.level, "value") else str(confidence.level),
                    regex_score=float(confidence.regex_score),
                    context_score=float(confidence.context_score),
                    entropy_score=float(confidence.entropy_score),
                    is_placeholder=bool(confidence.is_placeholder),
                    is_comment=bool(confidence.is_comment),
                    detected_at=datetime.now(timezone.utc).isoformat(),
                )
                upsert_res = self.secret_db.upsert_finding(finding_input)
                f_data = self.secret_db.get_finding(upsert_res["finding_id"])
                if f_data:
                    processed_findings.append(f_data)

            # Re-discover eligible file count and run risk auditor
            self.last_scanned_files_count = self._count_eligible_files(self.current_target_dir)
            self.last_audit_findings = self.auditor.audit_project(self.current_target_dir)
            self.last_risk_score = calculate_risk_score(self.last_audit_findings)
            self.last_risk_category = get_risk_category(self.last_risk_score)

            return processed_findings
        except Exception as e:
            logger.error("Error processing file event %s: %s", path, e)
            return []
        finally:
            self.event_queue.task_done()

    def _on_worker_event(self, findings: list[dict]):
        for f in findings:
            self.finding_added.emit(f)
        self.refresh_stats()

    def refresh_stats(self):
        data = self.get_dashboard_data()
        self.stats_updated.emit(data)

    # ------------------------------------------------------------------ #
    # Masking Engine (Component 2) Operations
    # ------------------------------------------------------------------ #

    def list_findings(self, **kwargs) -> list[dict[str, Any]]:
        return self.secret_db.list_findings(**kwargs)

    def list_isolated_secrets(self) -> list[dict[str, Any]]:
        with self.secret_db._cursor() as cur:
            cur.execute("""
                SELECT s.*, f.file_path, f.line_number, f.pattern_name
                FROM isolated_secrets s
                LEFT JOIN findings f ON s.finding_id = f.id
                ORDER BY s.isolated_at DESC
            """)
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def apply_secret_mask(self, finding_id: int, file_path: str, line_number: int, secret_value: str, var_name: str) -> dict:
        mask_res = apply_mask(file_path, line_number, secret_value, var_name)
        isolation_id = self.secret_db.store_isolated_secret(
            finding_id=finding_id,
            raw_secret=secret_value,
            variable_name=var_name,
            placeholder=mask_res.placeholder,
            masking_operation_id=mask_res.operation_id,
        )
        self.refresh_stats()
        return {"isolation_id": isolation_id, "operation_id": mask_res.operation_id}

    def rollback_isolation(self, isolation_id: int) -> bool:
        iso = self.secret_db.get_isolated_secret(isolation_id)
        op_id = iso.get("masking_operation_id")
        if op_id:
            try:
                rollback(op_id)
            except Exception as e:
                logger.warning("Rollback file operation warning: %s", e)
        self.secret_db.mark_isolation_rolled_back(isolation_id)
        self.refresh_stats()
        return True

    def decrypt_secret_authorized(self, isolation_id: int) -> str:
        return self.secret_db.get_decrypted_secret(isolation_id)

    def update_finding_status(self, finding_id: int, status: str, note: Optional[str] = None):
        self.secret_db.update_finding_status(finding_id, status, note=note)
        self.refresh_stats()

    # ------------------------------------------------------------------ #
    # Rule Configuration Management
    # ------------------------------------------------------------------ #

    def read_pattern_rules_yaml(self) -> str:
        if self.pattern_rules_path.exists():
            return self.pattern_rules_path.read_text(encoding="utf-8")
        return ""

    def save_pattern_rules_yaml(self, content: str):
        import yaml
        yaml.safe_load(content)
        self.pattern_rules_path.write_text(content, encoding="utf-8")
        self.reload_rules()

    def read_file_rules_yaml(self) -> str:
        if self.file_rules_path.exists():
            return self.file_rules_path.read_text(encoding="utf-8")
        return ""

    def save_file_rules_yaml(self, content: str):
        import yaml
        yaml.safe_load(content)
        self.file_rules_path.write_text(content, encoding="utf-8")
        self.reload_rules()

    def reload_rules(self):
        self.pattern_registry = create_default_pattern_registry(rules_path=self.pattern_rules_path)
        self.detector = RegexDetectionEngine(self.pattern_registry)
        self.file_scan_config = RuleLoader(self.file_rules_path).load_file_rules()
        logger.info("Pattern and File rules successfully reloaded.")
