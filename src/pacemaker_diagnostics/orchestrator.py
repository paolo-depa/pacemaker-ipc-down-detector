import os
import logging
import subprocess
from typing import List

from . import config
from .utils import DiagnosticsContext, ProcfsScanner
from .tasks import (
    DiagnosticTask, JournalContextTask, ProcessTraceTask, IpcStateTask, ClusterStateTask,
    NssLatencyTask, SystemPressureTask, SbdTask, ThirdPartyAuditTask,
    SapHanaAuditTask, BpfTraceTask
)

class DiagnosticsOrchestrator:
    """Manages the full diagnostic collection pipeline."""
    def __init__(self, daemon_name: str, pid: str, timeout_line: str = "", journal_lines=None):
        self.ctx = DiagnosticsContext(daemon_name, pid)
        self.tasks: List[DiagnosticTask] = []
        if timeout_line:
            self.tasks.append(JournalContextTask(timeout_line, journal_lines or []))

        # Pure Python Tasks (Enabled by default)
        if not config.DISABLE_PROCESS_TRACE:
            self.tasks.append(ProcessTraceTask())
        if not config.DISABLE_IPC_STATE:
            self.tasks.append(IpcStateTask())
        if not config.DISABLE_SYSTEM_PRESSURE:
            self.tasks.append(SystemPressureTask())
        if not config.DISABLE_SBD:
            self.tasks.append(SbdTask())
        if not config.DISABLE_THIRD_PARTY_AUDIT:
            self.tasks.append(ThirdPartyAuditTask())
        if not config.DISABLE_SAP_HANA_AUDIT:
            self.tasks.append(SapHanaAuditTask())

        # External Tool Tasks (Disabled by default)
        if config.ENABLE_CLUSTER_STATE:
            self.tasks.append(ClusterStateTask())
        if config.ENABLE_NSS_LATENCY:
            self.tasks.append(NssLatencyTask())
        if config.ENABLE_BPF_TRACE:
            self.tasks.append(BpfTraceTask())

    def execute(self):
        logging.info(f"START: Initiating diagnostic dump for {self.ctx.daemon_name} (PID: {self.ctx.pid}) in {self.ctx.base_dir}")
        try:
            # Single pass procfs scan
            targets = config.SECURITY_AGENTS + config.MONITORING_AGENTS + config.SAP_HANA_PROCESSES
            scanner = ProcfsScanner(targets)

            for task in self.tasks:
                try:
                    task.run(self.ctx, scanner)
                except Exception as e:
                    logging.error(f"Task {task.__class__.__name__} failed: {e}")

            # Spawn crm_report asynchronously for wider perspective.
            # We use Popen instead of run() because crm_report compresses large cluster logs
            # which takes minutes; we don't want to block this daemon from finishing.
            if config.ENABLE_CRM_REPORT:
                report_path = os.path.join(self.ctx.base_dir, "crm_report_diagnostics.tar.bz2")
                subprocess.Popen(
                    ["crm_report", "--from", "5 minutes ago", report_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

            logging.info(f"SUCCESS: Completed diagnostics for {self.ctx.daemon_name}. Saved to {self.ctx.base_dir}")
        except Exception as e:
            logging.error(f"Critical error during diagnostic dump: {e}")
