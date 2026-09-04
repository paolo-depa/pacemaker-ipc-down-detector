import re
import argparse
import sys

# --- Configuration Defaults ---
OUT_DIR = "/var/log/pacemaker"
LOG_FILE = f"{OUT_DIR}/push_diagnostics.log"
COOLDOWN_SECONDS = 60.0

# Tasks disabled by default (External software dependent)
ENABLE_CLUSTER_STATE = False
ENABLE_NSS_LATENCY = False
ENABLE_BPF_TRACE = False
ENABLE_CRM_REPORT = False

# Tasks enabled by default (Pure Python / ProcFS)
DISABLE_PROCESS_TRACE = False
DISABLE_IPC_STATE = False
DISABLE_SYSTEM_PRESSURE = False
DISABLE_SBD = False
DISABLE_THIRD_PARTY_AUDIT = False
DISABLE_SAP_HANA_AUDIT = False

BPFTRACE_DURATION_SEC = 5
NSS_LATENCY_THRESHOLD_MS = 100.0
JOURNAL_CONTEXT_LINES = 200

TIMEOUT_PATTERN = re.compile(
    r"(pacemaker-[a-z]+)\[(\d+)\] is unresponsive to ipc after 1 tries"
)

# Agents that could potentially block memory maps (mmap_sem)
# during deep anti-virus or compliance scans of large process spaces.
SECURITY_AGENTS = [
    "ds_agent", "falcon-sensor", "mfetpd", "mfeesp",
    "qualys-agent", "scx", "clamd", "auditd"
]

# Performance monitors that might aggressively read /proc/[pid]/smaps
MONITORING_AGENTS = [
    "atop", "datadog-agent", "dynatrace-agent", "saposcol", "collectd"
]

SAP_HANA_PROCESSES = [
    "hdbnameserver", "hdbindexserver", "hdbrsutil"
]

def parse_args(args_list=None):
    """Parses CLI arguments and updates the global configuration variables."""
    global OUT_DIR, LOG_FILE, COOLDOWN_SECONDS, BPFTRACE_DURATION_SEC, NSS_LATENCY_THRESHOLD_MS, JOURNAL_CONTEXT_LINES
    global ENABLE_CLUSTER_STATE, ENABLE_NSS_LATENCY, ENABLE_BPF_TRACE, ENABLE_CRM_REPORT
    global DISABLE_PROCESS_TRACE, DISABLE_IPC_STATE, DISABLE_SYSTEM_PRESSURE
    global DISABLE_SBD, DISABLE_THIRD_PARTY_AUDIT, DISABLE_SAP_HANA_AUDIT
    global SECURITY_AGENTS, MONITORING_AGENTS, SAP_HANA_PROCESSES

    if args_list is None:
        args_list = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Pacemaker Push-Based Diagnostic Suite")
    parser.add_argument("--out-dir", type=str, default=OUT_DIR, help="Base directory for diagnostic captures")
    parser.add_argument("--log-file", type=str, default=None, help="Path to the daemon log file (Defaults to OUT_DIR/push_diagnostics.log)")
    parser.add_argument("--cooldown", type=float, default=COOLDOWN_SECONDS, help="Cooldown in seconds between captures")

    # External tool flags (Disabled by default)
    parser.add_argument("--enable-cluster-state", action="store_true",
                        help="Enable cluster state task (Requires: corosync-cfgtool, corosync-cmapctl, cibadmin)")
    parser.add_argument("--enable-nss-latency", action="store_true", help="Enable NSS latency test task (Requires: getent)")
    parser.add_argument("--enable-bpf-trace", action="store_true", help="Enable eBPF kernel tracing task (Requires: bpftrace)")
    parser.add_argument("--enable-crm-report", action="store_true", help="Enable asynchronous crm_report collection (Requires: crm_report)")

    # Pure Python flags (Enabled by default)
    parser.add_argument("--disable-process-trace", action="store_true", help="Disable process trace task (Pure Python: /proc/[pid]/stack, fd)")
    parser.add_argument("--disable-ipc-state", action="store_true", help="Disable IPC state task (Pure Python: /proc/sysvipc, /dev/shm)")
    parser.add_argument("--disable-system-pressure", action="store_true", help="Disable System Pressure task (Pure Python: /proc/pressure)")
    parser.add_argument("--disable-sbd", action="store_true", help="Disable SBD config check task (Pure Python: /etc/sysconfig/sbd)")
    parser.add_argument("--disable-third-party-audit", action="store_true", help="Disable 3rd party audit task (Pure Python: /proc/[pid]/status)")
    parser.add_argument("--disable-sap-hana-audit", action="store_true", help="Disable SAP HANA audit task (Pure Python: /proc/[pid]/status)")

    parser.add_argument("--bpftrace-duration", type=int, default=BPFTRACE_DURATION_SEC, help="Duration for bpftrace capture in seconds")
    parser.add_argument("--nss-latency-threshold", type=float, default=NSS_LATENCY_THRESHOLD_MS, help="NSS getent latency warning threshold in ms")
    parser.add_argument(
        "--journal-context-lines", type=int, default=JOURNAL_CONTEXT_LINES,
        help="Number of recent pacemaker journal lines to persist per trigger"
    )
    parser.add_argument("--security-agents", type=str, nargs="*", default=SECURITY_AGENTS, help="List of security agents to monitor")
    parser.add_argument("--monitoring-agents", type=str, nargs="*", default=MONITORING_AGENTS, help="List of monitoring agents to monitor")
    parser.add_argument("--hana-processes", type=str, nargs="*", default=SAP_HANA_PROCESSES, help="List of SAP HANA processes to monitor")

    args = parser.parse_args(args_list)

    OUT_DIR = args.out_dir
    LOG_FILE = args.log_file if args.log_file else f"{OUT_DIR}/push_diagnostics.log"
    COOLDOWN_SECONDS = args.cooldown

    if args.enable_cluster_state:
        ENABLE_CLUSTER_STATE = True
    if args.enable_nss_latency:
        ENABLE_NSS_LATENCY = True
    if args.enable_bpf_trace:
        ENABLE_BPF_TRACE = True
    if args.enable_crm_report:
        ENABLE_CRM_REPORT = True

    if args.disable_process_trace:
        DISABLE_PROCESS_TRACE = True
    if args.disable_ipc_state:
        DISABLE_IPC_STATE = True
    if args.disable_system_pressure:
        DISABLE_SYSTEM_PRESSURE = True
    if args.disable_sbd:
        DISABLE_SBD = True
    if args.disable_third_party_audit:
        DISABLE_THIRD_PARTY_AUDIT = True
    if args.disable_sap_hana_audit:
        DISABLE_SAP_HANA_AUDIT = True

    BPFTRACE_DURATION_SEC = args.bpftrace_duration
    NSS_LATENCY_THRESHOLD_MS = args.nss_latency_threshold
    JOURNAL_CONTEXT_LINES = max(0, args.journal_context_lines)

    if args.security_agents:
        SECURITY_AGENTS = args.security_agents
    if args.monitoring_agents:
        MONITORING_AGENTS = args.monitoring_agents
    if args.hana_processes:
        SAP_HANA_PROCESSES = args.hana_processes

    return args
