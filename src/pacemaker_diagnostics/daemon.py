import os
import sys
import time
import signal
import logging
import threading
import subprocess
from typing import Dict

from . import config
from .orchestrator import DiagnosticsOrchestrator

def monitor_journal():
    """Streams systemd logs with minimal overhead."""
    logging.basicConfig(
        filename=config.LOG_FILE, level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.info("Starting journal monitoring loop...")

    # Spawn journalctl to stream logs.
    # bufsize=1 (line buffered) and universal_newlines=True (text mode)
    # ensure we process logs immediately line-by-line without buffering delays.
    proc = subprocess.Popen(
        ["journalctl", "-u", "pacemaker.service", "-f", "-n", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=1, universal_newlines=True, errors="replace"
    )

    def cleanup(signum, frame):
        logging.info("Termination signal received. Stopping child process...")
        proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    last_triggered: Dict[str, float] = {}
    cooldown_lock = threading.Lock()

    try:
        for line in proc.stdout:
            # Gate 1: Fast string search to cheaply discard >99% of irrelevant logs
            if "is unresponsive to ipc after 1 tries" not in line:
                continue

            # Gate 2: Expensive regex execution only on lines that passed Gate 1
            match = config.TIMEOUT_PATTERN.search(line)
            if not match:
                continue

            daemon_name, pid = match.groups()

            # Prevent diagnostic storms if a daemon spams timeouts.
            # Uses a thread lock since trigger() runs asynchronously.
            now = time.time()
            with cooldown_lock:
                last_time = last_triggered.get(daemon_name, 0.0)
                if (now - last_time) < config.COOLDOWN_SECONDS:
                    continue
                last_triggered[daemon_name] = now

            def trigger(d_name: str, d_pid: str):
                orchestrator = DiagnosticsOrchestrator(d_name, d_pid)
                orchestrator.execute()

            # Dispatch the blocking IO collection into a background thread
            # so we never stall the main log monitoring loop.
            threading.Thread(target=trigger, args=(daemon_name, pid), daemon=True).start()

    except Exception as e:
        logging.error(f"Monitoring loop aborted: {e}")
    finally:
        proc.terminate()

def main():
    config.parse_args()
    if os.getuid() != 0:
        print("This script must be run as root.", file=sys.stderr)
        sys.exit(1)
    monitor_journal()
