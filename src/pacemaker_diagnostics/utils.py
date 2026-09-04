import os
import time
import logging
import subprocess
import shutil
from typing import List, Dict

from . import config

class DiagnosticsContext:
    """Manages output directories and provides safe I/O utilities."""
    def __init__(self, daemon_name: str, pid: str):
        self.daemon_name = daemon_name
        self.pid = pid
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.base_dir = os.path.join(config.OUT_DIR, f"push_diag_{self.daemon_name}_{self.timestamp}")
        os.makedirs(self.base_dir, exist_ok=True)

    def mkdir(self, sub_dir: str) -> str:
        """Create and return an absolute path for a sub-directory."""
        path = os.path.join(self.base_dir, sub_dir)
        os.makedirs(path, exist_ok=True)
        return path

    def write_file(self, sub_dir: str, filename: str, content: str):
        """Safely write string content to a file."""
        path = os.path.join(self.mkdir(sub_dir), filename)
        try:
            with open(path, "w") as f:
                f.write(content)
        except IOError as e:
            logging.error(f"Failed to write {path}: {e}")

    def capture_cmd(self, sub_dir: str, filename: str, cmd: List[str], timeout: float = 5.0, shell: bool = False) -> bool:
        """Run a command and write its stdout to a file."""
        path = os.path.join(self.mkdir(sub_dir), filename)
        try:
            with open(path, "w") as f:
                subprocess.run(
                    cmd, stdout=f, stderr=subprocess.DEVNULL,
                    timeout=timeout, shell=shell
                )
            return True
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
            self.write_file(sub_dir, filename, f"Command execution failed: {e}\n")
            return False

    def copy_file(self, src: str, sub_dir: str, filename: str):
        """Safely copy a file if it exists."""
        if os.path.exists(src):
            path = os.path.join(self.mkdir(sub_dir), filename)
            try:
                shutil.copy2(src, path)
            except IOError:
                pass


class ProcfsScanner:
    """Single-pass /proc scanner to minimize OS impact."""
    def __init__(self, targets: List[str]):
        self.targets = targets
        self.found_pids: Dict[str, List[int]] = {t: [] for t in targets}
        self.scan()

    def scan(self):
        """Iterates over /proc once and maps process names to PIDs."""
        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit():
                    continue
                try:
                    # In Linux, /proc/[pid]/cmdline arguments are separated by null bytes (\x00).
                    # We read as bytes, replace nulls with spaces, and decode to allow standard substring matching.
                    with open(f'/proc/{pid_str}/cmdline', 'rb') as f:
                        cmd = f.read().replace(b'\x00', b' ').decode(errors='replace')
                        for target in self.targets:
                            if target in cmd:
                                self.found_pids[target].append(int(pid_str))
                except IOError:
                    continue
        except OSError:
            pass

    def get_pids(self, target: str) -> List[int]:
        return self.found_pids.get(target, [])
