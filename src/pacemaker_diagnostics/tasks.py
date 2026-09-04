import os
import time
import signal
import logging
import subprocess
import shutil

from . import config
from .utils import DiagnosticsContext, ProcfsScanner


class DiagnosticTask:
    """Base class for diagnostic collection modules."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        raise NotImplementedError()


class ProcessTraceTask(DiagnosticTask):
    """Captures kernel call stacks and process states. Pure Python implementation."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "process_trace"

        # Kernel callstack
        ctx.copy_file(f"/proc/{ctx.pid}/stack", sub, "kernel_callstack.txt")

        # Process params
        for param in ["status", "limits", "environ"]:
            ctx.copy_file(f"/proc/{ctx.pid}/{param}", sub, f"proc_{param}.txt")

        # File descriptors using pure python (No lsof external dependency)
        fd_dir = f"/proc/{ctx.pid}/fd"
        if os.path.exists(fd_dir):
            try:
                fds = os.listdir(fd_dir)
                links = [f"{fd} -> {os.readlink(os.path.join(fd_dir, fd))}" for fd in fds]
                ctx.write_file(sub, "open_file_descriptors.txt", "\n".join(links) + "\n")
            except OSError as e:
                ctx.write_file(sub, "open_file_descriptors.txt", f"Failed to enumerate /proc/pid/fd: {e}\n")

        # Send SIGTRAP to trigger Pacemaker's blackbox dump
        try:
            os.kill(int(ctx.pid), signal.SIGTRAP)
        except OSError as e:
            logging.error(f"Failed to send SIGTRAP to PID {ctx.pid}: {e}")


class IpcStateTask(DiagnosticTask):
    """Gathers POSIX and shared-memory state purely via Python I/O to avoid subprocess overhead."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "ipc"

        # Read sysvipc POSIX shared memory components directly from the kernel interface
        for ipc_type in ["shm", "sem", "msg"]:
            ctx.copy_file(f"/proc/sysvipc/{ipc_type}", sub, f"posix_{ipc_type}.txt")

        # Manually inspect the /dev/shm directory instead of invoking 'ls'
        if os.path.exists("/dev/shm"):
            try:
                dev_shm_entries = []
                qb_entries = []

                for name in os.listdir("/dev/shm"):
                    path = os.path.join("/dev/shm", name)
                    try:
                        st = os.stat(path)
                        info = f"{name}: size={st.st_size} uid={st.st_uid} gid={st.st_gid} mode={oct(st.st_mode)}"
                        dev_shm_entries.append(info)
                        if name.startswith("qb-"):
                            qb_entries.append(info)
                    except OSError:
                        pass

                ctx.write_file(sub, "dev_shm_root.txt", "\n".join(dev_shm_entries) + "\n")
                ctx.write_file(sub, "dev_shm_qb_segments.txt", "\n".join(qb_entries) + "\n")
            except OSError as e:
                ctx.write_file(sub, "dev_shm_error.txt", f"Error enumerating /dev/shm: {e}\n")


class ClusterStateTask(DiagnosticTask):
    """Gathers Corosync and Pacemaker cluster stats. (Requires External Tools)"""
    @staticmethod
    def _run_ss_snapshot(cmd):
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                check=False,
                text=True,
                errors="replace"
            )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return None

        if proc.returncode != 0:
            return None

        return proc.stdout if proc.stdout else ""

    @staticmethod
    def _capture_proc_net_snapshot(ctx: DiagnosticsContext, sub: str, filename: str, proc_files):
        lines = ["Capture backend: /proc/net fallback", ""]
        has_data = False
        for path in proc_files:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", errors="replace") as handle:
                    has_data = True
                    lines.append(f"=== {path} ===")
                    lines.append(handle.read().rstrip())
                    lines.append("")
            except OSError as ex:
                has_data = True
                lines.append(f"=== {path} ===")
                lines.append(f"Failed to read: {ex}")
                lines.append("")

        if has_data:
            ctx.write_file(sub, filename, "\n".join(lines).rstrip() + "\n")
            return

        ctx.write_file(sub, filename, "Capture backend: /proc/net fallback\n\nNo /proc/net socket data available.\n")

    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "cluster"
        ctx.capture_cmd(sub, "corosync_cfgtool.txt", ["corosync-cfgtool", "-s"])
        ctx.capture_cmd(sub, "corosync_cmapctl.txt", ["corosync-cmapctl"])

        ss_path = shutil.which("ss")
        if ss_path:
            ss_output = self._run_ss_snapshot([ss_path, "-anp"])
            if ss_output is not None:
                all_sockets_ok = True
                ctx.write_file(sub, "all_sockets.txt", "Capture backend: ss\n\n" + ss_output)

                udp_lines = []
                has_udp_rows = False
                for line in ss_output.splitlines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith("Netid"):
                        udp_lines.append(line)
                        continue
                    netid = stripped.split(None, 1)[0].lower()
                    if netid.startswith("udp"):
                        has_udp_rows = True
                        udp_lines.append(line)

                if has_udp_rows:
                    ctx.write_file(sub, "udp_sockets.txt", "Capture backend: ss\n\n" + "\n".join(udp_lines).rstrip() + "\n")
                    udp_sockets_ok = True
                else:
                    udp_sockets_ok = False
            else:
                all_sockets_ok = False
                udp_sockets_ok = False
        else:
            all_sockets_ok = False
            udp_sockets_ok = False

        if not all_sockets_ok:
            self._capture_proc_net_snapshot(
                ctx, sub, "all_sockets.txt",
                ["/proc/net/unix", "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6", "/proc/net/raw", "/proc/net/raw6"]
            )
        if not udp_sockets_ok:
            self._capture_proc_net_snapshot(
                ctx, sub, "udp_sockets.txt",
                ["/proc/net/udp", "/proc/net/udp6"]
            )

        ctx.capture_cmd(sub, "local_cib.xml", ["cibadmin", "-Ql", "-l"])


class NssLatencyTask(DiagnosticTask):
    """Measures lookup latency blocking non-root cluster operations. (Requires External Tools)"""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "directory_services"

        for conf in ["nsswitch.conf", "sssd/sssd.conf", "ldap.conf"]:
            ctx.copy_file(f"/etc/{conf}", sub, os.path.basename(conf))

        latency_out = ["--- NSS Lookup Latency Test ---"]
        for user in ["root", "hacluster", "postgres"]:
            start = time.time()
            try:
                # We specifically need to call 'getent' here to test the exact glibc
                # Name Service Switch resolution pathway that stalls the cluster.
                subprocess.run(["getent", "passwd", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
                elapsed = (time.time() - start) * 1000
                latency_out.append(f"Lookup for '{user}': {elapsed:.2f} ms")
                if elapsed > config.NSS_LATENCY_THRESHOLD_MS:
                    logging.warning(f"HIGH NSS LATENCY: '{user}' took {elapsed:.2f} ms (Threshold: {config.NSS_LATENCY_THRESHOLD_MS} ms).")
            except subprocess.TimeoutExpired:
                latency_out.append(f"Lookup for '{user}': TIMEOUT (>2000 ms)")
                logging.error(f"NSS TIMEOUT: '{user}'. This freezes executions.")

        ctx.write_file(sub, "lookup_latency.txt", "\n".join(latency_out) + "\n")


class SystemPressureTask(DiagnosticTask):
    """Captures CPU/Memory Pressure Stall Information (PSI). Pure Python."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "system"

        # First validate if PSI is enabled in the kernel
        if os.path.exists("/proc/pressure"):
            for psi_type in ["cpu", "memory", "io"]:
                ctx.copy_file(f"/proc/pressure/{psi_type}", sub, f"pressure_{psi_type}.txt")
        else:
            ctx.write_file(sub, "pressure_disabled.txt", "PSI (/proc/pressure) is not enabled on this kernel.\n")

        ctx.copy_file(
            "/sys/fs/cgroup/cpu/system.slice/pacemaker.service/cpu.stat",
            sub, "cgroup_cpu_stat.txt"
        )


class SbdTask(DiagnosticTask):
    """Captures STONITH Block Device Health. Pure Python."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "sbd"
        ctx.copy_file("/etc/sysconfig/sbd", sub, "sbd_config.txt")


class ThirdPartyAuditTask(DiagnosticTask):
    """Audits security and monitoring daemons exclusively through pure python ProcFS reads."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "security_and_monitoring"
        out = ["=== ACTIVE THIRD-PARTY SECURITY & MONITORING AGENTS ===\n"]

        for agent in config.SECURITY_AGENTS + config.MONITORING_AGENTS:
            pids = scanner.get_pids(agent)
            if not pids:
                continue

            out.append(f"Agent: {agent} (PIDs: {', '.join(map(str, pids))})")
            for pid in pids:
                out.append(f"  --- PID {pid} ---")

                # Extract vital memory/thread statistics directly from procfs (No ps subprocess overhead)
                status_path = f"/proc/{pid}/status"
                if os.path.exists(status_path):
                    try:
                        with open(status_path, "r") as s:
                            metrics = [line.strip() for line in s if any(key in line for key in ("State:", "VmSize:", "VmRSS:", "Threads:"))]
                            out.append("  System Usage:\n    " + "\n    ".join(metrics))
                    except Exception:
                        pass

                # Read kernel stack
                stack_path = f"/proc/{pid}/stack"
                if os.path.exists(stack_path):
                    try:
                        with open(stack_path, "r") as s:
                            out.append(f"  Kernel Stack:\n{s.read().strip()}")
                    except Exception as ex:
                        out.append(f"  Kernel Stack: Unable to read ({ex})")

                # Read wait channel
                wchan_path = f"/proc/{pid}/wchan"
                if os.path.exists(wchan_path):
                    try:
                        with open(wchan_path, "r") as w:
                            out.append(f"  Wait Channel (WCHAN): {w.read().strip()}")
                    except Exception:
                        pass
                out.append("")

        ctx.write_file(sub, "active_agents.txt", "\n".join(out) + "\n")


class SapHanaAuditTask(DiagnosticTask):
    """Audits SAP HANA locking via pure procfs reads. Pure Python."""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "sap_hana"
        out = ["=== SAP HANA PROCESS & KERNEL MEMORY LOCK AUDIT ===\n"]

        for proc in config.SAP_HANA_PROCESSES:
            pids = scanner.get_pids(proc)
            for pid in pids:
                out.append(f"Process: {proc} (PID: {pid})")

                try:
                    with open(f"/proc/{pid}/status", "r") as s:
                        for line in s:
                            if any(x in line for x in ["Name:", "State:", "VmSize:", "VmRSS:", "VmData:", "Threads:"]):
                                out.append(f"  {line.strip()}")
                except Exception:
                    pass

                stack_path = f"/proc/{pid}/stack"
                if os.path.exists(stack_path):
                    try:
                        with open(stack_path, "r") as s:
                            stack_content = s.read().strip()
                            out.append(f"  Kernel Stack:\n{stack_content}")

                            # Searching the kernel stack for memory semaphore locks (mmap_sem).
                            # If a process is blocked here, it's trapped in uninterruptible sleep (D state).
                            if any(x in stack_content for x in ["mmap_sem", "mmap_lock", "down_write", "down_read", "rwsem_down"]):
                                logging.critical(
                                    f"MMAP SEMAPHORE CONTENTION: HANA {proc} (PID {pid}) is locking mmap_sem!"
                                )
                    except Exception as ex:
                        out.append(f"  Kernel Stack: Unable to read ({ex})")
                out.append("")

        ctx.write_file(sub, "hana_process_limits.txt", "\n".join(out) + "\n")


class BpfTraceTask(DiagnosticTask):
    """Attaches bpftrace to stalling subdaemon. (Requires External Tools)"""
    def run(self, ctx: DiagnosticsContext, scanner: ProcfsScanner):
        sub = "bpf"
        bpftrace_path = shutil.which("bpftrace")
        if not bpftrace_path:
            for path in ["/usr/bin/bpftrace", "/usr/sbin/bpftrace", "/usr/local/bin/bpftrace"]:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    bpftrace_path = path
                    break

        if not bpftrace_path:
            logging.warning("bpftrace task enabled but executable not found.")
            ctx.write_file(sub, "bpftrace_missing.txt", "Install with: zypper in bpftrace | dnf install bpftrace\n")
            return

        logging.info(f"Starting bpftrace latency capture on PID {ctx.pid} for {config.BPFTRACE_DURATION_SEC}s...")

        # Inject eBPF tracepoints into the kernel to track futex (fast userspace mutex)
        # and semaphore wait latencies specifically for the stalled daemon's PID.
        bpf_prog = f"""
        tracepoint:syscalls:sys_enter_futex /pid == {ctx.pid}/ {{ @futex_start[tid] = nsecs; }}
        tracepoint:syscalls:sys_exit_futex /pid == {ctx.pid} && @futex_start[tid]/ {{
            @futex_wait_latency_us = hist((nsecs - @futex_start[tid]) / 1000); delete(@futex_start[tid]);
        }}
        tracepoint:syscalls:sys_enter_sem_timedwait /pid == {ctx.pid}/ {{ @sem_start[tid] = nsecs; }}
        tracepoint:syscalls:sys_exit_sem_timedwait /pid == {ctx.pid} && @sem_start[tid]/ {{
            @sem_wait_latency_us = hist((nsecs - @sem_start[tid]) / 1000); delete(@sem_start[tid]);
        }}
        tracepoint:raw_syscalls:sys_enter /pid == {ctx.pid}/ {{ @sys_start[tid] = nsecs; @sys_count[args->id]++; }}
        tracepoint:raw_syscalls:sys_exit /pid == {ctx.pid} && @sys_start[tid]/ {{
            $lat = (nsecs - @sys_start[tid]) / 1000;
            if ($lat > 10000) {{ @slow_syscalls[args->id] = hist($lat); }}
            delete(@sys_start[tid]);
        }}
        interval:s:{config.BPFTRACE_DURATION_SEC} {{ exit(); }}
        """

        ctx.capture_cmd(sub, "bpf_lock_latency.txt", [bpftrace_path, "-e", bpf_prog], timeout=config.BPFTRACE_DURATION_SEC + 5)
