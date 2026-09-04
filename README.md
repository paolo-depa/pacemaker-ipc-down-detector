# Pacemaker Push-Based Diagnostic Suite (v4.0)

An advanced, event-driven diagnostic sidecar designed specifically for production **SAP HANA** and high-availability database cluster deployments. 

This utility runs as a highly optimized, zero-dependency Python 3 daemon. Leveraging an object-oriented architecture and single-pass `/proc` filesystem scanning, it minimizes CPU and memory footprint even during intense system starvation. The moment `pacemakerd` logs that a sub-daemon has stalled on **try 1** (indicating an IPC unresponsiveness event), this daemon awakens to capture the execution, system, and environment parameters within the critical **20-second Golden Window** before `pacemakerd` terminates the stalled sub-daemon with a terminal `SIGKILL` (signal 9) [^1][^6][^21].

## ⚙️ Architecture and Toggles
By default, the tool is heavily locked down to use **Pure Python and ProcFS**. This prevents the overhead of spawning heavyweight child processes (`ls`, `ps`, `ipcs`) during system starvation.

Administrators can strictly toggle specific tasks via CLI arguments to run external tooling explicitly:
*   `--enable-cluster-state`: Uses `corosync-cfgtool`, `ss`, and `cibadmin`.
*   `--enable-nss-latency`: Uses `getent`.
*   `--enable-bpf-trace`: Uses `bpftrace`.
*   `--enable-crm-report`: Uses `crm_report` (spawned asynchronously).
*   `--out-dir`: Redirect captures to a customized logging directory (default: `/var/log/pacemaker`).

---

## 📂 Diagnostic Output Structure

When an IPC stall is detected, a dedicated, timestamped folder is created under `/var/log/pacemaker/push_diag_[daemon]_[timestamp]/` containing categorized diagnostic evidence [^21]:

### 1. `process_trace/` (Process Traces and Thread Stalls)
*   **`user_callstack.txt`**: Captures user-space call-stack parameters using `gstack` or `gdb` with a strict timeout [^21][^33]. Reveals whether the daemon is stuck in a user-space deadlock or GSource main loop block [^7].
*   **`kernel_callstack.txt`**: Direct dump of `/proc/[PID]/stack` [^33]. Crucial for investigating processes trapped in **uninterruptible sleep (D state)** [^5][^33], showing the exact kernel function (such as `rwsem_down` or page table traversals) holding up the thread [^33].
*   **`proc_status.txt`, `proc_limits.txt`, `proc_environ.txt`**: Gathers `/proc` filesystem tables to analyze virtual memory allocation, process environment variables, and system limits [^6][^33].
*   **`open_file_descriptors.txt`**: Complete output of `lsof -p [PID]` to audit for **`EMFILE` (Too many open files - Error 24)** conditions [^6][^33].

### 2. `security_and_monitoring/` (Endpoint Agent Inspection)
*   **`agent_audit.txt`**: Audits and snapshots active resource-intensive security, compliance, and monitoring services running on the machine, including:
    *   **Trend Micro Deep Security (`ds_agent`)** [^33]
    *   **CrowdStrike Falcon Sensor (`falcon-sensor`)** [^33]
    *   **McAfee / Trellix Endpoint Security (`mfetpd`, `mfeesp`)** [^33]
    *   **Qualys, ClamAV (`clamd`), and Auditd** [^33]
    *(Note: The kernel execution stacks and wait channels of all active third-party agents are appended directly into `active_agents.txt` to streamline the review of locked semaphores [^33].)*

### 3. `sap_hana/` (SAP HANA Landscape & Semaphore Audit)
*   **`hana_process_limits.txt`**: Gathers a snapshot of active SAP database components (`hdbnameserver`, `hdbindexserver`, `hdbrsutil`), their memory allocation stats, and their kernel execution stack to identify `mmap_sem` locking [^32].

### 4. `directory_services/` (SSSD & PAM Stalls)
*   **`lookup_latency.txt`**: Tests Name Service Switch (NSS) lookup latency by querying the `hacluster`, `postgres`, and `root` users with a strict **2-second timeout** [^28][^34]. Stalls indicate network-level LDAP, SSSD, or Active Directory outages that freeze local monitor script authentications [^28][^34].
*   **`sssd.conf`, `nsswitch.conf`**: Config captures to audit local identity lookup priorities [^28][^35].

### 5. `ipc/` (POSIX Shared Memory Validation)
*   **`dev_shm_qb_segments.txt`**: Validates file permissions and ownership groups on active `libqb` shared memory files under `/dev/shm/qb-*` [^2]. Checks if files are properly owned by `hacluster:haclient` [^2][^12].
*   **`posix_shm.txt`, `posix_semaphores.txt`, `posix_summary.txt`**: Runs POSIX IPC audits via `ipcs` to check for active system segment leaks or semaphore allocation blocks [^7].

### 6. `cluster/` (Corosync & CIB State)
*   **`corosync_cfgtool.txt`, `corosync_cmapctl.txt`**: Captures active totem membership rings, consensus configuration states, and network link latency statistics [^9][^39].
*   **`udp_sockets.txt`, `all_sockets.txt`**: Monitors socket queues to audit for packet fragmentation or dropped buffers on the UDP clustering ports (e.g., 5405) [^38].
*   **`local_cib.xml`**: Runs `cibadmin -Ql -l` to capture a raw local configuration snapshot, checking for configuration bloat [^11][^21].

### 7. `sbd/` (STONITH Block Device Health)
*   **`sbd_config.txt`**: Grabs `/etc/sysconfig/sbd` settings to verify watchdog timeouts, `SBD_DELAY_START`, and cluster shutdown properties [^41][^43].
*   **`watchdog_info.txt`**: Checks if the hardware watchdog (`/dev/watchdog`) is responsive [^43].

### 8. `system/` (Cgroup and PSI Starvation metrics)
*   **`cgroup_cpu_stat.txt`**: Logs systemd cgroup CPU statistics (`cpu.stat`) to identify if container boundaries or CFS quotas have throttled the Pacemaker service [^36][^37].
*   **`pressure_io.txt`, `pressure_cpu.txt`, `pressure_memory.txt`**: Captures Linux Pressure Stall Information (PSI) to measure host resource starvation preceding the freeze [^5][^33].
*   **`ps_auxf.txt`**: Captures a visual hierarchical snapshot of all executing system tasks [^31][^33].

### 9. `bpf/` (eBPF Kernel-Level Tracing)
*   **`bpf_lock_latency.txt`**: High-resolution histogram of futex/lock wait latencies and slow system calls in kernel-space, captured using `bpftrace`.
*   **`bpftrace_missing.txt`**: Created if bpftrace is enabled but the executable is not found on the host.

### 10. Archive
*   **`crm_report_diagnostics.tar.bz2`**: Broad cluster-wide context perspective generated by spawning `crm_report` spanning the last 5 minutes.

---

## 🔬 Suspected Root Causes of Pacemaker IPC Timeouts

Pacemaker sub-daemons (`pacemaker-controld`, `pacemaker-execd`, etc.) use the high-performance **`libqb` shared-memory loopback** architecture under `/dev/shm` [^2]. An IPC timeout indicates that a sub-daemon's main event loop was completely blocked and unable to process the loopback pings sent by the parent supervisor (`pacemakerd`) [^1][^6]. 

Our field studies and source analyses isolate the following primary failure vectors:

### 1. Kernel Semaphore Stalls (`mmap_sem` Contention)
*   **The Scenario**: This is the **most common trigger** in large-scale **SAP HANA** deployments running third-party security agents (like Trend Micro `ds_agent`, Trellix `mfetpd`) or active monitoring utilities (like `atop -R`) [^33].
*   **The Mechanism**: For a massive memory process such as SAP HANA's index server (`hdbindexserver` [^32]), reading its virtual memory maps via `/proc/<pid>/smaps` or `/proc/<pid>/smaps_rollup` requires the kernel to traverse millions of page table entries [^33]. To protect this operation, the kernel must acquire a read-lock or write-lock on the process's **`mmap_sem`** (virtual memory mapping semaphore) [^33].
*   **The Failure**: A single scan on a multi-terabyte address space can hold this lock for **30 to 60 seconds** [^33]. While the lock is held, any other thread attempting system calls like `mmap`, `brk`, or `get_mempolicy` is forced to freeze in **uninterruptible sleep (D state)** [^33]. If a Pacemaker sub-daemon (such as `pacemaker-execd` running a monitor check) executes one of these system calls, it blocks, misses its loopback ping window, and triggers node self-fencing [^1][^5][^33].
*   **Post-Mortem Proof**:
    *   System logs print: `pacemaker-execd: crit: process (PID xxx) will not die!` [^5][^20] followed by `pacemaker-controld is unresponsive to ipc after 5 tries` [^21].
    *   The sidecar's captured `kernel_callstack.txt` of the stalled sub-daemon reveals a stack blocked inside `down_read` or `down_write` targeting the `mmap_sem` semaphore [^33].

### 2. Synchronous Metadata Deadlocks (Pacemaker < 2.1.5)
*   **The Scenario**: A legacy architecture deadlock occurring during cluster state transitions or rolling upgrades [^21].
*   **The Mechanism**: Before version 2.1.5, metadata queries requested by Pacemaker were executed **synchronously** inside the main event loop of `pacemaker-controld` [^21]. If a standard or custom resource agent (such as an OCF script) invoked the command `crm_node -l` during a metadata call, the command attempted to establish a client IPC connection back to `pacemaker-controld` [^21].
*   **The Failure**: Because `pacemaker-controld` was blocked waiting for the resource agent's metadata call to complete, it could not accept the incoming connection from `crm_node -l` [^21]. This created a direct, synchronous deadlock that lasted until the metadata execution timed out (typically 30 seconds) [^21]. During this block, the daemon was completely deaf to `pacemakerd` pings, leading to unexpected fencing [^21].
*   **Post-Mortem Proof**:
    *   The logs show a `probe` or `metadata` operation initiated, followed by a 30-second delay: `wait_for_sync_result: Dummy_meta-data_0 timed out after 30000ms` [^21].
    *   The user-space call-stack shows `pacemaker-controld` blocked in a synchronous wait state [^21].

### 3. User/Group Authentication Lookup Stalls (SSSD, PAM, LDAP)
*   **The Scenario**: Database clustering environments (like PostgreSQL or SAP HANA) where cluster operations must run under a non-root system administrative account (e.g., `postgres` or `<sid>adm`) [^28][^34].
*   **The Mechanism**: To execute resource operations, the local executor (`pacemaker-execd`) runs utilities like `su` or `runuser` to launch OCF scripts as the administrative user [^28][^34]. If the host's Name Service Switch (`/etc/nsswitch.conf`) is configured to query an external LDAP directory or SSSD server before checking local files, local lookup commands will query the network first [^28][^34][^35].
*   **The Failure**: If the network is interrupted or the LDAP server experiences lag, the local lookup calls hang on network sockets until they hit high socket timeouts [^28][^34][^35]. This freezes the Pacemaker execution thread [^28][^34].
*   **Post-Mortem Proof**:
    *   System secure logs align with LDAP or SSSD timeout entries: `nslcd: ldap_result() timed out` [^28][^34].
    *   The sidecar's `lookup_latency.txt` shows the NSS lookup test exceeding the 2-second threshold [^28][^34].

### 4. IPC Buffer Exhaustion (`PCMK_ipc_buffer`)
*   **The Scenario**: Observed in large, resource-heavy clusters (often with >200 primitive resources or multi-node databases) [^11][^50].
*   **The Mechanism**: When configuration updates or state changes occur, Pacemaker serializes and compresses the entire CIB XML tree to transmit it to clients across the `libqb` shared memory rings [^2][^21].
*   **The Failure**: If the serialized XML size exceeds the configured IPC buffer size (defaulting to a restrictive limit of 51,200 bytes on older versions), the compression buffer allocation fails [^21]. Pacemaker cannot transmit the payload, causing client connections to time out and trigger cascading daemon restarts [^21].
*   **Post-Mortem Proof**:
    *   Syslogs record: `Compression of xxxxx bytes failed: output data will not fit into the buffer provided` [^21].
    *   Can be resolved by explicitly increasing `PCMK_ipc_buffer` up to `13396332` [^50] in `/etc/sysconfig/pacemaker`.

### 5. File Descriptor Exhaustion (`EMFILE`)
*   **The Scenario**: Starvation under high load or strict system limit boundaries [^6].
*   **The Mechanism**: As Pacemaker monitors dozens of resources, it frequently spawns helper processes and opens socket connection descriptors [^6].
*   **The Failure**: If systemd limits are not explicitly optimized, the daemon hits its file descriptor limit, preventing the allocation of new shared-memory ring segments under `/dev/shm/qb-*` for loopback client registrations [^2][^6].
*   **Post-Mortem Proof**:
    *   Syslogs print error code **`24`**: `qb_rb_open:REQUEST: Too many open files (24)` [^6].

### 6. Control Group (cgroup) CFS CPU Throttling
*   **The Scenario**: Cloud, virtualized (hypervisor), or containerized environments [^36].
*   **The Mechanism**: Under Completely Fair Scheduler (CFS) CPU bandwidth allocation quotas, system services are limited to specific runtime budgets per cycle [^36].
*   **The Failure**: If the hypervisor experiences host-level CPU overcommit, or if CPU resource pools are tightly capped, Pacemaker's systemd slice can be throttled [^36]. If the kernel suspends the Pacemaker thread for more than the loopback ping timeout, it triggers a false-positive unresponsiveness signal [^36][^37].
*   **Post-Mortem Proof**:
    *   The sidecar's `cgroup_cpu_stat.txt` reveals highly elevated metrics in `nr_throttled` or `throttled_time` inside Pacemaker's slice [^36][^37].

---

## ⚡ Deployment and Activation

To deploy the push-based sidecar daemon on your cluster nodes:

1.  **Build the Executable**:
    Compile the `src/` modules into a self-contained, high-performance binary:
    ```bash
    make build
    ```

2.  **Deploy the Files**:
    Place the binary on your nodes (e.g., in `/opt/pacemaker-diagnostics`):
    ```bash
    mkdir -p /opt/pacemaker-diagnostics/bin
    cp dist/pacemaker-push-diagnostics /opt/pacemaker-diagnostics/bin/
    chmod 700 /opt/pacemaker-diagnostics/bin/pacemaker-push-diagnostics
    chown -R root:root /opt/pacemaker-diagnostics
    ```

3.  **Register the Systemd Service**:
    Place `pacemaker-push-diagnostics.service` into systemd:
    ```bash
    cp systemd/pacemaker-push-diagnostics.service /etc/systemd/system/pacemaker-push-diagnostics.service
    systemctl daemon-reload
    systemctl enable --now pacemaker-push-diagnostics.service
    ```

3.  **Trace Status**:
    Confirm the sidecar is actively streaming the systemd journal logs:
    ```bash
    tail -f /var/log/pacemaker/push_diagnostics.log
    ```

---

## 🛡️ Antivirus Tuning & Exclusion Matrix

To prevent third-party security engines from triggering `mmap_sem` memory locks, configure the following system exclusions across your security platforms (e.g., Trend Micro, CrowdStrike, Trellix) [^33]:

1.  **Exclude Process Memory Space Scanning**:
    Configure exclusions to prevent endpoint scanners from reading virtual address mapping fields of:
    *   The SAP HANA Nameserver (`hdbnameserver`) [^32]
    *   The SAP HANA Indexserver (`hdbindexserver`) [^32]
    *   The Pacemaker executor (`pacemaker-execd`) [^1][^6]
2.  **Path Scanning Exclusions**:
    Exclude the high-frequency UNIX shared memory directory from on-access scanning [^2]:
    *   `/dev/shm/qb-*` (Loopback communication rings) [^2]
    *   `/var/lib/pacemaker/cib/*` (CIB configuration files) [^21][^41]
3.  **Command Execution Exclusions**:
    Exclude real-time scanning of execution utilities utilized inside clustering monitor scripts [^28][^34]:
    *   `/usr/sbin/crm_node` [^21], `/usr/sbin/cibadmin` [^21]
    *   `/usr/sap/${SID}/SYS/global/hdb/custom/config/global.ini` [^142]


## 📚 References & Footnotes

[^1]: **HA for SAP HANA: pacemaker sub-daemon is unresponsive to IPC | SUSE Support** - [https://support.scc.suse.com/s/kb/HA-for-SAP-HANA-pacemaker-sub-daemon-is-unresponsive-to-IPC](https://support.scc.suse.com/s/kb/HA-for-SAP-HANA-pacemaker-sub-daemon-is-unresponsive-to-IPC)
[^2]: **Pacemaker vulnerability and v1.1.9 release - Ultrabug** - [https://ultrabug.fr/Tech%20Blog/2013/2013-03-13-pacemaker-vulnerability-and-v1-1-9-release/](https://ultrabug.fr/Tech%20Blog/2013/2013-03-13-pacemaker-vulnerability-and-v1-1-9-release/)
[^5]: **Resource's monitor failing and showing the message 'PID will not die' in a Pacemaker cluster | SUSE Support** - [https://support.scc.suse.com/s/kb/PID-will-not-die-in-a-Pacemaker-cluster](https://support.scc.suse.com/s/kb/PID-will-not-die-in-a-Pacemaker-cluster)
[^6]: **Pacemaker service exits after fatal error: 'error: couldn't open file /dev/shm' | Red Hat Customer Portal** - [https://access.redhat.com/solutions/7083594](https://access.redhat.com/solutions/7083594)
[^7]: **Releases · ClusterLabs/pacemaker - GitHub** - [https://github.com/ClusterLabs/pacemaker/releases](https://github.com/ClusterLabs/pacemaker/releases)
[^9]: **Pacemaker cluster with QNETD showing resources as 'stopped' with 'due to no quorum (blocked)' during a fail-over | SUSE Support** - [https://support.scc.suse.com/s/kb/Pacemaker-with-QNETD-showing-due-to-no-quorum-blocked](https://support.scc.suse.com/s/kb/Pacemaker-with-QNETD-showing-due-to-no-quorum-blocked)
[^11]: **Tuning pacemaker for large clusters - Ultrabug** - [https://ultrabug.fr/Tech%20Blog/2014/2014-01-10-tuning-pacemaker-for-large-clusters/](https://ultrabug.fr/Tech%20Blog/2014/2014-01-10-tuning-pacemaker-for-large-clusters/)
[^12]: **A node fails to join the cluster or start resources and the logs show 'notice: mcp_read_config: Configured corosync to accept connections from group 189: Library error (2)' in a RHEL 7 High Availability cluster - Red Hat Customer Portal** - [https://access.redhat.com/solutions/1405553](https://access.redhat.com/solutions/1405553)
[^20]: **2121852 – During a rolling upgrade, monitor operations are not being communicated between nodes as expected. - Red Hat Bugzilla** - [https://bugzilla.redhat.com/show_bug.cgi?id=2121852](https://bugzilla.redhat.com/show_bug.cgi?id=2121852)
[^21]: **pacemaker/include/crm/stonith-ng.h at main - GitHub** - [https://github.com/ClusterLabs/pacemaker/blob/main/include/crm/stonith-ng.h](https://github.com/ClusterLabs/pacemaker/blob/main/include/crm/stonith-ng.h)
[^28]: **Unexpected SAP HANA DB failover if Pacemaker sub-daemon is unresponsive to IPC | SUSE Support** - [https://support.scc.suse.com/s/kb/Unexpected-SAP-HANA-DB-failover-if-Pacemaker-sub-daemon-is-unresponsive-to-IPC](https://support.scc.suse.com/s/kb/Unexpected-SAP-HANA-DB-failover-if-Pacemaker-sub-daemon-is-unresponsive-to-IPC)
[^31]: **Troubleshoot Unexpected Node Reboots in Azure Linux SUSE Pacemaker Cluster - Microsoft Learn** - [https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/linux/troubleshoot-unexpected-node-reboots-pacemaker-suse](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/linux/troubleshoot-unexpected-node-reboots-pacemaker-suse)
[^32]: **Address space monitoring and HANA DB performance | SUSE Support** - [https://support.scc.suse.com/s/kb/Address-space-monitoring-and-HANA-DB-performance](https://support.scc.suse.com/s/kb/Address-space-monitoring-and-HANA-DB-performance)
[^33]: **PSQL cluster failed without promoting secondary to master · Issue #1321 · ClusterLabs/resource-agents - GitHub** - [https://github.com/ClusterLabs/resource-agents/issues/1321](https://github.com/ClusterLabs/resource-agents/issues/1321)
[^34]: **Postgres pacemaker cluster failure - [ClusterLabs] Fwd** - [https://lists.clusterlabs.org/pipermail/users/2019-April/025710.html](https://lists.clusterlabs.org/pipermail/users/2019-April/025710.html)
[^35]: **Alibaba Cloud Linux: Prevent application performance jitter caused by cgroups** - [https://www.alibabacloud.com/help/en/alinux/support/prevent-application-performance-jitter-caused-by-cgroups](https://www.alibabacloud.com/help/en/alinux/support/prevent-application-performance-jitter-caused-by-cgroups)
[^36]: **Kubernetes CPU Throttling: CFS Quotas and Latency Fixes - CloudOptimo** - [https://www.cloudoptimo.com/blog/kubernetes-cpu-throttling-cfs-quotas-and-latency-fixes/](https://www.cloudoptimo.com/blog/kubernetes-cpu-throttling-cfs-quotas-and-latency-fixes/)
[^37]: **Corosync states the token was lost despite of actually received packets according to tcpdump #389 - GitHub** - [https://github.com/corosync/corosync/issues/389](https://github.com/corosync/corosync/issues/389)
[^38]: **[ClusterLabs] Corosync node gets unique Ring ID** - [https://lists.clusterlabs.org/pipermail/users/2021-January/028340.html](https://lists.clusterlabs.org/pipermail/users/2021-January/028340.html)
[^39]: **corosync.conf - corosync executive configuration file - Ubuntu Manpages** - [https://manpages.ubuntu.com/manpages/questing/man5/corosync.conf.5.html](https://manpages.ubuntu.com/manpages/questing/man5/corosync.conf.5.html)
[^41]: **2166243 – Commands pcs stonith sbd enable|disable do not work properly when cluster is not running - Bugzilla** - [https://bugzilla.redhat.com/show_bug.cgi?id=2166243](https://bugzilla.redhat.com/show_bug.cgi?id=2166243)
[^43]: **How to safely change SBD timeout settings in a Pacemaker cluster running SAP HANA | SUSE Support** - [https://support.scc.suse.com/s/kb/How-to-safely-change-SBD-timeout-settings-in-a-Pacemaker-cluster-running-SAP-HANA](https://support.scc.suse.com/s/kb/How-to-safely-change-SBD-timeout-settings-in-a-Pacemaker-cluster-running-SAP-HANA)
[^50]: **Tuning pacemaker for large clusters - Ultrabug** - [https://ultrabug.fr/Tech%20Blog/2014/2014-01-10-tuning-pacemaker-for-large-clusters/](https://ultrabug.fr/Tech%20Blog/2014/2014-01-10-tuning-pacemaker-for-large-clusters/)
[^142]: **SAP Note 2684254 - SAP HANA DB: Recommended OS settings for SLES 15 / SLES for SAP applications 15** - [https://me.sap.com/notes/2684254](https://me.sap.com/notes/2684254)
