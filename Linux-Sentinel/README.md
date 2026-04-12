# 🛡️ Linux-Sentinel.Advanced Kernel-Level Forensic Triage & Threat Hunting Tool
![Security: Forensic](https://img.shields.io/badge/Security-Forensic-blueviolet?style=for-the-badge)
![Kernel: /proc](https://img.shields.io/badge/Kernel-/proc-blue?style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 📖 Overview
**Linux-Sentinel** is a specialized tool designed for rapid forensic triage in compromised Linux environments. Unlike standard monitoring utilities (e.g., `ps`, `lsof`, `top`) that can be subverted by user-land rootkits or library hijacking (e.g., `LD_PRELOAD`), **Linux-Sentinel** interacts directly with the **Kernel Process Filesystem (`/proc`)**. 

It provides an unbiased "source of truth," enabling Security Operations Centers (SOC) and Incident Response (IR) teams to detect sophisticated threats that attempt to evade traditional detection mechanisms.



---

## 🏛️ Architecture & Core Philosophy

### 1. Zero-Dependency Execution
In a compromised environment, you cannot trust installed interpreters (Python, Ruby) or system binary integrity. **Linux-Sentinel** is written in **pure POSIX-compliant Bash**. This ensures the tool functions in minimal environments, recovery shells, or when executed from a trusted read-only forensic mount.

### 2. Direct-to-Kernel Interaction
By parsing `/proc/[pid]/maps` and `/proc/[pid]/exe`, we bypass the API-level filtering used by malware. This provides visibility into:
* **Memory-only malicious payloads** (no disk footprint).
* **Binary Masquerading** (legitimate binaries renamed to look like system tasks).
* **Indicator Removal** (execution from deleted inodes).

---

## 🔍 Capability Mapping (MITRE ATT&CK®)

| Module | Technique | Detection Logic |
| :--- | :--- | :--- |
| **RWX Segment Audit** | **T1055: Process Injection** | Scans for memory regions marked with simultaneous Read-Write-Execute permissions. |
| **Ghost Binary Check** | **T1070.004: Indicator Removal** | Detects processes running from files unlinked (deleted) from the filesystem. |
| **Volatile Path Scan** | **T1036: Masquerading** | Flags execution originating from high-risk paths like `/tmp`, `/dev/shm`, or `/var/tmp`. |

---

## 🧪 Forensic Evidence (Proof of Concept)

### Scenario A: Detecting "Ghost" Processes (T1070.004)
Adversaries often execute a payload and delete the file to hide from standard scanners. **Linux-Sentinel** detects these orphaned processes via `/proc/[pid]/exe`.

![Ghost Detection](https://github.com/cbrkrtek/Threat-Ops-Automation/blob/main/Linux-Sentinel/Images/scene1.PNG)
*Figure 1: Identification of a process (PID 42049) running from a deleted binary.*

### Scenario B: Volatile Path Execution (T1036)
Detection of a renamed interpreter attempting to masquerade within `/tmp`. The tool validates execution paths against known-safe directory structures.

![Volatile Path](https://github.com/cbrkrtek/Threat-Ops-Automation/blob/main/Linux-Sentinel/Images/scene2.PNG)
*Figure 2: Identification of unauthorized execution from volatile memory storage.*

### Scenario C: Advanced Memory Triage (T1055)
Deep analysis of process memory maps. The tool employs a whitelist to filter legitimate JIT-compilation (e.g., Python, Node.js), focusing operator attention only on suspicious RWX memory segments.

![Full Analysis](https://github.com/cbrkrtek/Threat-Ops-Automation/blob/main/Linux-Sentinel/Images/scene3.PNG)
*Figure 3: Comprehensive triage report showing a successful memory state validation.*

---

## 🚀 Installation & Usage

### Requirements
* **Root privileges** (mandatory for reading `/proc/[pid]/maps`).
* Linux kernel 3.10 or higher.

### Quick Start
```bash
# Download a script from repository and grant execution permissions
chmod +x Linux-Sentinel.sh

# Run the forensic audit
sudo bash ./Linux-Sentinel.sh
```
## 📈Future roadmap
- **Network Entropy Check:** correlating `/proc/net/tcp` with PIDs to detect active C2 connections.
- **Environment Variable Auditing:** scanning `/proc/[pid]/environ` for `LD_PRELOAD` connections
- **Kernel Module Integrity:** Basic cross-referencing of loaded modules versus /lib/modules.
