#!/bin/bash
# ============================
# Tool: Linux-Sentinel
# Description: A forensic tool for detecting Defense Evasion techniques
#              by analyzing process memory, filesystem artifacts, and
#              volatile execution paths.
# Author: Hleb Haushyn aka cbrkrtek
# MIT License
# ===========================
set -euo pipefail

# ANSI color codes for readable console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Whitelist to exclude legitimate JIT-compilers and system tools from alerts
# to minimize false positives during scanning.
WHITELIST=("python" "node" "electron" "java" "qterminal" "blueman" "applet.py")

echo -e "${BLUE}[*] Starting Linux-Sentinel Forensic Scan...${NC}"

# Ensure the script is executed with root privileges to access /proc/[pid]/maps
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: Root privileges required for memory access.${NC}"
   exit 1
fi

# Inspects process memory maps to identify segments with RWX (Read-Write-Execute)
# permissions, which is a common indicator of shellcode injection (T1055).
check_mem_injection() {
    echo -e "${YELLOW}[*] Checking for RWX memory segments (Suspicious Injection)...${NC}"
    local count=0

    # Iterate through memory maps of all running processes
    for maps in /proc/[0-9]*/maps; do
        # Look for the 'rwxp' flag pattern in the memory map
        if grep -q "rwxp" "$maps" 2>/dev/null; then
            pid=$(echo "$maps" | cut -d'/' -f3)
            comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")

            # Cross-reference with the whitelist to filter out authorized JIT processes
            local skip=0
            for w in "${WHITELIST[@]}"; do
                if [[ "$comm" == *"$w"* ]]; then skip=1; break; fi
            done

            # If process is not whitelisted, flag it as a potential threat
            if [ $skip -eq 0 ]; then
                echo -e "${RED}[!] CRITICAL ALERT: Suspicious RWX segment in PID $pid ($comm)${NC}"
                count=$((count + 1))
            fi
        fi
    done
    [[ $count -eq 0 ]] && echo -e "${GREEN}[+] Memory integrity: Clean${NC}"
}

# Identifies processes running from files that have been deleted from the disk
# while still executing in memory (Indicator Removal - T1070.004).
check_deleted_bins() {
    echo -e "${YELLOW}[*] Checking for processes with deleted binaries...${NC}"
    local count=0
    for exe in /proc/[0-9]*/exe; do
        # Check if the symbolic link points to a file marked as (deleted)
        if readlink "$exe" 2>/dev/null | grep -q "(deleted)"; then
            pid=$(echo "$exe" | cut -d'/' -f3)
            echo -e "${RED}[!] ALERT: Process $pid (Path: $(readlink "$exe")) is running from a deleted binary!${NC}"
            count=$((count + 1))
        fi
    done
    [[ $count -eq 0 ]] && echo -e "${GREEN}[+] Binary integrity: Clean${NC}"
}

# Detects processes executing binaries stored in volatile or temporary directories,
# a common technique for hosting and executing malicious payloads (T1105 / T1036).
check_volatile_exec() {
    echo -e "${YELLOW}[*] Checking for execution from volatile paths...${NC}"
    local found=0
    for exe in /proc/[0-9]*/exe; do
        path=$(readlink "$exe" 2>/dev/null || echo "")
        # Flag if the executable path resides in commonly abused temporary locations
        if [[ "$path" =~ ^/(tmp|dev/shm|var/tmp)/ ]]; then
            pid=$(echo "$exe" | cut -d'/' -f3)
            echo -e "${RED}[!] ALERT: Process $pid running from volatile path: $path${NC}"
            found=1
        fi
    done
    [[ $found -eq 0 ]] && echo -e "${GREEN}[+] Volatile storage: Clean${NC}"
}

# --- EXECUTION ---

# Run the suite of forensic checks
check_mem_injection
check_deleted_bins
check_volatile_exec

echo -e "\n${BLUE}[*] Analysis complete. Security posture check finished.${NC}"
