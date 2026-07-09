# Packet Sniffer: The Terminal Packet Sniffer

This directory contains the main source code, headers, and build configuration for Packet Sniffer, a terminal-only packet sniffer written in C and powered by libpcap.

> [!NOTE]  
> For the comprehensive project documentation, architecture diagrams, detailed feature explanations, and user guide, please refer to the main [README.md](../README.md) in the project root directory.

---

## Quick Start

### 1. Build the Executable
Compile all files and generate the executable:
```bash
make
```

### 2. Run the Sniffer
Run the program with root privileges (required for raw socket access):
```bash
sudo ./c_shark
```

### 3. Clean Build Artifacts
Remove compiled object files and binaries:
```bash
make clean
```

---

## Directory Structure

*   **[include/](include/)**: Header files declaring structures, functions, and global constants.
    *   `functions.h`: Packet parser routines, menu interfaces, and signal handlers.
    *   `handler_filter.h`: Packet dispatcher wrapper declaration.
    *   `store_packets.h`: Dynamic packet caching database structures.
*   **[main.c](main.c)**: Entry point.
*   **[functions.c](functions.c)**: Core packet parsing logic for Ethernet (L2), IPv4/IPv6/ARP (L3), TCP/UDP (L4), Application protocols (L7), signal handlers, and interactive flow.
*   **[handler_filter.c](handler_filter.c)**: libpcap dispatcher callback handler.
*   **[store_packets.c](store_packets.c)**: In-memory session logging database and diagnostics for the forensics lab.
*   **[Makefile](Makefile)**: Optimised compilation workflow.