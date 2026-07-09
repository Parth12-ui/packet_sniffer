# Packet Sniffer: A Terminal Network Capture Utility

Packet Sniffer is a high-performance, lightweight, terminal-based network packet sniffer written in C and powered by the libpcap engine. Built as a custom alternative to bulky graphical sniffers, Packet Sniffer provides a granular, layer-by-layer dissection of live network traffic, real-time protocol filtering, and a dedicated in-memory forensics session analyzer directly in your shell.

Developed for Mini Project 2 (Operating Systems and Networks), Packet Sniffer represents a robust, production-grade network capture utility featuring zero external runtime dependencies beyond standard network libraries and libpcap.

---

## Architectural Workflow

The flow diagram below demonstrates how the Packet Sniffer captures, stores, parses, and analyzes network traffic:

```mermaid
flowchart TD
    A["Network Interface (NIC)"] -->|Raw Frame Stream| B["libpcap Engine"]
    B -->|pcap_open_live| C["Capture Loop (pcap_dispatch)"]
    C -->|Signal Interrupt via Ctrl-C| Menu["Main Menu Interface"]
    C -->|Callback via p_handler| D["Parser & Storage Dispatcher"]
    D -->|Buffer Packet| E[("In-Memory Session Storage (MAX: 10k Packets)")]
    D -->|Deep Parse| L2["Layer 2 Parser (Ethernet Header)"]
    
    L2 -->|EtherType: IPv4| L3_IP4["Layer 3 Parser (IPv4)"]
    L2 -->|EtherType: IPv6| L3_IP6["Layer 3 Parser (IPv6)"]
    L2 -->|EtherType: ARP| L3_ARP["Layer 3 Parser (ARP)"]
    L2 -->|EtherType: Unknown| L3_UNK["Layer 3 Unknown Handler"]
    
    L3_IP4 -->|Protocol: TCP| L4_TCP["Layer 4 Parser (TCP)"]
    L3_IP4 -->|Protocol: UDP| L4_UDP["Layer 4 Parser (UDP)"]
    L3_IP6 -->|Next Header: TCP| L4_TCP
    L3_IP6 -->|Next Header: UDP| L4_UDP
    
    L4_TCP -->|Port Matching| L7["Layer 7 Parser (HTTP / HTTPS / DNS)"]
    L4_UDP -->|Port Matching| L7
    
    L7 -->|Hexadecimal & ASCII Dump| F["Console Output (Live Feed)"]
    
    E -.->|Selection by ID| Inspect["Forensics Lab (Inspect Last Session)"]
    Inspect -->|p_indepth| View["Detailed Diagnostic Output & Full Frame Hex Dump"]
```

---

## Core Features

### 1. Automated Device Discovery & Selection
Upon startup, the Packet Sniffer scans the host machine's network stack to discover all available active interfaces using pcap_findalldevs(). It presents them in a formatted list showing the interface name and system description (such as Loopback, Wi-Fi, Ethernet, Bluetooth, or virtual docker interfaces) and allows safe numbered selection.

### 2. Layer-by-Layer Protocol Dissection
The Packet Sniffer decodes packet headers at every boundary of the OSI network model:
*   **Layer 2 (Data Link - Ethernet)**: Extracts Destination & Source MAC Addresses and identifies EtherType payload wrappers (IPv4, IPv6, ARP, or Unknown).
*   **Layer 3 (Network - IPv4 / IPv6 / ARP)**:
    *   *IPv4*: Extracts Source & Destination IPs, Protocol (TCP/UDP/etc.), TTL, unique Packet ID, Total/Header Length, and flags (Reserved, DF, MF).
    *   *IPv6*: Extracts Source & Destination IPv6 addresses, Next Header, Hop Limit, Traffic Class, Flow Label, and Payload Length. It supports walking IPv6 extension headers (Routing, Fragment, Destination, Hop-by-Hop).
    *   *ARP*: Decodes specific operational codes (Request, Reply, RARP, InARP), Hardware/Protocol types/lengths, and lists Sender & Target MAC/IP addresses.
*   **Layer 4 (Transport - TCP / UDP)**:
    *   *TCP*: Decodes Source & Destination Ports, Sequence & Acknowledgment Numbers, TCP Window Size, Checksum, Header Length, and decodes Flags (SYN, ACK, FIN, RST, PUSH, URG).
    *   *UDP*: Decodes Source & Destination Ports, Length, and UDP Checksum.
*   **Layer 7 (Application & Payload Hex-Dump)**: Identifies application protocols (such as DNS on Port 53, HTTP on Port 80, HTTPS/TLS on Port 443) and outputs a clean, combined hexadecimal and ASCII format hex-dump of the first 64 bytes of the payload.

### 3. Precision Filtering
Real-time filtering of the captured stream allows isolation of specific network events. The Packet Sniffer compiles and applies Berkley Packet Filters (BPF) natively on the network interface:
*   **HTTP** (Port 80)
*   **HTTPS** (Port 443)
*   **DNS** (Port 53)
*   **ARP** (Address Resolution Protocol)
*   **TCP** (Transmission Control Protocol)
*   **UDP** (User Datagram Protocol)

### 4. In-Memory Forensics Lab
*   **Session Storage**: Captures and caches up to 10,000 packets in-memory during a sniffing run.
*   **Post-Mortem Analysis**: Use the Inspect Last Session menu to list a summary of all captured packets (ID, Length, EtherType, Source/Destination IPs, and Ports) and choose an individual Packet ID to run a thorough diagnostic, displaying its complete frame hex dump alongside its full dissected layer fields.
*   **Leak Prevention**: Auto-cleans the heap before initiating a new sniffing session, protecting your host machine against memory bloat.

### 5. Graceful Signals & Terminal Handling
*   `Ctrl+C` (SIGINT): Safely interrupts the active capture loop and drops the user back into the interactive menu without crashing the process or wiping in-memory session packet arrays.
*   `Ctrl+D` (EOF): Cleanly shuts down the sniffer from any submenu, releasing all allocated buffers and handles, restoring standard terminal options.
*   **Non-Blocking Inputs**: Uses select() over standard input to handle non-blocking keyboard interrupts.

---

## Repository Structure

```directory
packet_sniffer/
├── main/                       # Main source directory
│   ├── include/                # Header files directory
│   │   ├── functions.h         # Headers for main network parsers & control flows
│   │   ├── handler_filter.h    # Headers for BPF filtering and pcap callbacks
│   │   └── store_packets.h     # Headers for packet data structs and diagnostics
│   ├── Makefile                # Build automation tool configuration
│   ├── README.md               # Quick local reference documentation
│   ├── functions.c             # Implementation of packet parsers and UI loops
│   ├── handler_filter.c        # Implementation of libpcap dispatch callback
│   ├── main.c                  # Program entry point and signal setup
│   └── store_packets.c         # Session buffer database and Forensics Lab
└── prob_statement.pdf          # Academic specification details
```

---

## Build & Installation

### Prerequisites
Ensure you have a C compiler (gcc or clang) and the development headers for libpcap installed:

*   **macOS**: Pre-installed. You can update or link it via Homebrew if needed:
    ```bash
    brew install libpcap
    ```
*   **Ubuntu/Debian**:
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libpcap-dev
    ```

### Compilation
1. Navigate to the source folder:
   ```bash
   cd main
   ```
2. Build the project using the optimized Makefile:
   ```bash
   make
   ```
   This compiles all dependencies and produces the c_shark executable.

3. To clean temporary object files and binary outputs:
   ```bash
   make clean
   ```

---

## Usage Guide

Since packet capture requires raw access to the network socket interface, you must execute the sniffer with superuser privileges (sudo).

### 1. Launch Packet Sniffer
Run the compiled executable with root privileges:
```bash
sudo ./c_shark
```

### 2. Basic Capture Workflow
1.  **Select Interface**: The program will display a numbered list of all discovered network interfaces. Input the corresponding number (such as 3 for localhost/lo or the ID for your Wi-Fi interface).
2.  **Main Menu**:
    *   Select 1 to capture all flowing network frames.
    *   Select 2 to enter the filtering menu (options: HTTP, HTTPS, DNS, ARP, TCP, UDP) and begin filtered sniffing.
3.  **Live Sniffing Feed**: The screen will print packet details in real-time, detailing Layer 2, 3, and 4 headers, and showing payload hex-dumps.
4.  **Pause Capture**: Press Ctrl+C at any time to halt the stream. The program will close the capture handle and cleanly return to the Main Menu.
5.  **Forensics Analysis**:
    *   Select 3 from the Main Menu to view a table of all packets captured in the last run.
    *   Enter any Packet ID to view its comprehensive header values and full frame hex-dump.
    *   Enter 0 to return to the Main Menu.
6.  **Exit Program**: Press Ctrl+D or choose the exit option (4 in the main menu) to close handles, free memory, and exit.

---

## Rules of Engagement

> [!IMPORTANT]
> **Observation-Only Tool**  
> Packet Sniffer is strictly a passive listener/sniffer. It is designed to observe and analyze network streams. It does not craft, inject, or modify network frames. Please use this utility responsibly and only on networks that you own or have explicit authorization to monitor.

---

## Credits
This project was implemented as part of the Operating Systems and Networks coursework (Mini Project 2). 

*   **Developer**: Parth
*   **Academic Supervision**: OSN Course Staff
*   **Reference Materials**:
    *   devdungeon.com - libpcap C programming guide
    *   elf11.github.io - Network programming in C
    *   StackOverflow: Keyboard reading with select() in C
