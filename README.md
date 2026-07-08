# FluxGuard

**Autonomous Kernel-Level DDoS Mitigation via eBPF/XDP**

FluxGuard is a kernel-level DDoS mitigation system that identifies and drops attack traffic before the Linux kernel even allocates memory for the packet. It leverages eBPF (Extended Berkeley Packet Filter) programs running at the XDP (eXpress Data Path) hook—the earliest possible point in the receive path—to count, timestamp, and classify traffic at wire speed.

A Python-based control plane daemon periodically polls the kernel's BPF maps (every ~200ms) and makes intelligent, stateful blocking decisions using two statistical techniques.

## Features & Detection Logic

FluxGuard uses two primary research novelties for detecting attacks:

1. **Timing Dispersion (Primary)**: Measures the variance of inter-packet arrival times using `bpf_ktime_get_ns()` inside the kernel. Unlike commercial products that perform timing analysis at the application layer with significant latency, FluxGuard performs this per-packet inside the kernel data path at nanosecond precision.
   - *Mechanical bots* generate traffic with highly regular intervals (Coefficient of Variation ≈ 0).
   - *Legitimate humans/applications* generate irregular timing (Coefficient of Variation >> 0).

2. **Handshake Completion Rate (Supporting)**: Counts SYN vs. ACK packets per IP address. Bots often flood SYN packets without ever completing the TCP handshake (never sending ACKs).
   - FluxGuard detects and blocks these by measuring connection lifecycle intent in the kernel before the server is even involved.

## Repository Structure

- `files/fluxguard_kern.c`: The eBPF/XDP kernel program (C). Fast data-plane packet counting and timing.
- `files/fluxguard_brain.py`: The Python control plane daemon. Polls BPF maps and enforces blacklists.
- `files/setup.sh`: Full installation, compilation, and network topology setup script.
- `files/reset.sh`: Teardown script to reset the network namespace topology between demos.
- `files/demo_guide.md`: Comprehensive walkthrough and demo guide.

## Prerequisites

FluxGuard requires a Linux environment (tested on Ubuntu 22.04 / 24.04). The `setup.sh` script handles the installation of all necessary dependencies, which include:
- `clang`, `llvm`, `libelf-dev`, `libpcap-dev`, `build-essential`
- `linux-tools`, `linux-headers`
- `iproute2`, `python3`, `hping3`, `tcpdump`, `curl`, `jq`, `net-tools`

## Setup and Installation

A completely automated setup script is provided. It installs dependencies, sets up a simulated 3-namespace network topology (`client`, `fluxguard`, `backend`), compiles the eBPF program, and attaches it.

```bash
cd files
chmod +x setup.sh reset.sh
./setup.sh
```

## Running FluxGuard

1. **Start the backend server:**
   ```bash
   sudo ip netns exec backend python3 -m http.server 80
   ```

2. **Start the FluxGuard control plane (Brain):**
   ```bash
   sudo python3 fluxguard_brain.py --verbose
   ```
   *This starts polling the BPF maps and printing status updates to the terminal.*

3. **Simulate legitimate traffic:**
   ```bash
   # From a new terminal
   for i in $(seq 1 20); do
       sudo ip netns exec client curl -s -o /dev/null -w "HTTP %{http_code}\n" http://10.0.2.2
       sleep 0.$RANDOM
   done
   ```
   *FluxGuard will observe the traffic, but since the timing dispersion is high (irregular), it will not block it.*

4. **Simulate a SYN Flood attack:**
   ```bash
   # Use hping3 to send pure SYNs at 2000 pps
   sudo ip netns exec client hping3 -S -p 80 -i u500 10.0.2.2
   ```
   *Within ~2 seconds, FluxGuard's Brain will detect the mechanical regularity (CV near zero) and issue an XDP_DROP block for the client's IP.*

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FLUXGUARD SYSTEM                                   │
│                                                                             │
│  ┌──────────────┐      ┌──────────────────────────────────┐    ┌─────────┐ │
│  │ netns:client │      │       netns:fluxguard             │    │netns:   │ │
│  │              │      │                                   │    │backend  │ │
│  │  10.0.1.1   ─┼──────┼─► veth-fg-in                    │    │         │ │
│  │              │      │   ┌──────────────────────┐        │    │10.0.2.2 │ │
│  │  hping3      │      │   │  XDP HOOK (kernel)   │        │    │         │ │
│  │  curl        │      │   │  ┌────────────────┐  │        │────┼─► HTTP  │ │
│  │              │      │   │  │ blacklist_map  │  │        │    │  server │ │
│  └──────────────┘      │   │  │ meter_map      │  │        │    └─────────┘ │
│                        │   │  │ timing_map ★  │  │        │                │
│                        │   │  │ syn_map    ★  │  │        │                │
│                        │   │  │ ack_map    ★  │  │        │                │
│                        │   │  └────────────────┘  │        │                │
│                        │   └──────────────────────┘        │                │
│                        │                                   │                │
│                        │   ┌──────────────────────────┐   │                │
│                        │   │  PYTHON BRAIN (userspace) │   │                │
│                        │   │  • Polls maps @ 200ms     │   │                │
│                        │   │  • Computes CV (Novelty A)│   │                │
│                        │   │  • Computes ACK/SYN ratio │   │                │
│                        │   │  • Writes blacklist_map   │   │                │
│                        │   │  • Auto-unblocks @ 30s    │   │                │
│                        │   └──────────────────────────┘   │                │
│                        └──────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────────────────────┘
                          ★ = Novel research contribution
```

## How XDP_DROP Works

```
Normal path (iptables / application firewall):
  NIC → DMA → sk_buff allocation → netif_receive_skb() →
  netfilter → TCP/IP stack → socket → application
  ↑ Attack packets consume CPU at EVERY step

FluxGuard XDP path:
  NIC → DMA → [XDP HOOK] → XDP_DROP ← packet freed HERE
                ↑
        Before sk_buff ever allocated
        Before any protocol handler runs
        Before any interrupt handler completes
```

---

## BPF Maps Reference

| Map | Key | Value | Max Entries | Written By | Read By |
|-----|-----|-------|------------|-----------|---------|
| `blacklist_map` | `__u32` src IP | `__u32` (any != 0 = blocked) | 10,240 | Python brain | XDP |
| `meter_map` | `__u32` src IP | `__u32` total packet count | 65,536 | XDP | Python |
| `timing_map` | `__u32` src IP | `struct {u64 last_seen_ns; u64 last_gap_ns}` | 65,536 | XDP | Python |
| `syn_map` | `__u32` src IP | `__u32` pure SYN count | 65,536 | XDP | Python |
| `ack_map` | `__u32` src IP | `__u32` pure ACK count | 65,536 | XDP | Python |

---

## Log Format

Events are logged in **JSON Lines** format (one JSON object per line) for easy processing with `jq`, `pandas`, or any log aggregator:

```bash
# View all BLOCK events
jq 'select(.event == "BLOCK")' fluxguard.log

# Show CV values (near 0 = bot, high = legitimate)
jq 'select(.event == "BLOCK") | {ip, reason, pps, cv, completion_rate}' fluxguard.log

# Timeline of blocks and unblocks
jq -r 'select(.event=="BLOCK" or .event=="UNBLOCK") |
    "\(.ts)  \(.event)  \(.ip)  \(.reason // .blocked_for)"' fluxguard.log
```

**Sample log output:**
```json
{"ts": "2025-09-01T10:23:45Z", "event": "BLOCK", "ip": "10.0.1.1",
 "reason": "timing_dispersion", "pps": 1987.4, "cv": 0.0231,
 "completion_rate": 0.0, "syn_count": 398, "ack_count": 0, "gap_samples": 16}

{"ts": "2025-09-01T10:24:15Z", "event": "UNBLOCK", "ip": "10.0.1.1",
 "blocked_for": 30.1, "original_reason": "timing_dispersion"}
```

---

## Technical Stack

```
Language (Kernel)  : C (BPF subset, compiled with Clang -target bpf)
Language (Control) : Python 3.8+
Kernel interface   : eBPF / XDP via xdpgeneric mode
Map I/O            : bpftool --json subprocess bridge
Network simulation : Linux network namespaces + veth pairs
Attack simulation  : hping3
Traffic capture    : tcpdump
Testing            : pytest + unittest
CI                 : GitHub Actions
```

---

## Credits and Contributors

Designed and developed with ❤️ by **Devansh** and **Samarth**.
Built as part of an academic research project focused on high-performance networking and kernel-level security using eBPF/XDP.

---