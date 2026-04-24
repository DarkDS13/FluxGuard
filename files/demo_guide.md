# FluxGuard — Professor Demo Guide
**Autonomous Kernel-Level DDoS Mitigation via eBPF/XDP**
Samarth | University Viva Demonstration

---

## Project Summary (30-second pitch)

FluxGuard is a kernel-level DDoS mitigation system that drops attack traffic
**before the Linux kernel even allocates memory for the packet**. It uses eBPF
programs running at the XDP hook — the earliest possible point in the receive
path — to count, timestamp, and classify traffic at wire speed. A Python
daemon reads the kernel's BPF maps every 200ms and makes intelligent blocking
decisions using two novel statistical techniques.

**The two research novelties:**

| Feature | What It Does | Why It's Novel |
|---|---|---|
| **A: Timing Dispersion** (Primary) | Measures variance of inter-packet arrival times using `bpf_ktime_get_ns()` in the kernel | Cloudflare, AWS Shield do timing analysis at application layer with seconds of latency. We do it per-packet inside the kernel data path at nanosecond precision — not done by any commercial product at this layer |
| **B: Handshake Completion Rate** (Supporting) | Counts SYN vs ACK packets per IP; bots flood SYN and never send ACK | SYN cookies defend *against* SYN floods at server side. We *detect and block* by measuring connection lifecycle intent in the kernel, before the server is involved at all |

---

## File Structure

```
~/fluxguard/
├── fluxguard_kern.c      ← XDP kernel program (C, BPF)
├── fluxguard_kern.o      ← Compiled BPF object (after setup.sh)
├── fluxguard_brain.py    ← Python control plane daemon
├── fluxguard.log         ← JSON Lines event log (created at runtime)
├── setup.sh              ← Full install + compile + attach script
└── reset.sh              ← Between-demo reset script
```

---

## One-Time Setup

```bash
# On a fresh Ubuntu 22.04 / 24.04 VM (Multipass or VirtualBox):
cd ~/fluxguard
chmod +x setup.sh reset.sh
./setup.sh
```

`setup.sh` does everything: installs packages, builds the 3-namespace
topology, compiles `fluxguard_kern.c`, and attaches it to `veth-fg-in`.

**Verify setup succeeded:**
```bash
# Should show all 5 BPF maps: blacklist_map, meter_map, timing_map, syn_map, ack_map
sudo ip netns exec fluxguard bpftool map show

# Should show "xdp" attached to veth-fg-in
sudo ip netns exec fluxguard ip link show veth-fg-in
```

---

## Network Topology Diagram

```
  ┌───────────────┐         ┌─────────────────────────────────┐        ┌───────────────┐
  │  netns:client │         │        netns:fluxguard           │        │ netns:backend │
  │               │         │                                  │        │               │
  │  10.0.1.1     ├─────────┤ 10.0.1.2          10.0.2.1      ├────────┤ 10.0.2.2      │
  │  veth-client  │         │ veth-fg-in ◄──XDP  veth-fg-out  │        │ veth-backend  │
  │               │         │                                  │        │               │
  │  hping3       │         │ ┌─────────────────────────┐     │        │ python3       │
  │  curl         │         │ │ BPF Maps:               │     │        │ http.server   │
  └───────────────┘         │ │  blacklist_map (enforce) │     │        └───────────────┘
                            │ │  meter_map    (PPS)      │     │
                            │ │  timing_map   (Feature A)│     │
                            │ │  syn_map      (Feature B)│     │
                            │ │  ack_map      (Feature B)│     │
                            │ └─────────────────────────┘     │
                            │                                  │
                            │  fluxguard_brain.py              │
                            │  (polls maps, computes CV,       │
                            │   writes blacklist_map)          │
                            └──────────────────────────────────┘
```

All traffic from `client` to `backend` passes through `fluxguard`.
The XDP program runs on `veth-fg-in` (ingress from client side).

---

## Demo Script — Step by Step

> **Open 4 terminal windows** before starting the demo.
> All commands assume you are on the Ubuntu VM with `~/fluxguard` as your project directory.

---

### TERMINAL SETUP

**Terminal 1 — Backend web server** (start first, leave running)
```bash
sudo ip netns exec backend python3 -m http.server 80
```
Expected output: `Serving HTTP on 0.0.0.0 port 80 ...`

---

**Terminal 2 — FluxGuard brain** (start second, leave running)
```bash
sudo python3 ~/fluxguard/fluxguard_brain.py \
    --netns fluxguard \
    --pps-threshold 300 \
    --cv-threshold 0.15 \
    --min-gaps 6 \
    --gap-history 16 \
    --min-syns 20 \
    --completion-thresh 0.10 \
    --poll-interval 0.2 \
    --cooldown-sec 30 \
    --verbose
```

Expected startup output:
```
──────────────────────────────────────────────────────────────────────────
  FluxGuard Brain  |  2025-09-01T10:00:00+00:00
  Namespace         : fluxguard
  ── Feature A: Inter-Packet Timing Dispersion [PRIMARY NOVELTY]
  PPS threshold     : 300 pps
  CV threshold      : < 0.15  (below = mechanical bot)
  Gap samples needed: 6  |  history: 16
  ── Feature B: Handshake Completion Rate [SUPPORTING NOVELTY]
  Min SYNs before check : 20
  Completion threshold  : < 0.10  (below = SYN flood)
  ── Operational ───────────────────────────────────────────────────
  Poll interval : 0.2s  |  Cooldown: 30s
──────────────────────────────────────────────────────────────────────────

  Maps flushed. Monitoring active.
```

---

**Terminal 3 — Live attack observer** (leave running during attacks)
```bash
sudo ip netns exec backend tcpdump -i veth-backend -n 'tcp port 80'
```
This shows you exactly what traffic is reaching the backend.
During an attack, you will see it STOP when the block takes effect.

---

**Terminal 4 — Demo commands** (run each demo from here)

---

### DEMO 1 — Legitimate Traffic (Must NOT Be Blocked)

**What you say to the professor:**
> "This simulates a real user making HTTP requests with natural, irregular timing.
> The `sleep 0.$RANDOM` creates random delays between 0 and 999 milliseconds —
> exactly the kind of irregular inter-packet gap a human or real application produces.
> Watch Terminal 2: the brain should see this traffic but never issue a BLOCK."

**Run in Terminal 4:**
```bash
echo "=== DEMO 1: Legitimate curl loop with random delays ==="
for i in $(seq 1 20); do
    sudo ip netns exec client curl -s -o /dev/null \
        -w "Request $i: HTTP %{http_code}  time=%{time_total}s\n" \
        http://10.0.2.2
    sleep 0.$RANDOM
done
echo "=== Demo 1 complete: client was NOT blocked ==="
```

**Expected results:**
- Terminal 1 (backend server): Shows each GET request with HTTP 200
- Terminal 2 (brain): Shows `[TICK]` lines with `observed_ips=1 blocked_ips=0`
- Terminal 3 (tcpdump): Shows SYN, SYN-ACK, ACK packets (full handshakes)
- Terminal 4: All 20 requests return `HTTP 200`

**Point out to professor:**
- The brain sees the IP (10.0.1.1) but CV is high (irregular timing) → no block
- The `ack_count ≈ syn_count` → completion rate ≈ 1.0 → legitimate client confirmed

**Inspect the maps to prove it:**
```bash
# Show that syn and ack counts are roughly equal (legitimate behaviour)
echo "=== syn_map after Demo 1 ==="
sudo ip netns exec fluxguard bpftool --json map dump name syn_map | python3 -c "
import sys, json, ipaddress
data = json.load(sys.stdin)
for e in data:
    if isinstance(e.get('key'), list):
        ip  = str(ipaddress.IPv4Address(bytes(e['key'])))
        cnt = int.from_bytes(bytes(e['value']), 'little')
        print(f'  {ip}: syn_count = {cnt}')
"

echo "=== ack_map after Demo 1 ==="
sudo ip netns exec fluxguard bpftool --json map dump name ack_map | python3 -c "
import sys, json, ipaddress
data = json.load(sys.stdin)
for e in data:
    if isinstance(e.get('key'), list):
        ip  = str(ipaddress.IPv4Address(bytes(e['key'])))
        cnt = int.from_bytes(bytes(e['value']), 'little')
        print(f'  {ip}: ack_count = {cnt}')
"
# Expected: syn_count and ack_count are close → completion_rate ≈ 1.0
```

---

### DEMO 2 — SYN Flood Attack (Must Be BLOCKED)

**Reset first:**
```bash
./reset.sh
# Wait for it to complete, then restart Terminal 1 and Terminal 2 above
```

**What you say to the professor:**
> "Now I will simulate a SYN flood from the same client IP.
> hping3 sends only pure SYN packets at a fixed mechanical rate of 2000 per second.
> Watch two things: First, the tcpdump in Terminal 3 will suddenly STOP receiving
> packets when the block takes effect. Second, Terminal 2 will print a BLOCK line
> with a very low CV value — proving the brain detected the mechanical regularity
> of the bot, not just the volume."

**Run in Terminal 4:**
```bash
echo "=== DEMO 2: SYN flood — watch Terminal 2 for BLOCK and Terminal 3 for silence ==="
sudo ip netns exec client hping3 -S -p 80 -i u500 10.0.2.2
# -S        = pure SYN flag only
# -p 80     = port 80
# -i u500   = one packet every 500 microseconds = 2000 pps
# Press Ctrl+C in this terminal to stop after you see the block
```

**Expected sequence of events (narrate this to the professor):**

1. **Seconds 0-1**: Terminal 3 (tcpdump) fills with SYN packets from 10.0.1.1
2. **Seconds 1-2**: Terminal 2 (brain) shows `[TICK]` lines with `observed_ips=1`
   and gap samples accumulating
3. **~Second 2**: Terminal 2 prints:
   ```
   [BLOCK  ] 10.0.1.1          reason=timing_dispersion      pps=   1987.4  cv=0.0231
   ```
   Point out: **cv=0.023** is near zero — mechanically regular, the machine's fingerprint.
4. **Immediately after**: Terminal 3 (tcpdump) **goes completely silent** — XDP_DROP
5. **~30 seconds later**: Terminal 2 prints:
   ```
   [UNBLOCK] 10.0.1.1          blocked_for=30.2s
   ```

**After the block, while hping3 is still running:**
```bash
# In another sub-terminal — prove the blacklist is populated
echo "=== blacklist_map during attack ==="
sudo ip netns exec fluxguard bpftool --json map dump name blacklist_map | jq .

# Prove the backend is unreachable during the block
echo "=== curl during block — should timeout ==="
sudo ip netns exec client curl --max-time 3 http://10.0.2.2 \
    && echo "ERROR: should have been blocked!" \
    || echo "CORRECT: connection refused — XDP_DROP is active"
```

**After stopping hping3 and waiting for the 30s cooldown:**
```bash
echo "=== curl after amnesty — should succeed ==="
sudo ip netns exec client curl -s -o /dev/null -w "HTTP %{http_code}\n" http://10.0.2.2
# Expected: HTTP 200
```

---

### DEMO 3 — Feature B Isolated (Handshake Completion)

**What you say to the professor:**
> "Now I will demonstrate Feature B independently. I will set the PPS threshold
> very high so Feature A cannot trigger, then show that a SYN flood is still
> caught by the handshake completion rate alone — even at low packet rates."

**Reset and restart brain with high PPS threshold:**
```bash
./reset.sh

# Restart Terminal 1 (backend server)
sudo ip netns exec backend python3 -m http.server 80

# Restart brain with PPS threshold too high for Feature A to trigger
sudo python3 ~/fluxguard/fluxguard_brain.py \
    --netns fluxguard \
    --pps-threshold 999999 \
    --cv-threshold 0.15 \
    --min-syns 20 \
    --completion-thresh 0.10 \
    --poll-interval 0.2 \
    --cooldown-sec 30 \
    --verbose
```

**Run low-rate SYN flood:**
```bash
# Only 100 pps — well below 999999 pps threshold
# But 100% SYN, 0% ACK — completion rate = 0.0
sudo ip netns exec client hping3 -S -p 80 -i u10000 10.0.2.2
# -i u10000 = one packet every 10ms = 100 pps
```

**Expected:** After ~20 SYN packets (≈ 2 seconds), brain prints:
```
[BLOCK  ] 10.0.1.1   reason=handshake_completion   pps=98.3  cv=n/a  completion=0.0000
```

> "This proves Feature B is independent. Even at 100 pps — which any volumetric
> system would ignore — FluxGuard detects the bot because it never completes a
> single TCP handshake."

---

### Log File Analysis (for Professor's Review)

```bash
LOG=~/fluxguard/fluxguard.log

echo "=== All BLOCK events ==="
jq 'select(.event == "BLOCK")' "$LOG"

echo ""
echo "=== CV values (near 0 = bot, high = legitimate) ==="
jq 'select(.event == "BLOCK") | {ip, reason, pps, cv, completion_rate}' "$LOG"

echo ""
echo "=== Block/Unblock timeline ==="
jq -r 'select(.event == "BLOCK" or .event == "UNBLOCK") |
    "\(.ts)  \(.event)  \(.ip)  \(
        if .reason then "reason=\(.reason) pps=\(.pps) cv=\(.cv)"
        else "blocked_for=\(.blocked_for)s"
        end)"' "$LOG"
```

---

## Quick Reference — What Each Demo Proves

| Demo | Action | Expected Result | What It Proves |
|---|---|---|---|
| 1 — Legitimate | `curl` with `sleep 0.$RANDOM` | No BLOCK ever issued | High-variance legitimate traffic is correctly passed |
| 1 — Map inspect | Inspect syn_map + ack_map | syn_count ≈ ack_count | Completion rate ≈ 1.0 for real client |
| 2 — Attack | `hping3 -S -i u500` (2000 pps) | `[BLOCK] reason=timing_dispersion cv=0.02x` within ~2s | Feature A detects mechanical regularity |
| 2 — Network proof | `tcpdump` during block | Zero packets reaching backend | XDP_DROP enforced at kernel layer |
| 2 — App proof | `curl` during block | Connection timeout | Block is end-to-end effective |
| 2 — Amnesty | Wait 30s | `[UNBLOCK]`, `curl` returns HTTP 200 | Cooldown and auto-recovery work |
| 3 — Feature B | `hping3 -i u10000` (100 pps, PPS threshold = 999999) | `[BLOCK] reason=handshake_completion cv=n/a` | Feature B detects below volumetric threshold |

---

## Anticipated Professor Questions

**Q: Why XDP instead of iptables or nftables?**
> iptables/nftables process packets in the kernel's netfilter layer, which runs
> *after* sk_buff allocation. By that point, the kernel has already spent CPU
> copying packet data, allocating ~200 bytes of socket buffer metadata, and
> running through the netdevice receive stack. At 10 Gbps, this matters.
> XDP runs at the driver RX callback — the packet is still in DMA memory, no
> sk_buff exists yet. XDP_DROP frees the packet before any of that overhead.

**Q: What is bpf_ktime_get_ns() and why does it matter?**
> It is a BPF kernel helper function that returns nanosecond precision
> monotonic wall time from within the kernel data path. This is what enables
> Feature A — without per-packet nanosecond timestamps in the kernel, you
> cannot compute inter-packet gaps at this layer. This helper only became
> available in the BPF context relatively recently, and no commercial product
> exploits it for timing dispersion detection at XDP layer.

**Q: Why can't you do CV math in the C/BPF code?**
> The BPF virtual machine specification explicitly forbids floating-point
> instructions. The kernel does not save and restore FPU state during BPF
> execution because this would add ~100ns of overhead per packet — unacceptable
> at the data plane. `sqrt()`, `/`, and `pow()` are impossible in the XDP
> program. The architecture deliberately splits concerns: kernel counts fast,
> Python computes smart.

**Q: What is xdpgeneric vs native XDP?**
> Native XDP (xdpdrv) runs at the network driver level, before DMA completes,
> and requires the driver to explicitly support it. veth (virtual Ethernet)
> pairs do not support native XDP. xdpgeneric runs in the kernel's generic
> receive path — slightly later, but functionally identical for our purposes:
> XDP_DROP still prevents sk_buff allocation and further processing.

**Q: How is this different from Cloudflare's magic transit or XDP firewall?**
> Cloudflare's public eBPF work (Katran, XDP drop tools) uses XDP for
> forwarding and volumetric blocking — counting bytes/packets and dropping
> above a static threshold. They do behavioural analysis (timing, protocol
> semantics) at their scrubbing centre application layer, processing sampled
> NetFlow data with 10-60 second latency. FluxGuard does behavioural analysis
> in the kernel data path, per-packet, with nanosecond precision and ~200ms
> decision latency. The layer is fundamentally different.

**Q: What happens to the timing_map struct values in Python?**
> The struct `timing_val` has two `__u64` fields totalling 16 bytes. bpftool
> dumps them as either named dict fields (if BTF debug info was compiled in
> with `-g`) or raw byte arrays. The Python parser handles both: it reads the
> 8-byte little-endian `last_gap_ns` field, compares it against the previously
> observed value, and only appends to the rolling deque if the value changed —
> meaning a new packet arrived and the kernel updated the struct.

---

## Troubleshooting

**XDP attachment fails with "failed to attach XDP":**
```bash
# Check if another XDP program is already attached
sudo ip netns exec fluxguard ip link show veth-fg-in
# Detach first:
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdpgeneric off
```

**bpftool map show returns nothing:**
```bash
# The maps only exist after the XDP program is attached. Rerun:
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdpgeneric obj fluxguard_kern.o sec xdp
```

**Compilation error: "linux/bpf.h not found":**
```bash
sudo apt install linux-headers-$(uname -r)
```

**Compilation error: "bpf/bpf_helpers.h not found":**
```bash
# On Ubuntu 22.04+ this is in libbpf-dev:
sudo apt install libbpf-dev
# Then re-add the include path:
clang ... -I/usr/include/bpf ...
```

**ping/curl fails between namespaces:**
```bash
# Rebuild topology from scratch:
./reset.sh
# Then re-run just the network setup portion of setup.sh
```

**Brain prints "Command failed: bpftool map flush":**
> This is harmless — older bpftool versions don't support `flush`.
> The maps are reset at the start of each brain run anyway via individual
> key deletions. The warning can be ignored.

---

*FluxGuard — Samarth*
*Keywords: eBPF, XDP, DDoS mitigation, inter-packet timing, CV, handshake completion rate*
