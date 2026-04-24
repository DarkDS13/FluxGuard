/*
 * Runs inside the Linux kernel at the XDP hook — the earliest point in the
 * receive path, before sk_buff allocation. Executes per-packet at wire speed.
 *   Feature A (PRIMARY)  — Inter-Packet Timing Dispersion
 *                          Uses bpf_ktime_get_ns() to record the gap between
 *                          consecutive packets per source IP. Python reads
 *                          these gaps and computes Coefficient of Variation.
 *                          Mechanical bots → CV ≈ 0. Humans → CV >> 0.
 *
 *   Feature B (SUPPORTING) — Handshake Completion Rate
 *                          Counts pure SYN packets (syn_map) and pure ACK
 *                          packets (ack_map) per source IP. Python computes
 *                          completion_rate = ack / syn. Flood bots → ~0.0.
 *                          Legitimate clients → ~1.0+.
 *
 * WHY NO FLOATING POINT HERE:
 *   The BPF VM has no FPU. The kernel does not save/restore FPU state during
 *   BPF execution — doing so would be prohibitively expensive per-packet.
 *   All CV math and completion rate math is deferred to Python userspace.
 *
 * BPF MAPS:
 *   blacklist_map  — Enforcement. Python writes; XDP reads. Presence = drop.
 *   meter_map      — Total packet counter per source IP.
 *   timing_map     — [Feature A] last_seen_ns + last_gap_ns per source IP.
 *   syn_map        — [Feature B] Pure SYN packet count per source IP.
 *   ack_map        — [Feature B] Pure ACK packet count per source IP.
 *
 * COMPILE:
 *   clang -O2 -g -Wall -target bpf \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c fluxguard_kern.c -o fluxguard_kern.o
 *
 * ATTACH:
 *   sudo ip netns exec fluxguard \
 *       ip link set dev veth-fg-in xdpgeneric obj fluxguard_kern.o sec xdp
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>    /* struct ethhdr, ETH_P_IP              */
#include <linux/ip.h>          /* struct iphdr, IPPROTO_TCP            */
#include <linux/tcp.h>         /* struct tcphdr                        */
#include <bpf/bpf_helpers.h>   /* SEC(), bpf_map_*, bpf_ktime_get_ns  */
#include <bpf/bpf_endian.h>    /* bpf_htons()                         */

/*
 * BPF_MAP_TYPE_HASH is a kernel hash table with O(1) avg-case operations.
 * max_entries is fixed at load time — the map cannot grow at runtime.
 * SEC(".maps") tells the ELF loader to create/pin these maps on load.*/

/* Enforcement map: Python writes blocked IPs here; XDP drops their packets. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,         __u32);   /* Source IPv4, network byte order */
    __type(value,       __u32);   /* Any non-zero = blocked          */
} blacklist_map SEC(".maps");

/* Total packet counter per source IP. Python divides delta by dt for PPS. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);
    __type(value,       __u32);
} meter_map SEC(".maps");

/*
 * [FEATURE A] Per-IP inter-packet timing data.
 *
 * last_seen_ns: bpf_ktime_get_ns() timestamp of the most recent packet
 *               from this IP. Updated on every packet arrival.
 *
 * last_gap_ns:  Nanosecond gap between the previous packet and the most
 *               recent packet from this IP.
 *               Computed as: now - last_seen_ns (from the prior call).
 *               Python reads this across successive polls and accumulates
 *               a rolling history of gaps, then computes CV.
 *
 * WHY ONLY TWO FIELDS (not a ring buffer):
 *   BPF verifier limits prevent storing large arrays in map values without
 *   complex per-byte bounds proofs. We store the minimum needed (one gap per
 *   packet) and let Python accumulate history in a Python deque.
 */
struct timing_val {
    __u64 last_seen_ns;
    __u64 last_gap_ns;
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);
    __type(value,       struct timing_val);
} timing_map SEC(".maps");

/* [FEATURE B] Pure SYN counter: SYN=1, ACK=0 packets per source IP. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);
    __type(value,       __u32);
} syn_map SEC(".maps");

/* [FEATURE B] Pure ACK counter: ACK=1, SYN=0 packets per source IP. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);
    __type(value,       __u32);
} ack_map SEC(".maps");


/*
 * atomic_increment_u32 — Atomically increment a u32 counter in a BPF map.
 *
 * WHY ATOMIC:
 *   XDP runs one instance per hardware RX queue, potentially on multiple CPU
 *   cores simultaneously. A non-atomic read-modify-write would be a race:
 *   two cores reading value N, both computing N+1, both writing N+1 → net
 *   increment of 1 instead of 2 (lost update). __sync_fetch_and_add()
 *   compiles to LOCK XADD on x86_64 — atomic with no separate mutex.
 *
 * WHY NOT bpf_map_update_elem FOR INCREMENT:
 *   update_elem replaces the whole value atomically but is not a read-modify-
 *   write in one call. You'd need lookup + add + update = three ops = race.
 */
static __always_inline void atomic_increment_u32(void *map, __u32 key)
{
    __u32 *val = bpf_map_lookup_elem(map, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u32 init = 1;
        bpf_map_update_elem(map, &key, &init, BPF_ANY);
    }
}

/*
 * update_timing — [FEATURE A] Record inter-packet timing gap for an IP.
 *
 * bpf_ktime_get_ns() returns nanoseconds since boot (monotonic, never
 * decreasing). We only need the difference between successive packets,
 * so wall-clock time is irrelevant here.
 */
static __always_inline void update_timing(__u32 src_ip)
{
    __u64 now = bpf_ktime_get_ns();

    struct timing_val *tv = bpf_map_lookup_elem(&timing_map, &src_ip);
    if (tv) {
        __u64 gap = (now >= tv->last_seen_ns) ? (now - tv->last_seen_ns) : 0ULL;

        struct timing_val updated = {
            .last_seen_ns = now,
            .last_gap_ns  = gap,
        };
        bpf_map_update_elem(&timing_map, &src_ip, &updated, BPF_EXIST);
    } else {
        struct timing_val init_tv = {
            .last_seen_ns = now,
            .last_gap_ns  = 0ULL,
        };
        bpf_map_update_elem(&timing_map, &src_ip, &init_tv, BPF_NOEXIST);
    }
}


/* 
 * XDP ENTRY POINT
 *
 * THE BPF VERIFIER BOUNDS-CHECKING RULE:
 *   Before dereferencing ANY pointer into the packet buffer, you must prove
 *   to the verifier that the access stays within [data, data_end). The
 *   canonical check is:
 *
 *       if ((void *)(ptr + 1) > data_end) return XDP_PASS;
 *
 *   "ptr + 1" in C pointer arithmetic = ptr + sizeof(*ptr) bytes.
 *   If that address exceeds data_end, the struct would read past the packet.
 *   The verifier simulates every code path statically and rejects any program
 *   where this proof is absent. Missing a single check → EACCES at load time.
 */

SEC("xdp")
int fluxguard_filter(struct xdp_md *ctx)
{
    /*
     * ctx->data / ctx->data_end are __u32 offsets.
     * We cast through (long) to correctly sign-extend to 64-bit pointer.
     */
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    //L2: Ethernet

    struct ethhdr *eth = data;

    /* BOUNDS CHECK #1: Full Ethernet header (14 bytes). */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only handle IPv4. Pass IPv6, ARP, VLAN etc. up the stack. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // L3: IP

    struct iphdr *iph = (struct iphdr *)(eth + 1);

    /* BOUNDS CHECK #2: Minimum fixed IP header (20 bytes). */
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;   /* Network byte order throughout */

    /*  BLACKLIST CHECK (early exit - saves work for known-bad IPs) */
    {
        __u32 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);
        if (blocked)
            return XDP_DROP;
    }

    /* METER: Count all packets */

    atomic_increment_u32(&meter_map, src_ip);

    /* TIMING: Record inter-packet gap [FEATURE A] */

    update_timing(src_ip);

    /* L4: TCP — only process TCP packets further */

    if (iph->protocol != 6) /* IPPROTO_TCP */
        return XDP_PASS;

    /*
     * BOUNDS CHECK #3: Validate ihl before using it for pointer arithmetic.
     *
     * iph->ihl is the IP Header Length in 32-bit words (range: 5..15).
     * Minimum 5 words = 20 bytes. Values < 5 indicate a malformed packet.
     * We MUST check this before computing (void*)iph + ihl*4 because if
     * ihl were 0-4, the resulting pointer could precede or overlap the IP
     * header itself — a verifier violation and potential security hole.
     */
    if (iph->ihl < 5 || iph->ihl > 15)
        return XDP_PASS;

    struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

    /* BOUNDS CHECK #4: Minimum TCP header (20 bytes). */
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    /*
     * [FEATURE B] TCP flag classification.
     *
     * tcph->syn and tcph->ack are 1-bit fields in the TCP control byte.
     * No byte-order conversion needed — single bits are always 0 or 1.
     *
     * Pure SYN (syn=1, ack=0): Connection initiation. Every legitimate TCP
     *   connection starts with exactly one of these. A flood sending ONLY
     *   these never completes any handshake — classic SYN flood pattern.
     *
     * Pure ACK (syn=0, ack=1): Handshake completion or data acknowledgement.
     *   Legitimate clients always generate these. A bot blasting SYN packets
     *   with no intent of completing handshakes will produce zero ACKs.
     *
     * SYN+ACK (syn=1, ack=1): Server's handshake response.
     *   We don't count these — we're classifying client (10.0.1.1) behaviour
     *   and the server is 10.0.2.2. Server packets arrive on veth-fg-out,
     *   not veth-fg-in where this XDP program is attached.
     */
    if (tcph->syn == 1 && tcph->ack == 0) {
        atomic_increment_u32(&syn_map, src_ip);
    } else if (tcph->ack == 1 && tcph->syn == 0) {
        atomic_increment_u32(&ack_map, src_ip);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
