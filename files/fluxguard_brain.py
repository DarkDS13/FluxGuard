#!/usr/bin/env python3
"""
fluxguard_brain.py — FluxGuard Autonomous DDoS Mitigation Brain
Control plane daemon. Bridges kernel-speed BPF map data (raw integers)
to intelligent, stateful attack detection (statistics + decisions).

DETECTION LOGIC
Feature A — Inter-Packet Timing Dispersion  [PRIMARY NOVELTY]
  Reads last_gap_ns from timing_map each poll cycle.
  Maintains a rolling deque of gap values per source IP.
  Computes Coefficient of Variation: CV = stddev / mean.
    CV ≈ 0   → mechanically regular intervals → bot / flood tool
    CV >> 0  → irregular intervals            → human / real app
  Blocks if: PPS > pps_threshold AND CV < cv_threshold AND samples >= min_gaps.

Feature B — Handshake Completion Rate  [SUPPORTING NOVELTY]
  Reads syn_map and ack_map each poll cycle.
  completion_rate = ack_count / syn_count
    ~0.0 → IP sends SYN floods, never completes handshakes → attack
    ~1.0 → IP completes handshakes normally → legitimate client
  Blocks if: syn_count >= min_syns AND completion_rate < completion_thresh.

WHY PYTHON (not C) FOR STATISTICS:
  The BPF VM has no FPU. Floating-point instructions are forbidden in kernel
  BPF context. sqrt(), /, and math.sqrt() are impossible in the XDP program.
  Python does all statistical analysis on the raw integers the kernel exports.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import math
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

DEFAULT_NETNS                    = "fluxguard"
DEFAULT_BLACKLIST_MAP            = "blacklist_map"
DEFAULT_METER_MAP                = "meter_map"
DEFAULT_TIMING_MAP               = "timing_map"
DEFAULT_SYN_MAP                  = "syn_map"
DEFAULT_ACK_MAP                  = "ack_map"

# Feature A
DEFAULT_PPS_THRESHOLD            = 300.0   # Min PPS before CV is evaluated
DEFAULT_CV_THRESHOLD             = 0.15    # CV below this = mechanical bot
DEFAULT_MIN_GAPS_REQUIRED        = 6       # Need this many gap samples first
DEFAULT_GAP_HISTORY_LEN          = 16      # Rolling window depth per IP

# Feature B
DEFAULT_MIN_SYNS_FOR_COMPLETION  = 20      # Min SYNs before checking rate
DEFAULT_COMPLETION_RATE_THRESH   = 0.10    # Below this = SYN flood

# Operational
DEFAULT_POLL_INTERVAL            = 0.2
DEFAULT_COOLDOWN_SEC             = 30
DEFAULT_BATCH_SIZE               = 256
DEFAULT_LOG_FILE                 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fluxguard.log")

C = {
    "RED":     "\033[91m",
    "GREEN":   "\033[92m",
    "YELLOW":  "\033[93m",
    "CYAN":    "\033[96m",
    "MAGENTA": "\033[95m",
    "BOLD":    "\033[1m",
    "DIM":     "\033[2m",
    "RESET":   "\033[0m",
}

@dataclass
class Config:
    netns:                   str
    blacklist_map:           str
    meter_map:               str
    timing_map:              str
    syn_map:                 str
    ack_map:                 str
    pps_threshold:           float
    cv_threshold:            float
    min_gaps_required:       int
    gap_history_len:         int
    min_syns_for_completion: int
    completion_rate_thresh:  float
    poll_interval:           float
    cooldown_sec:            int
    batch_size:              int
    log_file:                str
    verbose:                 bool


@dataclass
class BlockRecord:
    ip:              str
    blocked_at:      float
    reason:          str      # "timing_dispersion" | "handshake_completion"
    pps:             float
    cv:              Optional[float]
    completion_rate: Optional[float]
    syn_count:       int
    ack_count:       int


@dataclass
class IPState:
    """
    Accumulated per-IP state across poll cycles.

    gap_history   : Rolling deque of last_gap_ns values from timing_map.
                    We only append when the value changes (new packet arrived).
    prev_gap_ns   : The last gap value we observed — used to detect updates.
    prev_meter    : Previous poll's total packet count — used for PPS delta.
    """
    gap_history: Deque[int] = field(default_factory=lambda: collections.deque(maxlen=16))
    prev_gap_ns: int        = 0
    prev_meter:  int        = 0


@dataclass
class BrainState:
    ip_states:      Dict[str, IPState]     = field(default_factory=dict)
    blocked:        Dict[str, BlockRecord] = field(default_factory=dict)
    prev_ts:        float                  = field(default_factory=time.monotonic)
    poll_count:     int                    = 0
    total_blocks:   int                    = 0
    total_unblocks: int                    = 0

_shutdown = False

def _on_signal(signum, frame):
    global _shutdown
    _shutdown = True
    print(f"\n{C['YELLOW']}[SIGNAL] {signum} — shutting down...{C['RESET']}")

signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT,  _on_signal)

def run_cmd(cmd: List[str], allow_empty: bool = False) -> str:
    """
    Execute a command and return stdout.
    Uses explicit list (not shell=True) to prevent shell injection —
    IP address strings from the network flow into these commands.
    """
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return r.stdout
    except subprocess.CalledProcessError as exc:
        if allow_empty:
            return "[]"
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"  exit={exc.returncode}  stderr={exc.stderr.strip()}"
        ) from exc

def _bpftool(cfg: Config, *args: str, allow_empty: bool = False) -> object:
    """
    Run bpftool inside the fluxguard namespace and parse JSON output.

    We exec inside the namespace because BPF maps are pinned to programs
    loaded in that namespace context. --json gives stable, version-independent
    output regardless of bpftool version differences across kernels.
    """
    cmd = ["sudo", "ip", "netns", "exec", cfg.netns,
           "bpftool", "--json"] + list(args)
    raw = run_cmd(cmd, allow_empty=allow_empty)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Non-JSON from bpftool: {raw[:300]}") from exc


# BPF MAP PARSING
#
# bpftool --json map dump produces one of several formats depending on
# kernel version and whether BTF (BPF Type Format) debug info is embedded
# in the compiled object:
#
#   With BTF    : {"key": {"": 16843009}, "value": {"last_seen_ns": 1234, ...}}
#   Without BTF : {"key": [1, 0, 168, 192], "value": [0, 42, 0, 0, ...]}
#   Hex strings : {"key": "0x01 0x00 0xa8 0xc0", "value": "..."}
#
# We normalise all formats to raw Python bytes for consistent downstream use.

def _to_bytes(field: object) -> Optional[bytes]:
    """Normalise any bpftool JSON field to raw bytes. Returns None on failure."""
    try:
        if isinstance(field, list):
            out = []
            for item in field:
                if isinstance(item, int):
                    out.append(item & 0xFF)
                elif isinstance(item, str):
                    out.append(int(item, 16) & 0xFF)
                else:
                    return None
            return bytes(out)

        elif isinstance(field, str):
            cleaned = field.strip().replace("0x", "").replace(" ", "")
            return bytes.fromhex(cleaned)

        elif isinstance(field, int):
            return field.to_bytes(4, "little")

        elif isinstance(field, dict):
            if "" in field and isinstance(field[""], int):
                return field[""].to_bytes(4, "little")

    except (ValueError, TypeError, OverflowError):
        return None

    return None

def _to_ipv4(raw: bytes) -> Optional[str]:
    if len(raw) < 4:
        return None
    try:
        return str(ipaddress.IPv4Address(raw[:4]))
    except ValueError:
        return None

def _to_u32_le(raw: bytes) -> Optional[int]:
    """4 bytes → u32 little-endian. BPF map values use host (LE) byte order."""
    if len(raw) < 4:
        return None
    return int.from_bytes(raw[:4], "little")


def _to_u64_le(raw: bytes) -> Optional[int]:
    if len(raw) < 8:
        return None
    return int.from_bytes(raw[:8], "little")

def parse_u32_map(entries: object) -> Dict[str, int]:
    """Parse a u32-key / u32-value BPF map dump. Returns {ip: count}."""
    result: Dict[str, int] = {}
    if not isinstance(entries, list):
        return result
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key_raw = _to_bytes(entry.get("key"))
        val_raw = _to_bytes(entry.get("value"))
        if key_raw is None or val_raw is None:
            continue
        ip  = _to_ipv4(key_raw)
        cnt = _to_u32_le(val_raw)
        if ip and cnt is not None:
            result[ip] = cnt
    return result

def parse_timing_map(entries: object) -> Dict[str, Tuple[int, int]]:
    """
    Parse timing_map dump.
    Returns {ip: (last_seen_ns, last_gap_ns)}.

    Struct memory layout (x86_64, no padding between u64 fields):
      Offset  0: last_seen_ns  — 8 bytes, little-endian u64
      Offset  8: last_gap_ns   — 8 bytes, little-endian u64
      Total: 16 bytes
    """
    result: Dict[str, Tuple[int, int]] = {}
    if not isinstance(entries, list):
        return result

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key_raw = _to_bytes(entry.get("key"))
        if key_raw is None:
            continue
        ip = _to_ipv4(key_raw)
        if ip is None:
            continue

        val = entry.get("value")

        if isinstance(val, dict) and "last_seen_ns" in val and "last_gap_ns" in val:
            try:
                result[ip] = (int(val["last_seen_ns"]), int(val["last_gap_ns"]))
                continue
            except (TypeError, ValueError):
                pass

        val_raw = _to_bytes(val)
        if val_raw and len(val_raw) >= 16:
            ls = _to_u64_le(val_raw[0:8])
            lg = _to_u64_le(val_raw[8:16])
            if ls is not None and lg is not None:
                result[ip] = (ls, lg)

    return result

def dump_u32_map(cfg: Config, map_name: str) -> Dict[str, int]:
    try:
        raw = _bpftool(cfg, "map", "dump", "name", map_name, allow_empty=True)
        return parse_u32_map(raw)
    except RuntimeError:
        return {}

def dump_timing_map(cfg: Config) -> Dict[str, Tuple[int, int]]:
    try:
        raw = _bpftool(cfg, "map", "dump", "name", cfg.timing_map, allow_empty=True)
        return parse_timing_map(raw)
    except RuntimeError:
        return {}

def _ip_to_hex(ip_str: str) -> List[str]:
    """
    "10.0.1.1" → ["0a", "00", "01", "01"]
    bpftool's 'key hex' argument expects space-separated big-endian bytes.
    """
    return [f"{b:02x}" for b in ipaddress.IPv4Address(ip_str).packed]

def blacklist_add(cfg: Config, ip: str) -> None:
    """Insert IP into kernel blacklist_map. XDP drops their packets immediately."""
    cmd = (["sudo", "ip", "netns", "exec", cfg.netns,
            "bpftool", "map", "update", "name", cfg.blacklist_map,
            "key", "hex"] + _ip_to_hex(ip) +
           ["value", "hex", "01", "00", "00", "00"])
    run_cmd(cmd)

def blacklist_remove(cfg: Config, ip: str) -> None:
    """Remove IP from blacklist_map (amnesty). XDP immediately passes their packets."""
    cmd = (["sudo", "ip", "netns", "exec", cfg.netns,
            "bpftool", "map", "delete", "name", cfg.blacklist_map,
            "key", "hex"] + _ip_to_hex(ip))
    run_cmd(cmd)


def flush_map(cfg: Config, map_name: str) -> None:
    """Flush all entries from a map. Silently ignored if map is empty."""
    try:
        run_cmd(["sudo", "ip", "netns", "exec", cfg.netns,
                 "bpftool", "map", "flush", "name", map_name])
    except RuntimeError:
        pass

def coefficient_of_variation(gaps: List[int]) -> Optional[float]:
    """
    Compute CV = stddev / mean over a list of inter-packet gap values (nanoseconds).

    WHY CV INSTEAD OF RAW VARIANCE:
      Variance is an absolute measure that scales with gap magnitude.
      hping3 at 1000 pps → gaps ≈ 1,000,000 ns → variance ≈ billions.
      hping3 at 100  pps → gaps ≈ 10,000,000 ns → variance ≈ trillions.
      Both are equally "regular" but raw variance differs by 100x.
      CV normalises by the mean: a bot at any rate has CV ≈ 0.
      A human at any rate has CV >> 0 (irregular timing dominates).

    Returns None if fewer than 2 samples or mean is zero.
    """
    n = len(gaps)
    if n < 2:
        return None
    mean = sum(gaps) / n
    if mean == 0.0:
        return None
    # Bessel's correction (n-1) for sample standard deviation
    variance = sum((g - mean) ** 2 for g in gaps) / (n - 1)
    return math.sqrt(variance) / mean


def handshake_completion_rate(syn_count: int, ack_count: int) -> Optional[float]:
    """
    Compute completion_rate = ack_count / syn_count.

    Interpretation:
      ~0.0  : Many SYNs, zero ACKs → SYN flood bot never completes handshakes.
      ~1.0+ : Balanced SYN/ACK counts → legitimate client.
              Rate > 1.0 is normal: data transfer generates many ACKs per SYN.

    Returns None if syn_count == 0.
    """
    if syn_count == 0:
        return None
    return ack_count / syn_count

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_jsonl(fd, event: str, **fields) -> None:
    """Write one JSON Lines record. Easily processed with jq or pandas."""
    fd.write(json.dumps({"ts": utcnow(), "event": event, **fields},
                        default=str) + "\n")
    fd.flush()


def print_header(cfg: Config) -> None:
    bar = "─" * 74
    print(f"\n{C['BOLD']}{bar}{C['RESET']}")
    print(f"  {C['BOLD']}FluxGuard Brain{C['RESET']}  |  {utcnow()}")
    print(f"  Namespace         : {cfg.netns}")
    print(f"  {C['CYAN']}── Feature A: Inter-Packet Timing Dispersion [PRIMARY NOVELTY]{C['RESET']}")
    print(f"  PPS threshold     : {cfg.pps_threshold:.0f} pps")
    print(f"  CV threshold      : < {cfg.cv_threshold:.2f}  (below = mechanical bot)")
    print(f"  Gap samples needed: {cfg.min_gaps_required}  |  history: {cfg.gap_history_len}")
    print(f"  {C['MAGENTA']}── Feature B: Handshake Completion Rate [SUPPORTING NOVELTY]{C['RESET']}")
    print(f"  Min SYNs before check : {cfg.min_syns_for_completion}")
    print(f"  Completion threshold  : < {cfg.completion_rate_thresh:.2f}  (below = SYN flood)")
    print(f"  ── Operational ───────────────────────────────────────────────────")
    print(f"  Poll interval : {cfg.poll_interval}s  |  Cooldown: {cfg.cooldown_sec}s")
    print(f"{C['BOLD']}{bar}{C['RESET']}\n")


def print_block(rec: BlockRecord) -> None:
    cv_s   = f"{rec.cv:.4f}"            if rec.cv is not None else "n/a"
    comp_s = f"{rec.completion_rate:.4f}" if rec.completion_rate is not None else "n/a"
    feat_c = C["CYAN"] if rec.reason == "timing_dispersion" else C["MAGENTA"]
    print(f"[{C['RED']}{C['BOLD']}BLOCK  {C['RESET']}] "
          f"{C['BOLD']}{rec.ip:<16}{C['RESET']}  "
          f"reason={feat_c}{rec.reason}{C['RESET']:<36}  "
          f"pps={C['YELLOW']}{rec.pps:>9.1f}{C['RESET']}  "
          f"cv={C['YELLOW']}{cv_s:<10}{C['RESET']}  "
          f"completion={C['YELLOW']}{comp_s}{C['RESET']}")


def print_unblock(ip: str, duration: float) -> None:
    print(f"[{C['GREEN']}{C['BOLD']}UNBLOCK{C['RESET']}] "
          f"{C['BOLD']}{ip:<16}{C['RESET']}  blocked_for={duration:.1f}s")


def print_tick(state: BrainState, n_obs: int, dt: float, cfg: Config) -> None:
    if cfg.verbose:
        print(f"[{C['DIM']}TICK{C['RESET']}]   "
              f"poll={state.poll_count:<5} observed={n_obs:<5} "
              f"blocked={len(state.blocked):<4} dt={dt:.3f}s  "
              f"blocks={state.total_blocks} unblocks={state.total_unblocks}")

def monitor(cfg: Config, log_fd) -> None:
    """
    Main poll-detect-enforce loop. Runs until SIGTERM/SIGINT.

    Each iteration:
      1. Snapshot meter_map, timing_map, syn_map, ack_map from kernel.
      2. For each observed IP:
           a. PPS = (delta_count) / dt
           b. Append gap to history if timing_map value changed  [Feature A]
           c. Compute CV from gap history                        [Feature A]
           d. Read syn/ack counts                                [Feature B]
           e. Compute completion rate                            [Feature B]
           f. Decide: block / pass / skip (already blocked)
      3. Apply blocks (sorted by severity, capped at batch_size).
      4. Expire blocks whose cooldown has elapsed (amnesty).
      5. Log TICK entry. Sleep remaining interval time.
    """
    state = BrainState()
    state.prev_ts = time.monotonic()

    print_header(cfg)

    for mn in [cfg.meter_map, cfg.timing_map, cfg.syn_map,
               cfg.ack_map, cfg.blacklist_map]:
        flush_map(cfg, mn)

    print(f"  {C['GREEN']}Maps flushed. Monitoring active.{C['RESET']}\n")

    while not _shutdown:
        loop_start = time.monotonic()

        try:
            curr_meter  = dump_u32_map(cfg, cfg.meter_map)
            curr_timing = dump_timing_map(cfg)
            curr_syn    = dump_u32_map(cfg, cfg.syn_map)
            curr_ack    = dump_u32_map(cfg, cfg.ack_map)
        except RuntimeError as exc:
            print(f"[WARN] Map read failed: {exc}", file=sys.stderr)
            _smart_sleep(cfg.poll_interval, loop_start)
            continue

        now = time.monotonic()
        dt  = max(now - state.prev_ts, 1e-6)
        state.poll_count += 1

        candidates: List[Tuple] = []
        # (ip, reason, pps, cv, comp_rate, syn_c, ack_c)

        for ip, curr_total in curr_meter.items():
            if ip in state.blocked:
                continue

            if ip not in state.ip_states:
                state.ip_states[ip] = IPState(
                    gap_history=collections.deque(maxlen=cfg.gap_history_len))
            ip_st = state.ip_states[ip]

            prev_total  = ip_st.prev_meter
            delta       = (curr_total - prev_total) if curr_total >= prev_total \
                          else curr_total
            pps         = delta / dt
            ip_st.prev_meter = curr_total

            timing_entry = curr_timing.get(ip)
            if timing_entry is not None:
                _, curr_gap_ns = timing_entry
                if curr_gap_ns > 0 and curr_gap_ns != ip_st.prev_gap_ns:
                    ip_st.gap_history.append(curr_gap_ns)
                    ip_st.prev_gap_ns = curr_gap_ns

            # [Feature A] Compute CV
            cv: Optional[float] = None
            timing_block = False
            if pps >= cfg.pps_threshold:
                gaps = list(ip_st.gap_history)
                if len(gaps) >= cfg.min_gaps_required:
                    cv = coefficient_of_variation(gaps)
                    if cv is not None and cv < cfg.cv_threshold:
                        timing_block = True

            # [Feature B] Completion rate
            syn_c  = curr_syn.get(ip, 0)
            ack_c  = curr_ack.get(ip, 0)
            comp_r = handshake_completion_rate(syn_c, ack_c)
            handshake_block = (
                syn_c >= cfg.min_syns_for_completion
                and comp_r is not None
                and comp_r < cfg.completion_rate_thresh
            )

            if timing_block:
                candidates.append(
                    (ip, "timing_dispersion", pps, cv, comp_r, syn_c, ack_c))
            elif handshake_block:
                candidates.append(
                    (ip, "handshake_completion", pps, cv, comp_r, syn_c, ack_c))

        if candidates:
            candidates.sort(key=lambda x: (x[1] != "timing_dispersion", -x[2]))
            if cfg.batch_size > 0:
                candidates = candidates[:cfg.batch_size]

            for ip, reason, pps, cv, comp_r, syn_c, ack_c in candidates:
                try:
                    blacklist_add(cfg, ip)
                    rec = BlockRecord(ip=ip, blocked_at=now, reason=reason,
                                      pps=pps, cv=cv, completion_rate=comp_r,
                                      syn_count=syn_c, ack_count=ack_c)
                    state.blocked[ip] = rec
                    state.total_blocks += 1
                    print_block(rec)
                    log_jsonl(log_fd, "BLOCK",
                              ip=ip, reason=reason, pps=round(pps, 2),
                              cv=round(cv, 6) if cv is not None else None,
                              completion_rate=round(comp_r, 4) if comp_r is not None else None,
                              syn_count=syn_c, ack_count=ack_c,
                              gap_samples=len(ip_st.gap_history))
                except RuntimeError as exc:
                    print(f"[WARN] Block failed {ip}: {exc}", file=sys.stderr)

        expired = [ip for ip, rec in state.blocked.items()
                   if (now - rec.blocked_at) >= cfg.cooldown_sec]
        for ip in expired:
            rec = state.blocked.pop(ip)
            try:
                blacklist_remove(cfg, ip)
                state.total_unblocks += 1
                print_unblock(ip, now - rec.blocked_at)
                log_jsonl(log_fd, "UNBLOCK", ip=ip,
                          blocked_for=round(now - rec.blocked_at, 1),
                          original_reason=rec.reason)
                state.ip_states.pop(ip, None)   
            except RuntimeError as exc:
                print(f"[WARN] Unblock failed {ip}: {exc}", file=sys.stderr)

        print_tick(state, len(curr_meter), dt, cfg)
        log_jsonl(log_fd, "TICK", poll=state.poll_count,
                  observed_ips=len(curr_meter),
                  blocked_ips=len(state.blocked), dt=round(dt, 4))

        state.prev_ts = now
        _smart_sleep(cfg.poll_interval, loop_start)

    print(f"\n{C['GREEN']}{C['BOLD']}FluxGuard stopped.{C['RESET']}")
    print(f"  Polls: {state.poll_count}  |  "
          f"Blocks: {state.total_blocks}  |  "
          f"Unblocks: {state.total_unblocks}")


def _smart_sleep(interval: float, loop_start: float) -> None:
    """Sleep the remaining poll interval in 50ms chunks for fast SIGTERM response."""
    deadline = loop_start + interval
    while not _shutdown and time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        time.sleep(min(0.05, max(0.0, remaining)))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="FluxGuard — autonomous DDoS mitigation brain",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--netns",              default=DEFAULT_NETNS)
    p.add_argument("--blacklist-map",      default=DEFAULT_BLACKLIST_MAP)
    p.add_argument("--meter-map",          default=DEFAULT_METER_MAP)
    p.add_argument("--timing-map",         default=DEFAULT_TIMING_MAP)
    p.add_argument("--syn-map",            default=DEFAULT_SYN_MAP)
    p.add_argument("--ack-map",            default=DEFAULT_ACK_MAP)
    p.add_argument("--pps-threshold",      type=float, default=DEFAULT_PPS_THRESHOLD,help="[A] Min PPS before CV is evaluated")
    p.add_argument("--cv-threshold",       type=float, default=DEFAULT_CV_THRESHOLD,help="[A] CV below this = mechanical bot → block")
    p.add_argument("--min-gaps",           type=int,   default=DEFAULT_MIN_GAPS_REQUIRED,help="[A] Minimum gap samples required before deciding")
    p.add_argument("--gap-history",        type=int,   default=DEFAULT_GAP_HISTORY_LEN,help="[A] Rolling window depth per IP")
    p.add_argument("--min-syns",           type=int,   default=DEFAULT_MIN_SYNS_FOR_COMPLETION,help="[B] Minimum SYN count before checking completion rate")
    p.add_argument("--completion-thresh",  type=float, default=DEFAULT_COMPLETION_RATE_THRESH,help="[B] Completion rate below this = SYN flood → block")
    p.add_argument("--poll-interval",      type=float, default=DEFAULT_POLL_INTERVAL)
    p.add_argument("--cooldown-sec",       type=int,   default=DEFAULT_COOLDOWN_SEC)
    p.add_argument("--batch-size",         type=int,   default=DEFAULT_BATCH_SIZE)
    p.add_argument("--log-file",                       default=DEFAULT_LOG_FILE)
    p.add_argument("--verbose", action="store_true",   help="Print per-tick status")
    return p


def main() -> int:
    args = build_parser().parse_args()
    cfg  = Config(
        netns                   = args.netns,
        blacklist_map           = args.blacklist_map,
        meter_map               = args.meter_map,
        timing_map              = args.timing_map,
        syn_map                 = args.syn_map,
        ack_map                 = args.ack_map,
        pps_threshold           = args.pps_threshold,
        cv_threshold            = args.cv_threshold,
        min_gaps_required       = args.min_gaps,
        gap_history_len         = args.gap_history,
        min_syns_for_completion = args.min_syns,
        completion_rate_thresh  = args.completion_thresh,
        poll_interval           = args.poll_interval,
        cooldown_sec            = args.cooldown_sec,
        batch_size              = args.batch_size,
        log_file                = args.log_file,
        verbose                 = args.verbose,
    )
    print(f"[INFO] Logging to: {cfg.log_file}")
    try:
        with open(cfg.log_file, "a", encoding="utf-8") as log_fd:
            monitor(cfg, log_fd)
    except RuntimeError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
