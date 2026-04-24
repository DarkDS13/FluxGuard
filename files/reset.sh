#!/usr/bin/env bash
# =============================================================================
# reset.sh — FluxGuard full reset between demo runs
#
# Run this to completely clean up and re-attach for a fresh demo.
# Usage:
#   chmod +x reset.sh
#   ./reset.sh
# =============================================================================

set -u
PROJ_DIR="/home/$USER/fluxguard"
cd "$PROJ_DIR" 2>/dev/null || { echo "Run from inside $PROJ_DIR"; exit 1; }

echo "=== Stopping brain (if running) ==="
sudo kill -TERM $(pgrep -f "fluxguard_brain.py") 2>/dev/null && echo "Stopped." || echo "Not running."
sleep 1

echo ""
echo "=== Detaching XDP program ==="
sudo ip netns exec fluxguard \
    ip link set dev veth-fg-in xdpgeneric off 2>/dev/null && echo "Detached." || echo "Not attached."

echo ""
echo "=== Flushing all BPF maps ==="
for MAP in meter_map timing_map syn_map ack_map blacklist_map; do
    sudo ip netns exec fluxguard bpftool map flush name $MAP 2>/dev/null \
        && echo "  Flushed: $MAP" || echo "  Skipped: $MAP (may be empty)"
done

echo ""
echo "=== Clearing log file ==="
> "$PROJ_DIR/fluxguard.log" && echo "Log cleared."

echo ""
echo "=== Re-attaching XDP program ==="
sudo ip netns exec fluxguard \
    ip link set dev veth-fg-in \
    xdpgeneric obj "$PROJ_DIR/fluxguard_kern.o" sec xdp \
    && echo "XDP re-attached successfully."

echo ""
echo "=== BPF maps after reset ==="
sudo ip netns exec fluxguard bpftool map show

echo ""
echo "✔  Reset complete. Ready for next demo run."
