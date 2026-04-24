#!/usr/bin/env bash
# =============================================================================
# setup.sh — FluxGuard complete setup script
#
# Run this on a fresh Ubuntu VM (tested on Ubuntu 22.04 / 24.04).
# Installs all dependencies, creates the network topology, compiles the
# XDP program, and confirms everything is ready to demo.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
# =============================================================================

set -e   # Exit immediately on any error
set -u   # Treat unset variables as errors

PROJ_DIR="/home/$USER/fluxguard"
cd "$PROJ_DIR" 2>/dev/null || { echo "Run from inside $PROJ_DIR"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0: Install dependencies
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  STEP 0: Installing dependencies"
echo "════════════════════════════════════════════"

sudo apt update -qq
sudo apt install -y \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    build-essential \
    linux-tools-$(uname -r) \
    linux-tools-common \
    linux-headers-$(uname -r) \
    m4 \
    pkg-config \
    iproute2 \
    python3 \
    hping3 \
    tcpdump \
    curl \
    jq \
    net-tools

echo ""
echo "=== Tool versions ==="
clang   --version  | head -1
bpftool  version
python3  --version
hping3   --version 2>&1 | head -1

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Network topology
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  STEP 1: Building network topology"
echo "════════════════════════════════════════════"

# Teardown previous state
sudo ip netns del client    2>/dev/null || true
sudo ip netns del fluxguard 2>/dev/null || true
sudo ip netns del backend   2>/dev/null || true
sudo ip link   del veth-client  2>/dev/null || true
sudo ip link   del veth-fg-out  2>/dev/null || true

# Create namespaces
sudo ip netns add client
sudo ip netns add fluxguard
sudo ip netns add backend

# Create veth pairs
sudo ip link add veth-client type veth peer name veth-fg-in
sudo ip link add veth-fg-out type veth peer name veth-backend

# Move into namespaces
sudo ip link set veth-client  netns client
sudo ip link set veth-fg-in   netns fluxguard
sudo ip link set veth-fg-out  netns fluxguard
sudo ip link set veth-backend netns backend

# Assign IP addresses
sudo ip netns exec client    ip addr add 10.0.1.1/24 dev veth-client
sudo ip netns exec client    ip addr add 10.0.1.10/24 dev veth-client
sudo ip netns exec client    ip addr add 10.0.1.11/24 dev veth-client
sudo ip netns exec fluxguard ip addr add 10.0.1.2/24 dev veth-fg-in
sudo ip netns exec fluxguard ip addr add 10.0.2.1/24 dev veth-fg-out
sudo ip netns exec backend   ip addr add 10.0.2.2/24 dev veth-backend

# Bring interfaces up
for NS in client fluxguard backend; do
    sudo ip netns exec $NS ip link set lo up
done
sudo ip netns exec client    ip link set veth-client  up
sudo ip netns exec fluxguard ip link set veth-fg-in   up
sudo ip netns exec fluxguard ip link set veth-fg-out  up
sudo ip netns exec backend   ip link set veth-backend up

# Routing + forwarding
sudo ip netns exec client    ip route add default via 10.0.1.2
sudo ip netns exec backend   ip route add default via 10.0.2.1
sudo ip netns exec fluxguard sysctl -w net.ipv4.ip_forward=1

# Verify
echo ""
echo "=== Connectivity check ==="
sudo ip netns exec client ping -c 2 -W 1 10.0.2.2 && echo "PASS: client->backend" || echo "FAIL"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Compile XDP program
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  STEP 2: Compiling XDP kernel program"
echo "════════════════════════════════════════════"

ARCH_INCLUDE="/usr/include/$(uname -m)-linux-gnu"
echo "Architecture include path: $ARCH_INCLUDE"

clang -O2 -g -Wall \
      -target bpf \
      -I"$ARCH_INCLUDE" \
      -c fluxguard_kern.c \
      -o fluxguard_kern.o

echo "Compilation exit code: $?"
echo ""
echo "=== ELF sections in compiled object ==="
llvm-objdump -h fluxguard_kern.o | grep -E "Name|xdp|maps|BTF"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Attach XDP program
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  STEP 3: Attaching XDP program"
echo "════════════════════════════════════════════"

sudo ip netns exec fluxguard \
    ip link set dev veth-fg-in xdpgeneric off 2>/dev/null || true

sudo ip netns exec fluxguard \
    ip link set dev veth-fg-in \
    xdpgeneric obj fluxguard_kern.o sec xdp

echo ""
echo "=== BPF maps loaded ==="
sudo ip netns exec fluxguard bpftool map show

echo ""
echo "=== XDP program attached ==="
sudo ip netns exec fluxguard ip link show veth-fg-in

# ─────────────────────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  ✔  FluxGuard setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Terminal 1:  sudo ip netns exec backend python3 -m http.server 80"
echo "  2. Terminal 2:  sudo python3 $PROJ_DIR/fluxguard_brain.py --verbose"
echo "  3. Terminal 3:  Demo commands from demo_guide.md"
echo "════════════════════════════════════════════"
