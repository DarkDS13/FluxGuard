≈≈#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// This macro tells the kernel where to find our XDP program inside the compiled file
SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx) {
    // ctx (Context) contains the raw packet data.
    // Right now, we just tell the network card to let the packet pass into the OS.
    return XDP_PASS;
}

// The Linux Kernel is strict. It requires an open-source license to load eBPF code.
char _license[] SEC("license") = "GPL";

