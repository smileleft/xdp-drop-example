//#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h> // for BPF helper functions


// BPF map definition (optional for this simple example, but good practice)
// This map could be used to pass configuration from userspace to BPF program

SEC("xdp") // Section name for XDP programs
int xdp_minimal_test(struct xdp_md *ctx) {
	bpf_printk("XDP: --- Minimal test program hit on enp1s0! ---\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; // Required license declaration
