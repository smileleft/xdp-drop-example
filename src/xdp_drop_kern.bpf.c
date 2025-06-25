//#include "vmlinux.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h> // for BPF helper functions

#include <linux/in.h> // IPPROTO_UDP 정의 포함 (주로 여기에 있음)
#include <bpf/bpf_endian.h> // bpf_htons, bpf_ntohs 등의 BPF 헬퍼 정의
//#include <bpf/libbpf.h>

// Define the UDP port to drop
#define DROP_UDP_PORT 7777

// BPF map definition (optional for this simple example, but good practice)
// This map could be used to pass configuration from userspace to BPF program

SEC("xdp") // Section name for XDP programs
int xdp_drop_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Malformed packet, pass
    }

    bpf_printk("XDP: Packet received. EtherType: 0x%x\n", bpf_htons(eth->h_proto));

    // Check if it's an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not IPv4, pass
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS; // Malformed IP header, pass
    }

    bpf_printk("XDP: Is IPv4. IP Protocol: 0x%x\n", ip->protocol);

    // Check if it's a UDP packet
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS; // Not UDP, pass
    }


    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS; // Malformed UDP header, pass
    }

    bpf_printk("XDP: Is UDP. Dest Port: %d\n", bpf_htons(udp->dest));

    // Check if destination port matches our DROP_UDP_PORT
    if (bpf_htons(udp->dest) == DROP_UDP_PORT) {
        bpf_printk("XDP: Dropping UDP packet to port %d\n", DROP_UDP_PORT);
        return XDP_DROP; // Drop the packet
    }

    bpf_printk("XDP: Destination port %d (not %d), PASS\n", bpf_htons(udp->dest), DROP_UDP_PORT);
    return XDP_PASS; // Otherwise, pass the packet
}

char _license[] SEC("license") = "GPL"; // Required license declaration
