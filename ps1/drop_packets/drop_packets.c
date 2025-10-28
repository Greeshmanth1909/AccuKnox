//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} get_port SEC(".maps");

SEC("xdp_drop")
int drop_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *portno;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // get the required port to block from map
    portno = bpf_map_lookup_elem(&get_port, &key);
    if (!portno) {
        return XDP_PASS;
    }
    
    bpf_printk("%llu is the port number\n", *portno);
    
    if ((void*)eth + sizeof(*eth) <= data_end) {
        bpf_printk("is valid eth\n");
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            bpf_printk("is valid ip\n");
            if (ip->protocol == IPPROTO_TCP) {
                bpf_printk("is TCP\n");
                struct tcphdr *tcp = (void*)ip + sizeof(*ip);
                if ((void*)tcp + sizeof(*tcp) <= data_end) {
                    bpf_printk("is valid tcp\n");
                    if (tcp->dest == bpf_htons((__u16)*portno)) {
                        bpf_printk("Dropping packet to port %d\n", bpf_ntohs(tcp->dest));
                        return XDP_DROP;
                    }
                    bpf_printk("destination port is %d given port is %llu\n", 
                               bpf_ntohs(tcp->dest), *portno);
                    return XDP_PASS;
                }
            }
        }
    }
    
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";