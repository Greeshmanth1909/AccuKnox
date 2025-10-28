
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

SEC("xdp_drop") 
int count_packets() {
    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";