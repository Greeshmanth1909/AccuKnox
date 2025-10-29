//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

const int ALLOW = 0;
const int BLOCK = -1;

#define AF_INET 2

struct process_data {
    __u64 port;
    char comm[16];
};

static __always_inline int str_equal(const char *s1, const char *s2) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (s1[i] != s2[i])
            return 0;
        if (s1[i] == '\0')
            return 1;
    }
    return 1;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, struct process_data);
    __uint(max_entries, 1);
} p_data SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(process_mask, struct socket *sock, struct sockaddr *address, int addrlen) {
    __u32 key = 0;
    char curr_process_name[16];
    bpf_get_current_comm(curr_process_name, sizeof(curr_process_name));
    
    struct process_data *process_data = bpf_map_lookup_elem(&p_data, &key);
    if (!process_data) {
        return ALLOW;
    }

    struct sockaddr_in *addr_in =  (struct sockaddr_in *)address;
    
    // If current process name doesn't match, allow
    if (!str_equal(curr_process_name, process_data->comm)) {
        return ALLOW;
    }
    
    __u16 curr_port = bpf_ntohs(addr_in->sin_port);
    __u16 allowed_port = (__u16)process_data->port;
    
    bpf_printk("Process: %s, curr port: %d, allowed port: %d\n", 
               curr_process_name, curr_port, allowed_port);
    
    // Block access to every port other than allowed_port
    if (curr_port == allowed_port) {
        return ALLOW;
    } else {
        bpf_printk("BLOCKING connection to port %d\n", curr_port);
        return BLOCK;
    }
}

char __license[] SEC("license") = "Dual MIT/GPL";