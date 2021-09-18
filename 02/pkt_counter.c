/*
 * pkt_counter.c
 *
 * Count packets received within the cgroup.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

enum {
	STAT_IN_RECEIVES = 0,
	MAX_STAT,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, MAX_STAT);
} stats SEC(".maps");

SEC("cgroup_skb/ingress")
int count_pkts(struct __sk_buff *skb __attribute__((unused)))
{
	__u32 key = STAT_IN_RECEIVES;
	__u64 *count = bpf_map_lookup_elem(&stats, &key);

	if (count)
		__sync_fetch_and_add(count, 1);

	return 1;
}

char _license[] SEC("license") = "GPL";
