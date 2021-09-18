#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>

int main(void)
{
	int fd;

	fd = bpf_create_map_name(BPF_MAP_TYPE_ARRAY, "pkt_stats",
				/*key_size=*/ 4, /*value_size=*/ 8,
				/*max_entries=*/ 1, /*map_flags=*/ 0);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "map create");

	close(fd);
	return EXIT_SUCCESS;
}
