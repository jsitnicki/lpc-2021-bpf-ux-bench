/*
 * Open a BPF map in a read-only mode and dump key 0.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
	union bpf_attr attr = {};
	const char *map_path;
	int map_fd;
	uint32_t key;
	uint64_t value;
	int err;

	if (argc != 2) {
		printf("Usage: %s <map path>\n", argv[0]);
		return EXIT_FAILURE;
	}
	map_path = argv[1];

	attr.pathname = (uintptr_t)map_path;
	attr.file_flags = BPF_F_RDONLY;
	map_fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (map_fd < 0)
		error(EXIT_FAILURE, errno, "BPF_OBJ_GET");

	key = 0;
	err = bpf_map_lookup_elem(map_fd, &key, &value);
	if (err)
		error(EXIT_FAILURE, errno, "BPF_MAP_LOOKUP_ELEM");

	printf("%lu\n", value);

	close(map_fd);

	return EXIT_SUCCESS;
}
