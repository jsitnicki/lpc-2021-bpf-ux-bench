/*
 * attach_pkt_counter.c
 *
 * Attach pkt_counter BPF prog to cgroup and pin objects onto BPF filesystem.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "pkt_counter.skel.h"

int main(int argc, char **argv)
{
	struct pkt_counter *obj;
	struct bpf_link *link;
	const char *cgrp_path;
	const char *pins_path;
	char buf[PATH_MAX + 1] = {};
	int cgrp_fd;
	long err;
	int ret;

	ret = EXIT_FAILURE;

	if (argc != 3) {
		warnx("Usage: %s <cgroup path> <pin path>", argv[0]);
		goto out;
	}
	cgrp_path = argv[1];
	pins_path = argv[2];

	/* (1) Open a cgroup FD */
	cgrp_fd = open(cgrp_path, O_DIRECTORY | O_RDONLY);
	if (cgrp_fd < 0) {
		warn("Failed to open cgroup dir %s", cgrp_path);
		goto out;
	}

	/* (2) Create BPF map, load BPF program */
	obj = pkt_counter__open_and_load();
	if (obj == NULL) {
		warn("Failed to open/load skeleton");
		goto out_cgroup;
	}

	/* (3) Pin the map */
	strncpy(buf, pins_path, sizeof(buf) - 1);
	strncat(buf, "/stats", sizeof(buf) - 1);
	err = bpf_map__pin(obj->maps.stats, buf);
	if (err) {
		errno = -err;
		warn("Failed to pin map at %s", buf);
		goto out_object;
	}
	printf("Pinned map at %s\n", buf);

	/* (4) Pin the prog */
	strncpy(buf, pins_path, sizeof(buf) - 1);
	strncat(buf, "/prog", sizeof(buf) - 1);
	err = bpf_program__pin(obj->progs.count_pkts, buf);
	if (err) {
		errno = -err;
		warn("Failed to pin map at %s", buf);
		goto out_object;
	}
	printf("Pinned prog at %s\n", buf);

	/* (5) Attach BPF program to cgroup */
	link = bpf_program__attach_cgroup(obj->progs.count_pkts, cgrp_fd);
	err = libbpf_get_error(obj->links.count_pkts);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		warnx("Failed to attach program to cgroup: %s", buf);
		goto out_object;
	}
	obj->links.count_pkts = link;

	/* (6) Pin the link */
	strncpy(buf, pins_path, sizeof(buf) - 1);
	strncat(buf, "/link", sizeof(buf) - 1);
	err = bpf_link__pin(obj->links.count_pkts, buf);
	if (err) {
		errno = -err;
		warn("Failed to pin link at %s", buf);
		goto out_object;
	}
	printf("Pinned link at %s\n", buf);

	printf("Attached to cgroup %s\n", cgrp_path);
	ret = EXIT_SUCCESS;

out_object:
	pkt_counter__destroy(obj);
out_cgroup:
	close(cgrp_fd);
out:
	return ret;
}
