#!/bin/bash
#
# Mount a dedicated BPF filesystem instance for user 'buzz'
#

mkdir -p /run/mount/bpf/pkt_counter
mount -t bpf -o uid=buzz,gid=buzz,mode=0700 none /run/mount/bpf/pkt_counter
ls -ld /run/mount/bpf/pkt_counter
chown buzz.buzz /run/mount/bpf/pkt_counter
ls -ld /run/mount/bpf/pkt_counter
