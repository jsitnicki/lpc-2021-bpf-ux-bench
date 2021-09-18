#!/bin/bash

# Lower BPF JIT memory limit to 1MiB
sysctl -w net.core.bpf_jit_limit=$[1024**2]

# Go over BPF JIT memory limit by loading a bunch cBPF progs
for ((i = 0; i < 100; i++)); do
        iptables -A OUTPUT -m bpf --bytecode '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' -j ACCEPT
done
