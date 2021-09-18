BPFTOOL ?= bpftool
CLANG ?= clang

CFLAGS = -Wall -Wextra -ggdb
LDFLAGS = -lbpf

BPF_CFLAGS = -Wall -Wextra -ggdb -O2 -fno-asynchronous-unwind-tables

ALL = 01/map-create 02/pkt_counter.o 05/pkt_counter.skel.h 05/attach-pkt-counter 06/map-dump

.PHONY: all
all: $(ALL)

01/map-create: 01/map_create.c
	$(CLANG) $(CFLAGS) -o $@ $< $(LDFLAGS)

02/pkt_counter.o: 02/pkt_counter.c
	$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

05/pkt_counter.skel.h: 02/pkt_counter.o
	$(BPFTOOL) gen skeleton $< > $@

05/attach-pkt-counter: 05/attach_pkt_counter.c 05/pkt_counter.skel.h
	$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

06/map-dump: 06/map_dump.c
	$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(ALL)
