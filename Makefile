ARGET := xdp_monitor
BPF_OBJ := $(TARGET).bpf.o
SKEL_H := $(TARGET).skel.h

CC := gcc
CLANG := clang
CFLAGS := -Wall -O2 -g
BPF_CFLAGS := -Wall -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu

.PHONY: all clean

all: $(TARGET)

$(BPF_OBJ): $(TARGET).bpf.c common.h
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_H): $(BPF_OBJ)
        bpftool gen skeleton $< > $@

$(TARGET): $(TARGET).c $(SKEL_H) common.h

