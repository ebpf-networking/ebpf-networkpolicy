BPF2GO_TARGETS=networkpolicy_bpfeb.go networkpolicy_bpfel.go networkpolicy_bpfeb.o networkpolicy_bpfel.o

all: $(BPF2GO_TARGETS)

$(BPF2GO_TARGETS): networkpolicy.c include/vmlinux.h
	go generate -mod=vendor .

include/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

clean:
	rm -f include/vmlinux.h $(BPF2GO_TARGETS)
