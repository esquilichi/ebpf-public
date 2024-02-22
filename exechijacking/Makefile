APP=exechijacking

.PHONY: $(APP)
$(APP): skel
	clang exechijacking.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -c exechijacking.bpf.c -o exechijacking.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton exechijacking.bpf.o name exechijacking > exechijacking.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *./.o *./skel.h ./vmlinux.h $(APP)
