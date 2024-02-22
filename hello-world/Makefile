APP=hello

.PHONY: $(APP)
$(APP): skel
	clang hello.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -c hello.bpf.c -o hello.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton hello.bpf.o name hello > hello.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *./.o *./skel.h ./vmlinux.h $(APP)
