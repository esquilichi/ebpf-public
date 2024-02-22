APP=sigkill

.PHONY: $(APP)
$(APP): skel
	clang sigkill.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -c sigkill.bpf.c -o sigkill.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton sigkill.bpf.o name sigkill > sigkill.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *./.o *./skel.h ./vmlinux.h $(APP)
