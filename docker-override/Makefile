APP=docker

.PHONY: $(APP)
$(APP): skel
	clang docker.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -c docker.bpf.c -o docker.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton docker.bpf.o name docker > docker.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *./.o *./skel.h ./vmlinux.h $(APP)
