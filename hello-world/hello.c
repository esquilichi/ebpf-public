#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hello.skel.h"

int main(void) {
    struct hello *skel;
    int err = 0;

    skel = hello__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program\n");
        return 1;
    }

    err = hello__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(-err));
        goto cleanup;
    }

    err = hello__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(-err));
        goto cleanup;
    }

    while (1) {
        sleep(1);
    }

cleanup:
    hello__destroy(skel);
    return err;
}