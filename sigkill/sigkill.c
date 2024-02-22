// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "sigkill.skel.h"

static volatile __sig_atomic_t exiting;

struct event {
    int pid;
    char comm[16];
    bool success;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Killed PID %d (%s) for trying to use ptrace syscall\n", e->pid, e->comm);
    else
        printf("Failed to kill PID %d (%s) for trying to use ptrace syscall\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct sigkill *skel;
    int err;

    // Open BPF application 
    skel = sigkill__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Verify and load program
    err = sigkill__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    err = sigkill__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    printf("Sending SIGKILL to any program using the bpf syscall\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    sigkill__destroy( skel);
    return -err;
}