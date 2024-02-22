#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
    int pid;
    char comm[16];
    bool success;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {

    size_t pid = /**/;

    long success = /**/;

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (success == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}