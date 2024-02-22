#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	char buffer[32];
	bpf_printk("Hello world!\n", 0);

	long success = bpf_get_current_comm(buffer, sizeof(buffer));
	if (success != 0){
		return -1;
	}

	bpf_printk("comm is %s\n", buffer);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
