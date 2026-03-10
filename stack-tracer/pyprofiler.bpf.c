#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
// libbpf_set_print(libbpf_print_fn);

struct event {
    u32 pid;
    u64 frame_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("uprobe/python_frame")
int trace_python_frame(struct pt_regs *ctx)
{
    bpf_printk("frame\n");
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    e->pid = pid_tgid >> 32;

    // ARM64 argument register x1
    e->frame_ptr = PT_REGS_PARM2(ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";