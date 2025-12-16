from bcc import BPF
trace_execve = r"""
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>

int trace_execve(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != 4012)
    {
        return 0;
    }

    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);

    char filename[256];

    // kernel memory → используем bpf_probe_read_kernel_str
    if (bpf_probe_read_kernel_str(
            filename, sizeof(filename),
            bprm->filename) > 0) {

        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(comm, sizeof(comm));

        bpf_trace_printk("pid=%d comm=%s exec=%s\\n", pid, comm, filename);
    }

    return 0;
}
"""

traces = r"""
#include <uapi/linux/ptrace.h>
int trace_accept(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid!=34683)
        return 0;

    bpf_trace_printk("accept()\\n");
    return 0;
}

int trace_epoll(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid!=34683)
        return 0;

    bpf_trace_printk("PID %d epoll_wait()\\n", pid);
    return 0;
}

int trace_select(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid!=34683)
        return 0;

    bpf_trace_printk("select()\\n");
    return 0;
}

"""

b = BPF(text=traces)

b.attach_kprobe(event="__arm64_sys_accept4", fn_name="trace_accept")

b.attach_tracepoint(tp="syscalls:sys_enter_epoll_pwait", fn_name="trace_epoll")
b.attach_tracepoint(tp="syscalls:sys_enter_epoll_pwait2", fn_name="trace_epoll")

b.attach_tracepoint(
    tp="syscalls:sys_enter_pselect6",
    fn_name="trace_select"
)


#b.attach_kprobe(event="bprm_execve", fn_name="trace_execve")

print("Tracing execve... Ctrl-C to exit")

while True:
    try:
        print(b.trace_readline().strip())
    except KeyboardInterrupt:
        break
