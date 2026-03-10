#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <stddef.h>

struct event {
    unsigned int pid;
    unsigned long frame;
};

/* Python 3.11+ internal frame */

struct interp_frame {
    unsigned long f_func;
    unsigned long previous;
};

struct py_function {
    unsigned long func_code;
};

struct py_code {
    unsigned long co_name;
    unsigned long co_filename;
};

static int read_mem(pid_t pid, void *dst, void *src, size_t size)
{
    struct iovec local = { dst, size };
    struct iovec remote = { src, size };

    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static void read_string(pid_t pid, unsigned long addr, char *buf, size_t size)
{
    struct iovec local = { buf, size };
    struct iovec remote = { (void*)addr, size };

    process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static void walk_stack(pid_t pid, unsigned long frame)
{
    struct interp_frame f;
    struct py_function func;
    struct py_code code;

    while (frame) {

        if (read_mem(pid, &f, (void*)frame, sizeof(f)) <= 0)
            break;

        if (read_mem(pid, &func, (void*)f.f_func, sizeof(func)) <= 0)
            break;

        if (read_mem(pid, &code, (void*)func.func_code, sizeof(code)) <= 0)
            break;

        char name[128] = {};
        char file[256] = {};

        read_string(pid, code.co_name, name, sizeof(name));
        read_string(pid, code.co_filename, file, sizeof(file));

        printf("  %s (%s)\n", name, file);

        frame = f.previous;
    }
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf("\nPython stack pid=%d\n", e->pid);

    walk_stack(e->pid, e->frame);

    return 0;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int map_fd;

    obj = bpf_object__open_file("pyprofiler.bpf.o", NULL);
    bpf_object__load(obj);

    prog = bpf_object__find_program_by_name(obj, "trace_python_frame");

    struct bpf_uprobe_opts opts;

    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.func_name = "_PyEval_EvalFrameDefault";
    
    link = bpf_program__attach_uprobe_opts(
        prog,
        -1,
        "/usr/bin/python3",
        0,
        &opts);

    
    if (!link) {
        fprintf(stderr, "failed to attach uprobe\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    while (1)
        ring_buffer__poll(rb, 100);

    return 0;
}