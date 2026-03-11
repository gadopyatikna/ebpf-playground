#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <stddef.h>

#define OFFSET_FUNC_CODE 48
#define OFFSET_CO_FILENAME 112
#define OFFSET_CO_NAME 120

struct event {
    unsigned int pid;
    unsigned long frame;
};

// less /usr/include/python3.13/internal/pycore_frame.h
struct interp_frame {
    uint64_t previous;
    uint64_t frame_obj;
    uint64_t f_func;
};

// /usr/include/python3.13/cpython/funcobject.h
struct py_function {
    char pad[OFFSET_FUNC_CODE];
    unsigned long func_code;
};

// /usr/include/python3.13/cpython/code.h
struct py_code {
    char pad1[OFFSET_CO_FILENAME];
    uint64_t co_filename;

    char pad2[OFFSET_CO_NAME - OFFSET_CO_FILENAME - 8];
    uint64_t co_name;
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

struct py_ascii {
    uint64_t refcnt;
    uint64_t type;
    uint64_t length;
    uint64_t hash;
    uint32_t state;
    uint32_t padding;
    uint64_t wstr;
};

static void read_py_string(pid_t pid, unsigned long addr, char *buf, size_t size)
{
    struct py_ascii ascii;

    if (read_mem(pid, &ascii, (void*)addr, sizeof(ascii)) <= 0)
        return;

    size_t len = ascii.length;
    if (len >= size)
        len = size - 1;

    int compact = (ascii.state >> 5) & 1;
    int ascii_flag = (ascii.state >> 6) & 1;

    unsigned long data_addr;

    if (compact && ascii_flag) {
        /* compact ASCII string */
        data_addr = addr + sizeof(struct py_ascii);
    } else {
        /* fallback: read pointer from PyCompactUnicodeObject */
        struct {
            struct py_ascii base;
            uint64_t utf8_length;
            uint64_t utf8;
            uint64_t wstr_length;
        } compact_obj;

        if (read_mem(pid, &compact_obj, (void*)addr, sizeof(compact_obj)) <= 0)
            return;

        data_addr = compact_obj.utf8;
    }

    read_mem(pid, buf, (void*)data_addr, len);

    buf[len] = 0;
}

static void walk_stack(pid_t pid, unsigned long frame)
{
    struct interp_frame f;
    struct py_function func;
    struct py_code code;
    
    int depth = 0;
    while (frame && depth < 40) {

        if (read_mem(pid, &f, (void*)frame, sizeof(f)) <= 0)
            break;

        if (read_mem(pid, &func, (void*)f.f_func, sizeof(func)) <= 0)
            break;

        if (read_mem(pid, &code, (void*)func.func_code, sizeof(code)) <= 0)
            break;

        char name[128] = {};
        char file[256] = {};

        read_py_string(pid, code.co_name, name, sizeof(name));
        read_py_string(pid, code.co_filename, file, sizeof(file));

        printf("  %s (%s)\n", name, file);

        frame = f.previous;
        depth++;
    }

    printf("code=%lx filename=%lx name=%lx previous=%lx\n",
        func.func_code,
        code.co_filename,
        code.co_name,
        f.previous);
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
        "/usr/bin/python3.13",
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