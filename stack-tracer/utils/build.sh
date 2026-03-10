bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -O2 -g \
  -target bpf \
  -D__TARGET_ARCH_arm64 \
  -c pyprofiler.bpf.c \
  -o pyprofiler.bpf.o

gcc stack-walker.c -lbpf -lelf -o stack-walker
