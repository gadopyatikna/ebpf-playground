nm -D $(which python3) | grep _PyEval_EvalFrameDefault # virtual address not offset in elf
sudo bpftrace -e 'uprobe:/usr/bin/python3:_PyEval_EvalFrameDefault { printf("hit\n"); }'
sudo bpftrace -lv 'uprobe:/usr/bin/python3:PyEval_EvalFrameDefault'
objdump -T /usr/bin/python3 | grep PyEval

sudo cat /sys/kernel/debug/tracing/uprobe_events
sudo cat /sys/kernel/debug/tracing/trace_pipe
