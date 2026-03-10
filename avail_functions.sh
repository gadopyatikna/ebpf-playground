sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep accept
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep epoll
sudo ls /sys/kernel/debug/tracing/events/syscalls | grep epoll

# user space
perf probe -x /usr/bin/python3 --funcs
bpftrace -l 'uprobe:/usr/bin/python3:*'
