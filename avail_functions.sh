sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep accept
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep epoll
sudo ls /sys/kernel/debug/tracing/events/syscalls | grep epoll
