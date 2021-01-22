#!/usr/bin/env python3

from __future__ import print_function
from bcc import BPF

prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
print("PID MESSAGE")
try:
    b.trace_print(fmt="{1} {5}")
except KeyboardInterrupt:
    exit()
