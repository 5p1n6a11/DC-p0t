from __future__ import print_function
from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>

struct sys_enter_execve_arg {
    u64 __unused__;
    const char * filename;
    const char * argv;
    const char * envp;
};

int do_trace(struct sys_enter_execve_arg *args) {
    return 0;
};
"""

b = BPF(text=bpf_text)
b.attach_tracepoint("syscalls:sys_enter_execve", "do_trace")
b.trace_print()
