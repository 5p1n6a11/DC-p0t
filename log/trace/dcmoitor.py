from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

int trace_go_test(struct pt_regs *ctx) 
{
    u64 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("New test process running with PID: %d\\n", pid);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="./test", sym="runtime.usleep", fn_name="trace_go_test")
bpf.trace_print()
