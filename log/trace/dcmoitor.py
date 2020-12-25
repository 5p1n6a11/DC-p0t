from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

int do_trace_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

b = BPF(text=bpf_text)

execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="do_trace_execve")

while 1:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        exit()

