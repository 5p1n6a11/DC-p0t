from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_HASH(hash);

int do_trace_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u64 key, value;
    key = 1, value = 1234;

    hash.update(&key, &value);

    return 0;
}

int do_trace_ret_execve(struct pt_regs *ctx)
{
    u64 *p;
    u64 key = 1;

    p = hash.lookup(&key);
    if (p == NULL) {
        bpf_trace_printk("Not found\\n");
        return 0;
    }

    bpf_trace_printk("%d\\n", *p);
    return 0;
}
"""

b = BPF(text=bpf_text)

execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="do_trace_execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_trace_ret_execve")

while 1:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        exit()

