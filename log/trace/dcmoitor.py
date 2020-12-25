from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>

int trace_ret_execve(struct pt_regs *ctx)
{
    u32 pid;
    struct task_struct *task;
    char comm[TASK_COMM_LEN];
    char nodename[9];

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    task = (struct task_struct *) bpf_get_current_task();
    struct pid_namespace *pns = (struct pid_namespace *) task->nsproxy->pid_ns_for_children;

    if (pns->ns.inum == PROC_PID_INIT_INO) {
        return 0;
    }

    struct uts_namespace *uns = (struct uts_namespace *) task->nsproxy->uts_ns;

    bpf_trace_printk("name: %s\\n", uns->name.nodename);
    bpf_trace_printk("comm: %s, ns: %lld\\n", comm, pns->ns.inum);
    return 0;
}
"""

b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kretprobe(event=execve_fnname, fn_name="trace_ret_execve")

while 1:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        exit()
