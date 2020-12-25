from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    char comm[TASK_COMM_LEN];
    u32 pid;
};

int do_trace(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

bpf = BPF(text=bpf_text)
execve_fnname = bpf.get_syscall_fnname("execve")
bpf.attach_kretprobe(event=execve_fnname, fn_name="do_trace")

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print("pid: %d, comm: %s" % (event.pid, event.comm))

bpf["events"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
