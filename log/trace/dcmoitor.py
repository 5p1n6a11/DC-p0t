from bcc import BPF, libbcc, table
import ctypes

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_HASH(counts);

int do_trace_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u64 key = 1;
    u64 zero = 0;
    u64 *val;

    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
        bpf_trace_printk("%d\\n", *val);
    }
    counts.increment(key);

    return 0;
}
"""

path = "/sys/fs/bpf/counter"

class PinnedArray(table.Array):
    def __init__(self, path, keytype, leaftype, max_entries):
        map_fd = libbcc.lib.bpf_obj_get(ctypes.c_char_p(path.encode('utf-8')))

        if map_fd < 0:
            raise ValueError("Failed to open eBPF map")

        self.map_fd = map_fd
        self.key = keytype
        self.Leaf = leaftype
        self.max_entries = max_entries


b = BPF(text=bpf_text)
pin_path = "/sys/fs/bpf/counter"
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="do_trace_execve")

h = b.get_table("counts")
ret = libbcc.lib.bpf_obj_pin(h.map_fd, ctypes.c_char_p(pin_path.encode('utf-8')))
if ret != 0:
    raise Exception("Failed to pin map")


while 1:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        counts = PinnedArray(
            path = path,
            keytype = ctypes.c_uint64,
            leaftype = ctypes.c_uint64,
            max_entries = 10240,
        )
        print(counts.values()[0].value)
        exit()

