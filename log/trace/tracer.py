#!/usr/bin/env python3

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime

BPF_PROGRAM = "event_monitor_ebpf.c"

def load_bpf_program():
    with open(BPF_PROGRAM, "r") as f:
        bpf = f.read()
    return bpf

bpf_text = load_bpf_program()

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboradInterrupt:
        exit()
