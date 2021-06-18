#!/usr/bin/env python3

import array
import ctypes
import json
import logging
import sys
import os

from bcc import BPF

log = logging.getLogger()
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
log.addHandler(handler)

BPF_PROGRAM = "event_monitor_ebpf.2.c"

syscalls = ["execve", "execveat"]

essential_syscalls = ["execve", "execveat"]

event_id = {
    59: "execve",
    322: "execveat",
}

class ArgType(object):
    NONE            = 0
    INT_T           = 1
    UINT_T          = 2
    LONG_T          = 3
    ULONG_T         = 4
    OFF_T_T         = 5
    MODE_T_T        = 6
    DEV_T_T         = 7
    SIZE_T_T        = 8
    POINTER_T       = 9
    STR_T           = 10
    STR_ARR_T       = 11
    SOCKADDR_T      = 12
    OPEN_FLAGS_T    = 13
    EXEC_FLAGS_T    = 14
    SOCK_DOM_T      = 15
    SOCK_TYPE_T     = 16
    CAP_T           = 17
    SYSCALL_T       = 18
    PROT_FLAGS_T    = 19
    ACCESS_MODE_T   = 20
    PTRACE_REQ_T    = 21
    PRCTL_OPT_T     = 22
    TYPE_MAX        = 255

class context_t(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("ppid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
                ("eventid", ctypes.c_uint),
                ("argnum", ctypes.c_uint8),
                ("retval", ctypes.c_int64), ]

def load_bpf_program():
    with open(BPF_PROGRAM, "r") as f:
        bpf = f.read()
    return bpf

def execveat_flags_to_str(flags):
    f_str = "0"

    if flags & 0x1000:
        f_str = "AT_EMPTY_PATH"

    if flags & 0x100:
        if f_str == "0":
            f_str = "AT_SYMLINK_NOFOLLOW"
        else:
            f_str += "|AT_SYMLINK_NOFOLLOW"

    return f_str

def get_kprobes(events):
    sc = essential_syscalls
    for e in events:
        if e in syscalls:
            sc.append(e)
        else:
            raise ValueError("Bad event name {0}".format(e))

    sc = list(set(sc))
    return sc


class DCMonitor:

    def __init__(self):
        self.cur_off = 0
        self.events = list()
        self.do_trace = True
        self.bpf = None
        self.event_bufs = list()
        self.total_lost = 0
        self.events_to_trace = syscalls

    def init_bpf(self):
        bpf_text = load_bpf_program()

        self.bpf = BPF(text=bpf_text)

        sk = get_kprobes(self.events_to_trace)

        # sk = essential_syscalls

        for syscall in sk:
            syscall_fnname = self.bpf.get_syscall_fnname(syscall)
            self.bpf.attach_kprobe(event=syscall_fnname, fn_name="syscall__" + syscall)
            self.bpf.attach_kretprobe(event=syscall_fnname, fn_name="trace_ret_" + syscall)

        log.info("%-6s %-16s %-16s %-6s %-6s %-6s %-12s %s" % (
            "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS"))

    def get_type_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_byte)).contents
        self.cur_off = self.cur_off + 1
        return c_val.value

    def get_uint8_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_uint8)).contents
        self.cur_off = self.cur_off + 1
        return c_val.value

    def get_uint16_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_uint16)).contents
        self.cur_off = self.cur_off + 2
        return c_val.value

    def get_int_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_int)).contents
        self.cur_off = self.cur_off + 4
        return c_val.value

    def get_uint_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_uint)).contents
        self.cur_off = self.cur_off + 4
        return c_val.value

    def get_long_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_long)).contents
        self.cur_off = self.cur_off + 8
        return c_val.value

    def get_ulong_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_ulong)).contents
        self.cur_off = self.cur_off + 8
        return c_val.value

    def get_pointer_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_void_p)).contents
        self.cur_off = self.cur_off + 8
        return hex(0 if c_val.value is None else c_val.value)

    def get_string_from_buf(self, buf):
        str_size = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_uint)).contents.value
        str_off = self.cur_off + 4
        str_buf = buf[str_off:str_off + str_size]
        self.cur_off = self.cur_off + str_size + 4
        try:
            ret_str = str(array.array('B', str_buf).tostring().decode("utf-8"))
            return ret_str
        except:
            return ""

    def get_str_arr_from_buf(self, buf):
        str_list = list()
        while self.cur_off < ctypes.sizeof(buf):
            argtype = self.get_type_from_buf(buf)
            if argtype == ArgType.STR_T:
                str_list.append(self.get_string_from_buf(buf).rstrip('\x00'))
            else:
                return '[%s]' % ', '.join(map(str, str_list))

    def print_event(self, eventname, context, args):
        eventfunc = "dummy"
        if context.eventid == 4:
            eventfunc = "newstat"
        elif context.eventid == 5:
            eventfunc = "newfstat"
        elif context.eventid == 6:
            eventfunc = "newlstat"

        try:
            comm = context.comm.decode("utf-8")
        except:
            return

        if eventname in self.events_to_trace or eventfunc in self.events_to_trace:
            log.info("%-6d %-16s %-16s %-6d %-6d %-6d %-12d %s" % (
                context.uid, eventname, comm, context.pid, context.tid, context.ppid, context.retval, " ".join(args)))

            data = dict()
            data["uid"] = context.uid
            data["api"] = eventname
            data["process_name"] = comm
            data["pid"] = context.pid
            data["tid"] = context.tid
            data["ppid"] = context.ppid
            data["return_value"] = context.retval
            dict_args = dict()
            args_len = len(args)
            for i in range(args_len):
                dict_args["p" + str(i)] = args[i].rstrip('\0')
            data["arguments"] = dict_args

            # log.info(json.dumps(data))
            self.events.append(data)

    def parse_event(self, event_buf):
        context = ctypes.cast(ctypes.byref(event_buf), ctypes.POINTER(context_t)).contents
        self.cur_off = ctypes.sizeof(context_t)
        args = list()

        if context.eventid in event_id:
            eventname = event_id[context.eventid]
            for i in range(context.argnum):
                argtype = self.get_type_from_buf(event_buf)

                if self.cur_off >= ctypes.sizeof(event_buf):
                    return

                if argtype == ArgType.INT_T:
                    args.append(str(self.get_int_from_buf(event_buf)))
                elif argtype == ArgType.UINT_T:
                    args.append(str(self.get_uint_from_buf(event_buf)))
                elif argtype == ArgType.LONG_T:
                    args.append(str(self.get_long_from_buf(event_buf)))
                elif argtype == ArgType.ULONG_T:
                    args.append(str(self.get_ulong_from_buf(event_buf)))
                elif argtype == ArgType.OFF_T_T:
                    args.append(str(self.get_ulong_from_buf(event_buf)))
                elif argtype == ArgType.MODE_T_T:
                    args.append(mode_to_str(self.get_uint_from_buf(event_buf)))
                elif argtype == ArgType.DEV_T_T:
                    args.append(str(self.get_uint_from_buf(event_buf)))
                elif argtype == ArgType.SIZE_T_T:
                    args.append(str(self.get_ulong_from_buf(event_buf)))
                elif argtype == ArgType.POINTER_T:
                    args.append(str(self.get_pointer_from_buf(event_buf)))
                elif argtype == ArgType.STR_T:
                    args.append(self.get_string_from_buf(event_buf))
                elif argtype == ArgType.STR_ARR_T:
                    args.append(self.get_str_arr_from_buf(event_buf))
                elif argtype == ArgType.EXEC_FLAGS_T:
                    flags = self.get_int_from_buf(event_buf)
                    args.append(execveat_flags_to_str(flags))
                elif argtype == ArgType.SYSCALL_T:
                    syscall = self.get_int_from_buf(event_buf)
                    if syscall in event_id:
                        args.append('(%s)' % event_id[syscall])
                    else:
                        args.append('(%s)' % str(syscall))
        else:
            return

        return self.print_event(eventname, context, args)

    def handle_event(self, cpu, data, size):
        buf = ctypes.cast(data, ctypes.POINTER(ctypes.c_char*size)).contents
        event_buf = (ctypes.c_char * size).from_buffer_copy(buf)
        self.event_bufs.append(event_buf)

    def monitor_events(self):
        self.bpf["events"].open_perf_buffer(self.handle_event)

        while self.do_trace:
            try:
                for event in self.event_bufs:
                    self.parse_event(event)
                self.event_bufs = list()
                self.bpf.perf_buffer_poll(1000)
            except KeyboardInterrupt:
                exit()
