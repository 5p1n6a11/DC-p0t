#!/usr/bin/env python3

from monitor import DCMonitor

if __name__ == '__main__':

    event_monitor = DCMonitor()
    event_monitor.init_bpf()
    event_monitor.monitor_events()
