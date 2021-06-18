#!/usr/bin/bash

ps aux | grep tcpdump | grep -v grep | awk '{ print "kill -INT", $2 }' | sudo sh
ps aux | grep tracer.py | grep -v tracer.py | awk '{ print "kill -INT", $2 }' | sudo sh
./monitor/get_log.sh
sudo docker stop victim
sudo docker rm victim
echo -e "\n*** DC-p0t stop ***\n"
