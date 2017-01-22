#!/bin/bash
ip netns add t2

#add port
ip link set ens6f1 netns t2

#set ip address
# t2 is server, used by kernel
ip netns exec t2 ifconfig ens6f1 1.1.2.3 netmask 255.255.255.0 up
