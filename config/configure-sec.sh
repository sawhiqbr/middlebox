#!/bin/bash
ip route add 10.0.0.0/16 via 10.1.0.2 dev eth0
echo '10.0.0.21 insec' >> /etc/hosts
echo '10.1.0.21 sec' >> /etc/hosts

while true; 
    do sleep 0.01;
    done