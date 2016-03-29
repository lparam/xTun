#!/bin/sh

NET=10.0.0.1/24
CHAIN=xTun

# Turn off IP forwarding
#sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1

# Turn off NAT over VPN
iptables -t nat -D POSTROUTING -s $NET ! -d $NET -m comment --comment "xTun" -j MASQUERADE > /dev/null 2>&1

iptables -D FORWARD -j $CHAIN > /dev/null 2>&1
iptables -F $CHAIN > /dev/null 2>&1
iptables -X $CHAIN > /dev/null 2>&1

# Turn off MSS fix (MSS = MTU - TCP header - IP header)
iptables -t mangle -D FORWARD -j $CHAIN > /dev/null 2>&1
iptables -t mangle -F $CHAIN > /dev/null 2>&1
iptables -t mangle -X $CHAIN > /dev/null 2>&1

echo $0 done
