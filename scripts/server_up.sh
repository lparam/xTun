#!/bin/sh

IFACE=tun0
NET=10.0.0.1/24
CHAIN=xTun

# Turn on IP forwarding
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1

# turn on NAT over VPN
if !(iptables-save -t nat | grep -q "xTun"); then
    iptables -t nat -A POSTROUTING -s $NET ! -d $NET -m comment --comment "xTun" -j MASQUERADE
fi
iptables -N $CHAIN > /dev/null 2>&1 || (
    iptables -D FORWARD -j $CHAIN
    iptables -F $CHAIN
    iptables -Z $CHAIN
)
iptables -A $CHAIN -s $NET -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A $CHAIN -d $NET -j ACCEPT
iptables -A FORWARD -j $CHAIN

# Turn on MSS fix (MSS = MTU - TCP header - IP header)
iptables -t mangle -N $CHAIN > /dev/null 2>&1 || (
    iptables -t mangle -D FORWARD -j $CHAIN
    iptables -t mangle -F $CHAIN
    iptables -t mangle -Z $CHAIN
)
iptables -t mangle -A $CHAIN -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -j $CHAIN

echo $0 done
