#!/bin/sh

# Turn off IP forwarding
#sysctl -w net.ipv4.ip_forward=0

IFACE=tun0
IP_ROUTE_TABLE=xTun
FWMARK="0x02/0x02"
SETNAME=wall
CHAIN=xTun

for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 > $f
done

# turn off NAT over VPN
iptables -t nat -D POSTROUTING -j $CHAIN > /dev/null 2>&1
iptables -t nat -F $CHAIN > /dev/null 2>&1
iptables -t nat -X $CHAIN > /dev/null 2>&1

iptables -D FORWARD -j $CHAIN > /dev/null 2>&1
iptables -F $CHAIN > /dev/null 2>&1
iptables -X $CHAIN > /dev/null 2>&1

iptables -t mangle -D PREROUTING -j $CHAIN > /dev/null 2>&1
iptables -t mangle -D OUTPUT -j $CHAIN > /dev/null 2>&1
iptables -t mangle -F $CHAIN > /dev/null 2>&1
iptables -t mangle -X $CHAIN > /dev/null 2>&1

ip route delete 180.97.33.108 dev $IFACE > /dev/null 2>&1
ip route delete default dev $IFACE table $IP_ROUTE_TABLE > /dev/null 2>&1
xTun_rule_ids=`ip rule list | grep "lookup $IP_ROUTE_TABLE" | sed 's/://g' | awk '{print $1}'`
for rule_id in $xTun_rule_ids
do
    ip rule delete prio $rule_id
done

ipset -F $SETNAME > /dev/null 2>&1
ipset -X $SETNAME > /dev/null 2>&1

ip route flush cache

echo $0 done
