#!/bin/sh

IFACE=tun0
IP_ROUTE_TABLE=$IFACE
FWMARK="0x02/0x02"
SETNAME=wall
CHAIN=xTun
DNS=8.8.8.8

sysctl -w net.ipv4.ip_forward=1 >> /dev/null

for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 0 > $f
done

iptables -t nat -N $CHAIN > /dev/null 2>&1 || (
    iptables -t nat -D POSTROUTING -j $CHAIN
    iptables -t nat -F $CHAIN
    iptables -t nat -Z $CHAIN
)
iptables -t nat -A $CHAIN -o $IFACE -j MASQUERADE
iptables -t nat -A POSTROUTING -j $CHAIN

iptables -N $CHAIN > /dev/null 2>&1 || (
    iptables -D FORWARD -j $CHAIN
    iptables -F $CHAIN
    iptables -Z $CHAIN
)
iptables -I $CHAIN 1 -i $IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I $CHAIN 1 -o $IFACE -j ACCEPT
iptables -I FORWARD -j $CHAIN

iptables -t mangle -N $CHAIN > /dev/null 2>&1 || (
    iptables -t mangle -D PREROUTING -j $CHAIN
    iptables -t mangle -D OUTPUT -j $CHAIN
    iptables -t mangle -F $CHAIN
    iptables -t mangle -Z $CHAIN
)
ipset -N $SETNAME iphash -exist
iptables -t mangle -A $CHAIN -m set --match-set $SETNAME dst -j MARK --set-mark $FWMARK
iptables -t mangle -A PREROUTING -j $CHAIN
iptables -t mangle -A OUTPUT -j $CHAIN

ip route del default dev $IFACE table $IP_ROUTE_TABLE > /dev/null 2>&1
ip route del $DNS dev $IFACE > /dev/null 2>&1
xTun_rule_ids=`ip rule list | grep "lookup $IP_ROUTE_TABLE" | sed 's/://g' | awk '{print $1}'`
for rule_id in $xTun_rule_ids
do
    ip rule del prio $rule_id
done

CHKIPROUTE=$(grep $IP_ROUTE_TABLE /etc/iproute2/rt_tables)
if [ -z "$CHKIPROUTE" ]; then
    echo "1012 $IP_ROUTE_TABLE" >> /etc/iproute2/rt_tables
fi

ip route add default dev $IFACE table $IP_ROUTE_TABLE
ip route list | grep -q "$DNS dev $IFACE" || ip route add $DNS dev $IFACE
ip rule list | grep -q "fwmark $FWMARK lookup $IP_ROUTE_TABLE" || ip rule add fwmark $FWMARK table $IP_ROUTE_TABLE

ip route flush cache

echo $0 done
