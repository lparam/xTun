#!/bin/sh

IFACE=tun0
CIDR=10.0.1.1/24
PORT=1082
PASSWORD=password

CHAIN=xTun
COMMENT=xTun

RC=0
if [ -f /usr/bin/xTun ]; then
    DAEMON=/usr/bin/xTun
elif [ -f /usr/local/bin/xTun ]; then
    DAEMON=/usr/local/bin/xTun
fi

check_running(){
    PID=$(ps -ef | grep -v grep | grep -i "${DAEMON}" | awk '{print $2}')
    if [ -n "$PID" ]; then
        return 0
    else
        return 1
    fi
}

start() {
    $DAEMON -i $IFACE -I $CIDR -k $PASSWORD -s -p $PORT
    net_start
}

stop() {
    net_stop
    $DAEMON --signal stop
}

shutdown() {
    net_stop
    $DAEMON --signal quit
}

restart() {
    stop
    start
}

status() {
    check_running
    if [ $? -eq 0 ]; then
        echo "xTun (pid $PID) is running..."
    else
        echo "xTun is stopped"
        RC=1
    fi
}

net_start() {
    # Turn on IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # turn on NAT over VPN
    if !(iptables-save -t nat | grep -q $CHAIN); then
        iptables -t nat -A POSTROUTING -s $CIDR ! -d $CIDR -m comment --comment $COMMENT -j MASQUERADE
    fi
    iptables -N $CHAIN >/dev/null 2>&1 || (
        iptables -D FORWARD -j $CHAIN
        iptables -F $CHAIN
        iptables -Z $CHAIN
    )
    iptables -A $CHAIN -s $CIDR -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    iptables -A $CHAIN -d $CIDR -j ACCEPT
    iptables -I FORWARD -j $CHAIN

    # Turn on MSS fix (MSS = MTU - TCP header - IP header)
    iptables -t mangle -N $CHAIN >/dev/null 2>&1 || (
        iptables -t mangle -D FORWARD -j $CHAIN
        iptables -t mangle -F $CHAIN
        iptables -t mangle -Z $CHAIN
    )
    iptables -t mangle -A $CHAIN -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    iptables -t mangle -A FORWARD -j $CHAIN
}

net_stop() {
    # Turn off NAT over VPN
    iptables -t nat -D POSTROUTING -s $CIDR ! -d $CIDR -m comment --comment $COMMENT -j MASQUERADE 2>/dev/null

    iptables -D FORWARD -j $CHAIN 2>/dev/null
    iptables -F $CHAIN 2>/dev/null
    iptables -X $CHAIN 2>/dev/null

    # Turn off MSS fix (MSS = MTU - TCP header - IP header)
    iptables -t mangle -D FORWARD -j $CHAIN 2>/dev/null
    iptables -t mangle -F $CHAIN 2>/dev/null
    iptables -t mangle -X $CHAIN 2>/dev/null
}

show_help() {
    echo "Usage: $ProgName <command> [options]"
    echo "Commands:"
    echo "    start     start tun"
    echo "    stop      stop tun"
    echo "    restart   restart tun"
    echo "    status    tun status"
    echo ""
    echo "For help with each command run:"
    echo "$ProgName <command> -h|--help"
    echo ""
}

ProgName=$(basename $0)

command=$1
case $command in
    "" | "-h" | "--help")
        show_help
        ;;
    *)
        shift
        ${command} $@
        if [ $? = 127 ]; then
            echo "Error: '$command' is not a known command." >&2
            echo "       Run '$ProgName --help' for a list of known commands." >&2
            exit 1
        fi
        ;;
esac

exit $RC
