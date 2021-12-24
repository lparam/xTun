# xTun

A secure and fast VPN for protect your network traffic

## Features

* Stateless
* CCA security
* Low cost (CPU, RAM and packet overhead)
* Cross-platform, including PC (Linux), Mobile ([Android](https://github.com/lparam/xTun-android)) and Router (OpenWrt, Padavan)
* TCP and UDP support
* Parallelization

## BUILD

### Linux

```bash
make && make install
```

### OpenWrt

```bash
# At OpenWrt build root
git clone https://github.com/lparam/xTun.git package/xTun
make package/xTun/openwrt/compile
```

## Usage

```bash
$ xTun -h
xTun Version: v0.6.3-6d59478 Maintained by lparam
Usage:
  xTun [options]
Options:
  -I <ifconf>            CIDR of interface (e.g. 10.3.0.1/16)
  -k <password>          shared password for data encryption
  -c --client <host>     run in client mode, connecting to <host>
  -s --server            run in server mode
  [-p --port <port>]     server port to listen on/connect to (default: 1082)
  [-i <iface>]           interface name (e.g. tun0)
  [-b --bind <host>]     bind to a specific interface (only available on server mode, default: 0.0.0.0)
  [-P <parallel>]        number of parallel tun queues (only available on server mode & UDP)
  [--pid <pid>]          PID file of daemon (default: /var/run/xTun.pid)
  [--mtu <mtu>]          MTU size (default: 1426)
  [--keepalive <second>] keepalive delay (default: 0)
  [--signal <signal>]    send signal to xTun: quit, stop
  [-t --tcp]             use TCP rather than UDP (only available on client mode)
  [-n]                   non daemon mode
  [--debug]              debug mode
  [-h, --help]           this help
  [-v, --version]        show version
  [-V]                   verbose mode
```

### scripts

```bash
$ scripts/{client.sh, server.sh} -h
Usage: client.sh | server.sh <command> [options]
Commands:
    start   start tun
    stop    stop tun
    restart restart tun

For help with each command run:
client.sh | server.sh <command> -h|--help
```

### OpenWrt

Modify your `SERVER` and `PASSWORD` in /etc/init.d/xTun

```bash
/etc/init.d/xTun {start, stop}
```

## License

Copyright (C) 2015 lparam

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
