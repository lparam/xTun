xTun
=================
A secure and fast VPN for protect your network traffic

Features
------------
* Stateless
* CCA security
* Low cost (CPU, RAM and packet overhead)
* Cross-platform, including PC (Linux), Mobile ([Android](https://github.com/lparam/xTun-android)) and Router (OpenWRT)
* TCP and UDP support
* Parallelization


BUILD
------------

### Linux

```bash
make && make install
```

### OpenWRT

```bash
# At OpenWRT build root
git clone https://github.com/lparam/xTun.git package/xTun
make package/xTun/openwrt/compile
```

Usage
------------

### Server

```bash
xTun -I IP/MASK -k PASSWORD -s -P PARALLEL
scripts/server_up.sh
```

Stop:
```bash
xTun --signal stop
scripts/server_down.sh
```

### Client

```bash
xTun -I IP/MASK -k PASSWORD -c SERVER
scripts/client_up.sh
```

Stop:
```bash
xTun --signal stop
scripts/client_down.sh
```

### OpenWrt

Modify your SERVER and PASSWORD in /etc/init.d/xTun
```bash
/etc/init.d/xTun start
```

Stop:
```bash
/etc/init.d/xTun stop
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
