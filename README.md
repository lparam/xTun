xTun
=================
A secure and fast VPN for protect your network traffic

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
xTun -i IFACE -I IP/MASK -c server -k PASSWORD
scripts/server_up.sh
```

Stop:
```bash
xTun --signal stop
scripts/server_down.sh
```

### Client

```bash
xTun -i IFACE -I IP/MASK -c client -k PASSWORD -s SERVER
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

The MIT License (MIT)

Copyright (c) 2015 Ken

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
