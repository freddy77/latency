latency
=======

Utility to help test network latency/bandwidth problems.

This project provide an utility to help testing environments
with high latency and low bandwidth.

Currently requires root privileges as use tun/tap.

Syntax: `latency` *delay* *bandwidth*

For delay you can specify **ms** (milliseconds, default) or **s**
(seconds) for unit.
For bandwidth you can specify:

 * **k** (1000 bytes/s)
 * **K** (1024 bytes/s)
 * **m** (1000000 bytes/s)
 * **M** (1048576 bytes/s)

Also adding **bit** (ie **Mbit**) to specify bits instead of
bytes.
All numbers can be decimal, for instance:


```bash
$ latency 10ms 2.3M
```

Currently connecting to 192.168.127.1 allows to connect to
the local machine with the connection modified as specified.
