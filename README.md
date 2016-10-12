latency (1) -- Utility to help test network latency/bandwidth problems
======================================================================

## SYNOPSIS

  `latency` *delay* *bandwidth* [`--client` *server_ip*] [*OPTION*]  
or  
  `latency` `--server` [*OPTION*]

## DESCRIPTION

This project provides an utility to help testing environments
with high latency and low bandwidth.

Currently requires root privileges as uses tun/tap.

## OPTIONS

  * `--port` *port*:
    specify the port to use for client/server.
    The default is `61234`.
  * `--cap-file` *filename*:
    specify a file name to write captured packets (in tcpdump/pcap format).
  * `--framing-bytes` *bytes*:
    specify how many bytes taking into account for framing IP packets.
    On a real network IP packets are encapsulated in some physical layer so
    take this layer into account. The default for this setting is 14 which is
    the usual Ethernet encapsulation.
  * `--help`:
    show usage help.

For delay you can specify **ms** (milliseconds, default) or **s**
(seconds) for unit. The delay is added to the real one, there is no
attempt to discover the current delay.
For bandwidth you can specify:

 * **k** (1000 bytes/s)
 * **K** (1024 bytes/s)
 * **m** (1000000 bytes/s)
 * **M** (1048576 bytes/s)
 * **g** (1000000000 bytes/s)
 * **G** (1073741824 bytes/s)

Also adding **bit** (ie **Mbit**) to specify bits instead of
bytes.
All numbers can be decimal, for instance:


```bash
$ latency 10ms 2.3M
```

## USAGE

Currently connecting to 192.168.127.1 allows to connect to
the local machine with the connection modified as specified.

To use the client/server launch the server first with

```bash
$ latency --server
```

(you can optionally specify a port). Then on the client machine
you can launch

```bash
$ latency 10ms 2.3M --client 192.168.0.11
```

(where `192.168.0.11` is the address of the server). The client
will send latency/bandwidth to server at the beginning so launching
the client where is frequent to change latency/bandwidth makes this
change easier (currently you have to stop the client and open with
new options).

The client/server uses UDP protocol. The server will bind to the UDP
port specified while the client will send packets to this port. If
something is not working check your firewall for this port/protocol.

For better results use the restricted latency/bandwidth over a more
powerful connection (like 1 Gbit cable). This will allow to have for
instance a unrestricted connection (like ssh) and a restricted one.

## NOTES

This program was written for test purposes, is not expected to be
used in production (like used for QoS).

It can be used to test some conditions but is not so sofisticated
to reproduce real network conditions. For instance latency in a real
network is not constant but always have fluctuations.
On the other end this determinism may be used for test reproductions
as conditions are much more predictable.
For instance using local connections and same parameters you can
expect the same results so timing data used for performance are
reasonable more accurate than using a real network.

## HISTORY

This program was written to have an easy way to try reproduce some
limited networks conditions. Mainly for testing a program that was
using tcp connections.

At the beginning I was using a Linux script that used traffic shaper
and some emulation module.
However this was quite complicate to use and I discovered the kernel
too much tweaks on the packets causing some issues.
Trying to fix the problems with kernel modules was not easy and
wouldn't fix the easiness (actually would have more complicated to
update) so I decided to write something in userspace.

At the beginning it was a tcp socket proxy which added latency and
bandwidth control but this could not reproduce some issues due to
acks latency and didn't allows the programs to check the network
queues (as emptied by the proxy).

I knew a solution would be to use tun/tap but I didn't like the
idea of having to be root but the limitations were too high and I
came to use tun/tap with a SUID executable.

Result is quite neat and easy to use.
