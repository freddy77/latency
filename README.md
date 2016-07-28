latency
=======

Utility to help test network latency/bandwidth problems.

This project provide an utility to help testing environments
with high latency and low bandwidth.

Currently requires root privileges as use tun/tap.

Syntax:  
  `latency` *delay* *bandwidth* [`--client` *server_ip*] [*OPTION*]  
or  
  `latency` `--server` [*OPTION*]

Options:

  * `--port` *port* specify the port to use for client/server.
    The default is `61234`.
  * `--help` show usage help.

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
the client where is frequent to change latency/bandwidth make this
change easier (currently you have to stop the client and open with
new options).

The client/server used UDP protocol. The server will bind to the UDP
port specified while the client will send packets to this port. If
something is not working check your firewall for this port/protocol.

For better results use the restricted latency/bandwidth over a more
powerful connection (like 1 Gbit cable). This will allow to have for
instance a unrestricted connection (like ssh) and a restricted one.
