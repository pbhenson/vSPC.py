This is a fork of the vSPC.py project [1]. Most of vSPC.py, as you can
see, was written by Zach Loafman. I made this temporary repository to
hold some changes I made to vSPC.py until they get accepted upstream.
These changes include SSL support for connections between ESX hosts and
vSPC.py, console activity logging, and some other minor improvements.

## Requirements ##

Python 2.5 or better is required, due to use of the 'with' statement and
other syntax that was introduced in Python 2.5.

Due to the use of epoll in the server implementation, Linux is required.
There may be other issues associated with using vSPC.py on other OSs, as
large parts of vSPC.py were only developed & tested on Linux.

## Configuring VMs to connect to the concentrator ##

In order to configure a VM to use the virtual serial port concentrator,
you must be running ESXi 4.1+. You must also have a software license
level that allows you to use networked serial ports.

First, add a networked virtual serial port to the VM. Configure it as
follows:

```
    (*) Use Network
      (*) Server
      Port URI: vSPC.py
      [X] Use Virtual Serial Port Concentrator:
      vSPC: telnet://hostname:proxy_port
```
NOTE: Direction MUST be Server, and Port URI MUST be vSPC.py. 

where hostname is the FQDN (or IP address) of the machine running the
virtual serial port concentrator, and proxy_port is the port that you've
configured the concentrator to listen for VM connections on. Virtual
serial ports support TLS/SSL on connections to a concentrator.  To use
TLS/SSL, configure the serial port as above, except for the vSPC field,
which should specify telnets instead of telnet. For this to work
correctly, you'll also need to launch the server with the --ssl, --cert,
and possibly --key options.

## Running the Concentrator ##

You run the concentrator through the vSPCServer program. The vSPCServer
program is configurable with a number of options, documented below and
in the program's usage text. Without options, the program will listen
for VM connections on port 13770, listen for admin protocol connections
on port 13371, and, for each connected VM, starts a telnet server that
listens for and serves connections from clients to the VM end of the
virtual serial port.

As mentioned, vSPCServer starts a telnet server for each connected VM by
default; by connecting to these servers with a telnet client, one can
interact with connected VMs. vSPCServer also knows how to open
connections on demand to a specific VM; you can take advantage of this
behavior with the vSPCClient program. These connections do everything
that the automatically opened telnet servers do, and also allow clients
to lock VMs. The --no-vm-ports option disables automatically opened
telnet servers, forcing all client-to-VM traffic to use the vSPCClient
program. This may be desirable if you don't want a bunch of unused
network servers open on the same system as the concentrator, or if
locking is important to your use case (automatically opened telnet
server connections are incompatible with locking and will ignore it).

vSPCServer makes a best effort to keep VM to port number mappings
stable, based on the UUID of the connecting VM. Even if a VM
disconnects, client connections are maintained in anticipation of the VM
reconnecting (e.g. if the VM is rebooting). The UUID<->port mapping is
maintained as long as there are either client connections or as long as
the VM is connected, and even after this condition is no longer met, the
mapping is retained for --vm-expire-time seconds (default 24*3600, or
one day).

The backend of vSPCServer serves three major purposes: (a) On initial
load, all port mappings are retrieved from the backend. The main thread
maintains the port mappings after initial load, but the backend is
responsible for setting the initial map. (This design was chosen to
avoid blocking on the backend when a new VM connects.) (b) The backend
serves all admin connections (because it has full knowledge of the
mappings), (c) The backend can fire off customizable hooks as VMs come
and go, allowing for persistence, or database tracking, or
whatever.

By default, vSPCServer uses the "Memory" backend, which really just
means that no initial mappings are loaded on startup and all state is
retained in memory alone. The other builtin backend is the "File"
backend, which can be configured like so: --backend File --backend-args
'-f /tmp/vSPC'.  As a convenience, this same configuration can be
accomplished using the top level parameter -f or --persist-file, i.e.
'-f /tmp/vSPC' is synonymous with the previous set of arguments.

If '--backend Foo' is given but no builtin backend Foo exists, vSPC.py
tries to import module vSPCBackendFoo, looking for class vSPCBackendFoo.
See --backend-help for programming details.

## Authors ##

- Zach Loafman (initial implementation)
- Kevan Carstensen (SSL support, logging backend, lazy client connections to VMs, internal work necessary to support lazy connections to VMs)
- Dave Johnson (fixes for missing getopt modules and missing shelf.sync() calls)

[1] http://sourceforge.net/p/vspcpy/home/Home/
