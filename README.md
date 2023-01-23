# Overview

vSPC.py is a Virtual Serial Port Concentrator (also known as a virtual
serial port proxy) that makes use of the
[VMware telnet extensions](http://www.vmware.com/support/developer/vc-sdk/visdk41pubs/vsp41_usingproxy_virtual_serial_ports.pdf).

# Features

- Point any number of virtual serial ports to a single vSPC.py server
(great for cloned VMs)
- Multiplexed client connects: Multiple entities can interact with the
same console. Also allows for gdb connections while monitoring the console.
- Port mappings are sticky - port number will stay constant as long as
the VM or a client is connected, with a set expiration timer after all
connections terminate
- vMotion is fully supported
- Query interface allows you to see VM name, UUID, port mappings on the
vSPC.py server
- Clients can connect using standard telnet, binary mode is negotiated
automatically
- Support VMs with multiple serial ports

# Lineage

This began as is a fork of the
[vSPC.py project hosted at SourceForge](http://sourceforge.net/p/vspcpy/home/Home/)
written by Zach Loafman while at EMC Isilon. It languished until it was
forked by [Kevan Carstensen on github](https://github.com/isnotajoke) and
extensively refactored and enhanced. Changes introduced since the SF fork
include SSL support for connections between ESX hosts and vSPC.py, console
activity logging, and some other minor improvements.

Kevan's fork was re-forked by EMC Isilon to address bugs as we began using
it heavily in our environment once more.

EMC's fork was integrated into Kevan's repo, which was eventually handed
off to Paul B. Henson (https://github.com/pbhenson) to maintain.

# Requirements

Python 3.6 or greater is required.

Due to the use of epoll in the server implementation, Linux is required.
There may be other issues associated with using vSPC.py on other OSs, as
large parts of vSPC.py were only developed & tested on Linux.

# Configuring VMs to connect to the concentrator

In order to configure a VM to use the virtual serial port concentrator,
you must be running ESXi 4.1+. You must also have a software license
level that allows you to use networked serial ports.

First, add a networked virtual serial port to the VM. Configure it as
follows:

```
    (*) Use Network
      (*) Server
      Port URI: s0
      [X] Use Virtual Serial Port Concentrator:
      vSPC: telnet://hostname:proxy_port
```
NOTE: Direction MUST be Server.

where hostname is the FQDN (or IP address) of the machine running the
virtual serial port concentrator, and proxy_port is the port that you've
configured the concentrator to listen for VM connections on. Virtual
serial ports support TLS/SSL on connections to a concentrator.  To use
TLS/SSL, configure the serial port as above, except for the vSPC field,
which should specify telnets instead of telnet. For this to work
correctly, you'll also need to launch the server with the --ssl, --cert,
and possibly --key options.

An arbitrary string can be chosen for "Port URI", but note that "_" is
a restricted character. To support VMs with multiple serial ports,
export the environment variable SUPPORT_MULTI_CONSOLE as "true" to
enable the feature. This tells the VSPC to automatically add the Port
URI as a suffix to the VM name and UUID, which yields identifiers that
are unique per serial port. Port URIs under a single device should be
unique, but dont need to be unique globally. A suggested convention is
to choose "s0" for the first serial port, "s1" for the 2nd, etc.

# Running the Concentrator

You run the concentrator through the vSPCServer program. The vSPCServer
program is configurable with a number of options, documented below and
in the program's usage text. Without options, the program will listen
for VM connections on port 13370, listen for admin protocol connections
on port 13371, and, for each connected VM, starts a telnet server that
listens for and serves connections from clients to the VM end of the
virtual serial port. By default, the program listens for incoming proxy
connections on 0.0.0.0, and listens for incoming admin protocol & client
to VM connections on 127.0.0.1. Use the --proxy-port, --admin-port, and
--port-range-start to change the default port settings; use
--proxy-iface, --admin-iface, and --interface to change the default
interface settings.

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

The backend of vSPCServer serves three major purposes:
- On initial load, all port mappings are retrieved from the backend.
The main thread maintains the port mappings after initial load, but the
backend is responsible for setting the initial map. (This design was
chosen to avoid blocking on the backend when a new VM connects.)
- The backend serves all admin connections (because it has full knowledge
of the mappings)
- The backend can fire off customizable hooks as VMs come and go, allowing
for persistence, or database tracking, or whatever.

By default, vSPCServer uses the "Memory" backend, which really just
means that no initial mappings are loaded on startup and all state is
retained in memory alone. The other builtin backend is the "File"
backend, which can be configured like so: --backend File -f /tmp/vSPC.

If '--backend Foo' is given but no builtin backend Foo exists, vSPC.py
tries to import module vSPCBackendFoo, looking for class vSPCBackendFoo.
Use --help with the desired --backend for help using that backend.

The environment variable VM_CLIENT_LIMIT can be set to a positive
integer, in which case only VM_CLIENT_LIMIT clients can be connected
to a VM at once.

# Building the distribution

source distribution
```
/path/to/your/python setup.py sdist
```

binary distribution
```
/path/to/your/python setup.py bdist
```

build rpm
```
/path/to/your/python setup.py sdist
rpmbuild -ta vSPC-<version>.tar.gz
```

# Authors

- Zach Loafman (initial implementation)
- Kevan Carstensen (SSL support, logging backend, lazy client connections to VMs, internal work necessary to support lazy connections to VMs)
- Dave Johnson (fixes for missing getopt modules and missing shelf.sync() calls)
- Fabien Wernli (add options to configure listen interface, fix broken -f option, packaging improvements)
- Casey Peel (simplified backend argument parsing, fix connection leaks, and improved logging performance)
- Paul B. Henson (minor fixes and maintenance)
