# orbox
## Wrap tor-using applications in a box.

This is a simple wrapper program, written in Golang, that wraps
each command in a separate network namespace. All connections
from this namespace are routed through Tor.

Within this namespace, running applications do not have access
to any other network interfaces.

**NOTE!** This program must be run setuid root. This is absolutely
alpha software. Please do not run this.

## Example
```
./orbox -- curl  'https://api.ipify.org?format=json'
```
