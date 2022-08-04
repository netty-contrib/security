# Netty Security
Netty Security is a security extension of Netty.
It provides simple yet powerful API for securing endpoint(s).
Unlike other platform specific firewalls like Linux IPTables or 
Windows Firewall, this runs on all platforms where JVM is supported
while still providing unmatched security services.

### Why reinvent the wheel? Why not use already existing solutions?
It's because there is no ALL-IN-ONE framework in Java which provides
all the functionality of Netty Security. Using solutions such as
Linux IPTables does provide lots of advantage like low-level access
and higher performance, but it's not vendor-neutral.
<br>
When we try to run an application on Windows which was originally
designed to run with Linux IPTables, we need to perform Windows
Firewall configuration from scratch. This will result in lots of
different firewall configuration and eventually, it make simple things
super-complicated.