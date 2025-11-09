Dry documentation for firewall module by Alon Balassiano:

The module consists of the following source files:

fw.h: 
A header file

hw5secws.c: 
An initialization file, calls every sub initialization of other source files.
Sysfs class is initialized here, as it is shared between devices.

inspection.c:
Netfilter hook and handler are defined there in pre-routing.
When a packet is caught, the relevant information is passed to rules.c to check for match.
When required, the relevant information is passed to log.c in order to log the action.
TCP packets are handled in a connection table in managed in conns.c. 

rules.c: 
Rule table logic is defined there, rules are kept in a static array of size MAX_RULES (50).
When packet info arrives from inspection.c, it is analyzed in rule_match function.
Rules sysfs device is initialized here, and communication with user is made with sysfs attributes.

log.c:
Logs are created with add_log which is called from inspection.c.
Logs are kept as a list, when a struct log_entry has two members - log_row_t which contains info, and klist_node which keeps the order.
Communication with user is made with two devices - reset and show.

conns.c:
Handles the TCP connections which were allowed to pass through the firewall. 
Communication with user is made with sysfs device.

mitm.c:
Packets which are part of HTTP, FTP or SMTP protocols are redirected to user space programs retrieving relevant data.
This source file handles redirection to proxy programs, and from them.


User space programs:

main.c:
Inside user directory. This file help communicate with the kernel module.
It shows relevant data from the firewall, as well as passes data to it.
Simply compile it (e.g. 'gcc main.c') and run it, passing one of the following arguments:
show_rules - for showing rule table, printed to stdout.
load_rules <path_to_rules_file> - for loading rules from a file, written in the accepted format.
show_log - for showing logs of packets passing through the firewall
clear_log - to reset the logs
show_conns - for showing connection table

http.c:
Inside http directory. Listens on port 800, accepting packets redirected from firewall.
Compile it and run (with sudo) to allow both HTTP and SMTP connections to go through the firewall.
Retrieves the data, and does the following:
- Erases "gzip" from "Accept-Encoding" header in HTTP request (if appears)
- Closes connection and prevents the transfer of files with size > 1024kB
- DLP system: Blocking potential C code going from client to server (in HTTP and SMTP)
- IPS: Protects client from WordPress Really Simple SSL Plugin 2FA Bypass

ftp.c:
Inside ftp directory. Listens on port 210, accepting packets redirected from firewall.
Compile it and run (with sudo) to allow ftp connection going through the firewall.
Retrieves the data, and looks for "PORT" command. When found, passes data to the firewall, 
which opens data connection from ftp server (port 20) to the client (listening on this port).