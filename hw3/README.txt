Dry documentation for firewall module by Alon Balassiano:

The module consists of the following source files:

fw.h: 
A header file

hw3secws.c: 
An initialization file, calls every sub initialization of other source files.
Sysfs class is initialized here, as it is shared between devices.

inspection.c:
Netfilter hook and handler are defined there.
When a packet is caught, the relevant information is passed to rules.c to check for match.
When required, the relevant information is passed to log.c in order to log the action.

rules.c: 
Rule table logic is defined there, rules are kept in a static array of size MAX_RULES (50).
When packet info arrives from inspection.c, it is analyzed in rule_match function.
Rules sysfs device is initialized here, and communication with user is made with sysfs attributes.

log.c:
Logs are created with add_log which is called from inspection.c.
Logs are kept as a list, when a struct log_entry has two members - log_row_t which contains info, and klist_node which keeps the order.
Communication with user is made with two devices - reset and show.