#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/klist.h>
#include <linux/time.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>


// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_PART_OF_CONN			 = -3,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conns"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"enp0s8"
#define OUT_NET_DEVICE_NAME			"enp0s9"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	htons(1023)
#define PORT_20			htons(20)
#define PORT_21			htons(21)
#define PORT_25			htons(25)
#define PORT_80			htons(80)
#define PORT_210			htons(210)
#define PORT_250			htons(250)
#define PORT_800			htons(800)
#define MAX_RULES		(50)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_LO	= 0,
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

typedef enum {
	STATE_NONE 			= 0,
	STATE_LISTEN		= 1,
	STATE_NEW 			= 2,
	STATE_SYN_SENT 		= 3,
	STATE_SYN_ACK_SENT 	= 4,
	STATE_ESTABLISHED 	= 5,
	STATE_FIN_WAIT 		= 6,
} conn_state_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

struct conn_entry {
    struct klist_node node;
    __be32	src_ip;
    __be32	dst_ip;
    __be16	src_port;
    __be16	dst_port;
    __be16  proxy_port;
    reason_t reason;
    conn_state_t state;
	char prot;
};

//shared variables
extern struct class* fw_class;        		// created in hw5secws
extern struct device *conns_device;			// created in conns, used also in mitm
extern struct conn_entry *ftp_entry;		// created in mitm
extern struct conn_entry *http_entry;		// created in mitm
extern struct conn_entry *smtp_entry;		// created in mitm

//function declarations

//hw3secws
int hook_init(void);
void release_hook(void);

//rules
int rule_action(int i);
int rule_match(direction_t direction, __be32 src_ip, __be32 dst_ip , 
    prot_t protocol , __be16 src_port, __be16 dst_port, ack_t ack, int i);
int init_rule_table(void);
void release_rule_table(void);

//log.c
int init_log_module(void);
void release_log_module(void);
int add_log(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, prot_t protocol, __u8 verdict, reason_t reason);

//inspection.c
int init_inspection(void);
void release_inspection(void);

//conns.c
int init_conns(void);
void release_conns(void);
struct conn_entry* add_conn(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, conn_state_t state, reason_t reason, char prot);
__u8 check_tcp_validity(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 fin, __u8 syn, __u8 rst);
struct conn_entry* get_conn_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);
void del_entry(struct conn_entry *entry);

//mitm.c
int init_mitm(void);
void release_mitm(void);
int redirect_to_mitm(struct sk_buff *skb, direction_t direction);

#endif // _FW_H_