#include "fw.h"

static struct klist conns_list;

static int major_number;
struct device *conns_device = NULL;

static struct file_operations fops = 
{
    .owner = THIS_MODULE
};

// deleting an entry from the connection table given the entry
void del_entry(struct conn_entry *entry)
{
    if (!entry) return;
    klist_del(&(entry->node));
    switch (entry->prot)
    {
    case 'f':
        ftp_entry = NULL;
        break;
    
    case 'h':
        http_entry = NULL;
        break;

    case 's':
        smtp_entry = NULL;
        break;

    default:
        break;
    }
    kfree(entry);
}

// deleting an entry from connection table given a klist_node
void del_node(struct klist_node *curr_node)
{
    struct conn_entry *entry;
    if (!curr_node) return;
    entry = container_of(curr_node, struct conn_entry, node);
    del_entry(entry);
}

// adding a new connection to the table
struct conn_entry* add_conn(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, conn_state_t state, reason_t reason, char prot)
{
    struct conn_entry *entry;

    //checking connection is not already in
    entry = get_conn_entry(src_ip, dst_ip, src_port, dst_port);
    del_entry(entry);
    
    //inserting to list
    entry = kmalloc(sizeof(struct conn_entry), GFP_KERNEL);
    if (!entry) return NULL;
    klist_add_head(&(entry->node), &conns_list);
    entry->src_ip = src_ip;
    entry->dst_ip = dst_ip;
    entry->src_port = src_port;
    entry->dst_port = dst_port;
    entry->state = state;
    entry->proxy_port = 0;
    entry->reason = reason;
    entry->prot = prot;                //'t' = tcp, 'f' = ftp, 'h' = http, 's' = smtp
    switch (prot)
    {
    case 'f':
        ftp_entry = entry;
        break;
    
    case 'h':
        http_entry = entry;
        break;

    case 's':
        smtp_entry = entry;
        break;

    default:
        break;
    }

    return entry;
}

// getting an entry of the connection table, given the 5-tuple identifying the connection
struct conn_entry* get_conn_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port)
{
    struct klist_iter iter;
    struct klist_node *curr_node;
    struct conn_entry *entry;

    klist_iter_init(&conns_list, &iter);
    while ((curr_node = klist_next(&iter)))
    {
        // getting the entry given klist_node using container_of
        entry = container_of(curr_node, struct conn_entry, node);
        if ((entry->src_ip == src_ip) && (entry->dst_ip == dst_ip) && 
            (entry->src_port == src_port) && (entry->dst_port == dst_port)) 
            {
                klist_iter_exit(&iter);
                return entry;
            }
    }
    klist_iter_exit(&iter);
    return NULL;
}


void clean_conns_list(void)
{
    struct klist_iter iter;
    struct klist_node *next, *curr_node;

    // we have to get the next element before deleting an element, so we don't mess the iterator
    klist_iter_init(&conns_list, &iter);   
    curr_node = klist_next(&iter);      // get first element

    if (!curr_node)                     // empty list
    {
        klist_iter_exit(&iter);
        return;
    }
    
    while ((next = klist_next(&iter)))      // next is always valid inside the loop, releasing curr_node
    {
        del_node(curr_node);
        curr_node = next;
    }       
    // next is null, curr_node is still valid
    klist_iter_exit(&iter);
    del_node(curr_node);
}

__u8 check_tcp_validity(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 fin, __u8 syn, __u8 rst)
{
    // here necessarily ack == 1
    struct conn_entry *entry, *receiver_entry;
    conn_state_t state, receiver_state;
    entry = get_conn_entry(src_ip, dst_ip, src_port, dst_port);
    state = (entry == NULL) ? STATE_NONE : entry->state;
    receiver_entry = get_conn_entry(dst_ip, src_ip, dst_port, src_port);
    receiver_state = (receiver_entry == NULL) ? STATE_NONE : receiver_entry->state;
    
    // if reset is sent
    if (rst)
    {
        del_entry(entry);
        del_entry(receiver_entry);
        return NF_ACCEPT;
    }

    switch (state)
    {
    case STATE_LISTEN:        // syn-ack
        if (syn && !fin)
        {
            entry->state = STATE_ESTABLISHED;
            return NF_ACCEPT;
        }
        break;

    case STATE_NEW:     // happens only for new connections with port 20 (ftp data connections)
        if (!syn || fin) break;
        entry->state = STATE_SYN_SENT;
        return NF_ACCEPT;

    case STATE_SYN_SENT:        // ack for syn-ack
        if (syn || fin) break;
        entry->state = STATE_ESTABLISHED;
        return NF_ACCEPT;
        
        break;
    
    case STATE_ESTABLISHED:     // if fin is sent, wait for other side to close connection
        if (syn) break;
        if (!fin) return NF_ACCEPT;
        entry->state = STATE_FIN_WAIT;
        return NF_ACCEPT;

    case STATE_FIN_WAIT:
        if (fin || syn) break;     // cant fin twice
        if (receiver_state == STATE_FIN_WAIT)        //last ack, close connection
        {
            del_entry(entry);
            del_entry(receiver_entry);
            return NF_ACCEPT;
        }    
        else if (receiver_state == STATE_ESTABLISHED)       //wait for fin from other side
        {
            return NF_ACCEPT;
        }
        break;
        
    default:
        return NF_DROP;
    }

    // doesnt follow TCP protocol, close connection
    del_entry(entry);
    del_entry(receiver_entry);
    return NF_DROP;
}


// show connection table
ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
    struct klist_iter iter;
    struct klist_node *curr_node;
    struct conn_entry *entry;
    ssize_t len = 0;           // length of already written lines
    
    klist_iter_init(&conns_list, &iter);

    while ((curr_node = klist_next(&iter)) && (len < PAGE_SIZE)) 
    {
        entry = container_of(curr_node, struct conn_entry, node);
        if (entry->state == STATE_LISTEN) continue;     // server did not send syn-ack yet...
        len += scnprintf(buf + len, PAGE_SIZE - len, "%u %u %hu %hu %hu\n", entry->src_ip, 
            entry->dst_ip, entry->src_port, entry->dst_port, entry->state);
    }
    klist_iter_exit(&iter);
	return len;
}

static DEVICE_ATTR(conns, S_IRUGO , display_conns, NULL);



int init_conns(void)
{
    klist_init(&conns_list, NULL, NULL);

    //create char device
    major_number = register_chrdev(0, DEVICE_NAME_CONN_TAB, &fops);
    if (major_number < 0) return 1;
	
    //class already created in hw5secws
    if (!fw_class) 
    {
        unregister_chrdev(major_number, DEVICE_NAME_CONN_TAB);
        return 1;
    }

    //create sysfs device
    conns_device = device_create(fw_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME_CONN_TAB);	
    if (IS_ERR(conns_device))
    {
        unregister_chrdev(major_number, DEVICE_NAME_CONN_TAB);
        return 1;
    }

    //create sysfs file attributes	
    if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
    {
        device_destroy(fw_class, MKDEV(major_number, 0));
        unregister_chrdev(major_number, DEVICE_NAME_CONN_TAB);
        return 1;
    }

    

    return 0;
}

void release_conns(void)
{
    clean_conns_list();
    device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
    device_destroy(fw_class, MKDEV(major_number, 0));
    unregister_chrdev(major_number, DEVICE_NAME_CONN_TAB);
}