#include "fw.h"

static struct klist conns_list;

static int major_number;
static struct device* conns_device = NULL;

static struct file_operations fops = 
{
    .owner = THIS_MODULE
};


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

    default:
        break;
    }
    kfree(entry);
}

void del_node(struct klist_node *curr_node)
{
    struct conn_entry *entry;
    if (!curr_node) return;
    entry = container_of(curr_node, struct conn_entry, node);
    del_entry(entry);
}

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
    entry->prot = prot;                //'t' = tcp, 'f' = ftp, 'h' = http
    switch (prot)
    {
    case 'f':
        ftp_entry = entry;
        break;
    
    case 'h':
        http_entry = entry;
        break;

    default:
        break;
    }

    return entry;
}

struct conn_entry* get_conn_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port)
{
    struct klist_iter iter;
    struct klist_node *curr_node;
    struct conn_entry *entry;

    klist_iter_init(&conns_list, &iter);
    while ((curr_node = klist_next(&iter)))
    {
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

    //we have to get the next element before deleting an element, so we don't mess the iterator
    klist_iter_init(&conns_list, &iter);   
    curr_node = klist_next(&iter);      //get first element

    if (!curr_node)                     //empty list
    {
        klist_iter_exit(&iter);
        return;
    }
    
    while ((next = klist_next(&iter)))      //next is always valid inside the loop, releasing curr_node
    {
        del_node(curr_node);
        curr_node = next;
    }       
    //next is null, curr_node is still valid
    klist_iter_exit(&iter);
    del_node(curr_node);
}

__u8 check_tcp_validity(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 fin, __u8 syn, __u8 rst)
{
    //here necessarily ack == 1
    struct conn_entry *entry, *receiver_entry;
    conn_state_t state, receiver_state;
    entry = get_conn_entry(src_ip, dst_ip, src_port, dst_port);
    state = (entry == NULL) ? STATE_NONE : entry->state;
    receiver_entry = get_conn_entry(dst_ip, src_ip, dst_port, src_port);
    receiver_state = (receiver_entry == NULL) ? STATE_NONE : receiver_entry->state;
    
    if (rst)
    {
        del_entry(entry);
        del_entry(receiver_entry);
        return NF_ACCEPT;
    }

    switch (state)
    {
    case STATE_LISTEN:        //syn-ack
        if (syn && !fin)
        {
            entry->state = STATE_ESTABLISHED;
            return NF_ACCEPT;
        }
        break;

    case STATE_NEW:     //happens only for new connections with port 20 (ftp data connections)
        if (!syn || fin) break;
        entry->state = STATE_SYN_SENT;
        return NF_ACCEPT;

    case STATE_SYN_SENT:        //ack for syn-ack
        if (syn || fin) break;
        entry->state = STATE_ESTABLISHED;
        return NF_ACCEPT;
        
        break;
    
    case STATE_ESTABLISHED:
        if (syn) break;
        if (!fin) return NF_ACCEPT;
        entry->state = STATE_FIN_WAIT;
        return NF_ACCEPT;

    case STATE_FIN_WAIT:
        if (fin || syn) break;     //cant fin twice
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

    del_entry(entry);
    del_entry(receiver_entry);
    return NF_DROP;
}


//show connection table
ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
    struct klist_iter iter;
    struct klist_node *curr_node;
    struct conn_entry *entry;
    ssize_t len = 0;           //length of already written lines
    
    klist_iter_init(&conns_list, &iter);

    while ((curr_node = klist_next(&iter)) && (len < PAGE_SIZE)) 
    {
        entry = container_of(curr_node, struct conn_entry, node);
        if (entry->state == STATE_LISTEN) continue;     //server did not send syn-ack yet...
        len += scnprintf(buf + len, PAGE_SIZE - len, "%u %u %hu %hu %hu\n", entry->src_ip, 
            entry->dst_ip, entry->src_port, entry->dst_port, entry->state);
    }
    klist_iter_exit(&iter);
	return len;
}

static DEVICE_ATTR(conns, S_IRUGO , display_conns, NULL);

//showing the server ip
ssize_t proxy_show(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
    struct conn_entry *entry;
    __be32 ftp_server_ip = 0;
    __be32 http_server_ip = 0;
    
    entry = ftp_entry;
    ftp_server_ip = entry ? entry->dst_ip : 0;
    
    entry = http_entry;
    http_server_ip = entry ? entry->dst_ip : 0;

	return scnprintf(buf, PAGE_SIZE, "%u %u", ftp_server_ip, http_server_ip);
}


//store: for ftp it stores the data connection, and for http it deletes connection that violates size limits
ssize_t proxy_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
    __be16 new_port;
    struct conn_entry *entry, *sec_entry;
    char prot;

    if (sscanf(buf, "%c %hu", &prot, &new_port) != 2) return -EFAULT;
    switch(prot)
    {
        case 'f':
            entry = ftp_entry;
            if (!entry) return -EFAULT;
            add_conn(entry->dst_ip, entry->src_ip, PORT_20, new_port, STATE_NEW, REASON_PART_OF_CONN, 't');
            add_conn(entry->src_ip, entry->dst_ip, new_port, PORT_20, STATE_LISTEN, REASON_PART_OF_CONN, 't');
            break;
        
        case 'h':
            entry = http_entry;
            if (!entry) return -EFAULT;
            sec_entry = get_conn_entry(entry->dst_ip, entry->src_ip, entry->dst_port, entry->src_port);
            del_entry(entry);
            del_entry(sec_entry);
            break;
        
        default:
            return -EFAULT;
    }
    return count;
}

static DEVICE_ATTR(proxy, S_IRUGO | S_IWUSR , proxy_show, proxy_store);

int init_conns(void)
{
    klist_init(&conns_list, NULL, NULL);

    //create char device
    major_number = register_chrdev(0, DEVICE_NAME_CONN_TAB, &fops);
    if (major_number < 0) return 1;
	
    //class already created in hw4secws
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

    if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_proxy.attr))
    {
        device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
        device_destroy(fw_class, MKDEV(major_number, 0));
        unregister_chrdev(major_number, DEVICE_NAME_CONN_TAB);
        return 1;
    }

    return 0;
}

void release_conns(void)
{
    clean_conns_list();
    device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_proxy.attr);
    device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
    device_destroy(fw_class, MKDEV(major_number, 0));
    unregister_chrdev(major_number, DEVICE_NAME_CONN_TAB);
}