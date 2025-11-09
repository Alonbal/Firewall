#include "fw.h"

static int reset_major, log_major;
static struct device* reset_device;
static struct device* log_device;

static struct klist log_list;
static struct klist_iter *show_iter;        //for list iterations
static struct klist_node *curr_node;        //for list iterations

struct log_entry 
{
    struct klist_node node;     //helps managing logs as a list
    log_row_t row;              //keeps info of logs
};

//logging

int add_log(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, prot_t protocol, __u8 verdict, reason_t reason)
{
    struct klist_iter iter;
    struct log_entry *entry;

    unsigned long time = ktime_get_real_seconds();
    klist_iter_init(&log_list, &iter);

    while ((curr_node = klist_next(&iter)))
    {
        entry = container_of(curr_node, struct log_entry, node);       //get address of the entry
        if ((src_ip == entry->row.src_ip) && (dst_ip == entry->row.dst_ip) && 
            (src_port == entry->row.src_port) && (dst_port == entry->row.dst_port) &&
                (protocol == entry->row.protocol) && (entry->row.action == verdict) && 
                    (entry->row.reason == reason))      //same connection and same action: update
        {
            klist_iter_exit(&iter);
            //modify log
            entry->row.count++;
            entry->row.timestamp = time;
            klist_del(curr_node);
            klist_add_head(curr_node, &log_list);      //sorting logs by time
            return 0;       //log added successfully
        }
    }
    klist_iter_exit(&iter);

    //create a new log entry
    entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
    if (!entry) return 1;
    klist_add_head(&(entry->node), &log_list);
    entry->row.timestamp = time;
    entry->row.protocol = protocol;
    entry->row.action = (unsigned char)verdict;
    entry->row.src_ip = src_ip;
    entry->row.dst_ip = dst_ip;
    entry->row.src_port = src_port;
    entry->row.dst_port = dst_port;
    entry->row.count = 1;
    entry->row.reason = reason;
    return 0;
}

//show_log device

int open_log_dev(struct inode *_inode, struct file *_file)
{
    //same reads should use the same iterator, and curr_node will save the last node 
    
    show_iter = kmalloc(sizeof(struct klist_iter), GFP_KERNEL);
    if (!show_iter) return -EFAULT;

    klist_iter_init(&log_list, show_iter);
    curr_node = klist_next(show_iter);
    return 0;
}

ssize_t show_log_dev(struct file *filp, char *buf, size_t count, loff_t *offp)
{
    log_row_t log_row;
    char new_row[256];
    int written;        //written = number of bytes trying to write
    int len = 0;        //len = number of bytes successfully copied
    
    while (curr_node)
    {
        //write a single log
        
        log_row = container_of(curr_node, struct log_entry, node)->row;
        written = sprintf(new_row, "%lu %u %u %hu %hu %hhu %hhu %d %u\n", log_row.timestamp, 
            log_row.src_ip, log_row.dst_ip, log_row.src_port, log_row.dst_port, log_row.protocol, 
                log_row.action, log_row.reason, log_row.count);
        if (len + written > count) break;       //not writing more than asked
        if (copy_to_user(buf + len, new_row, written)) 
        {
            klist_iter_exit(show_iter);
            kfree(show_iter);
            show_iter = NULL;
            return -EFAULT;
        }
        len += written;
        curr_node = klist_next(show_iter);
    }

    return len;
}

int release_log_dev(struct inode *_inode, struct file *_file)
{
    if (show_iter)
    {
        klist_iter_exit(show_iter);
        kfree(show_iter);
    }
    return 0;
}

static struct file_operations log_fops = {
    .owner = THIS_MODULE,
    .open = open_log_dev,
    .read = show_log_dev,
    .release = release_log_dev    
};

//reset device 

static struct file_operations reset_fops = {
    .owner = THIS_MODULE
};

void klist_clean(void)
{
    struct klist_iter iter;
    struct klist_node *next;
    struct log_entry *entry;

    //we have to get the next element before deleting an element, so we don't mess the iterator
    klist_iter_init(&log_list, &iter);
    curr_node = klist_next(&iter);      //get first element
    if (!curr_node)                     //empty list
    {
        klist_iter_exit(&iter);
        return;
    }
    while ((next = klist_next(&iter)))      //next is always valid inside the loop, releasing curr_node
    {
        entry = container_of(curr_node, struct log_entry, node);
        klist_del(curr_node);
        kfree(entry);
        curr_node = next;
    }       
    //next is null, curr_node is still valid
    klist_iter_exit(&iter);
    entry = container_of(curr_node, struct log_entry, node);
    klist_del(curr_node);
    kfree(entry);
}

ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
    //user should pass "0" to the driver

    int res;
    if (sscanf(buf, "%d", &res) != 1) return -1;
    if (res) return -1;
    klist_clean();
    return count;
}

static DEVICE_ATTR(reset, S_IWUSR , NULL, reset_log);

//initialization and cleanup

int init_log_module(void)
{
    klist_init(&log_list, NULL, NULL);

    reset_major = register_chrdev(0, DEVICE_NAME_LOG, &reset_fops);
    if (reset_major < 0) return 1;

    //class already created in hw3secws
    if (!fw_sysfs_class) 
    {
        unregister_chrdev(reset_major, DEVICE_NAME_LOG);
        return 1;
    }

    //create sysfs device
    reset_device = device_create(fw_sysfs_class, NULL, MKDEV(reset_major, 0), NULL, DEVICE_NAME_LOG);	
    if (IS_ERR(reset_device))
    {
        unregister_chrdev(reset_major, DEVICE_NAME_LOG);
        return 1;
    }

    //create sysfs file attributes	
    if (device_create_file(reset_device, (const struct device_attribute *)&dev_attr_reset.attr))
    {
        device_destroy(fw_sysfs_class, MKDEV(reset_major, 0));
        unregister_chrdev(reset_major, DEVICE_NAME_LOG);
        return 1;
    }

    log_major = register_chrdev(0, CLASS_NAME "_" DEVICE_NAME_LOG, &log_fops);
    if (log_major < 0)
    {
        device_remove_file(reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
        device_destroy(fw_sysfs_class, MKDEV(reset_major, 0));
        unregister_chrdev(reset_major, DEVICE_NAME_LOG);
        return 1;
    }

    //create /dev device
    log_device = device_create(fw_sysfs_class, NULL, MKDEV(log_major, 0), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);	
    if (IS_ERR(log_device))
    {
        unregister_chrdev(log_major, CLASS_NAME "_" DEVICE_NAME_LOG);
        device_remove_file(reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
        device_destroy(fw_sysfs_class, MKDEV(reset_major, 0));
        unregister_chrdev(reset_major, DEVICE_NAME_LOG);
        return 1;
    }

    return 0;
}

void release_log_module(void)
{
    klist_clean();
    device_destroy(fw_sysfs_class, MKDEV(log_major, 0));
    unregister_chrdev(log_major, CLASS_NAME "_" DEVICE_NAME_LOG);
    device_remove_file(reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(fw_sysfs_class, MKDEV(reset_major, 0));
    unregister_chrdev(reset_major, DEVICE_NAME_LOG);
}