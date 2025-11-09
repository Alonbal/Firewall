#include "fw.h"

//initializations

static rule_t table[MAX_RULES];
static unsigned int last_index;
static int major_number;
static struct device* rules_device = NULL;

static struct file_operations fops = 
{
    .owner = THIS_MODULE
};

//rule matching

int direction_match(direction_t pkt_direction, direction_t rule_direction)
{
    if (rule_direction == DIRECTION_ANY) return 1;
    return (pkt_direction == rule_direction);
    
}

int ack_match(ack_t pkt_ack, ack_t rule_ack)
{
    if (rule_ack == ACK_ANY) return 1;
    if (rule_ack == ACK_YES) return (pkt_ack == 1);
    return (pkt_ack == 0);
    
}

int port_match(__be16 pkt_port, __be16 rule_port)
{
    if (rule_port == PORT_ANY) return 1;
    if (rule_port == PORT_ABOVE_1023) return (pkt_port >= rule_port);
    return (rule_port == pkt_port);
}

int protocol_match(prot_t pkt_prot, prot_t rule_prot)
{
    if (rule_prot == PROT_ANY) return 1;
    if ((rule_prot == PROT_ICMP) || (rule_prot == PROT_UDP) || 
        (rule_prot == PROT_TCP)) return (rule_prot == pkt_prot);
    return 1;
}

int ip_match(__be32 addr, __be32 rule_addr, __be32 prefix_mask)
{
    return ((addr & prefix_mask) == (rule_addr & prefix_mask));
}

int rule_action(int i) 
{
    return table[i].action;
}



int rule_match(direction_t direction, __be32 src_ip, __be32 dst_ip , 
    prot_t protocol , __be16 src_port, __be16 dst_port, ack_t ack, int i)
{
    rule_t *rule;

    if (i >= last_index) return 0;      //rule doesnt exist

    rule = &(table[i]);
    if (!direction_match(direction, rule->direction)) return 0;
    if (!ip_match(src_ip, rule->src_ip, rule->src_prefix_mask)) return 0;
    if (!ip_match(dst_ip, rule->dst_ip, rule->dst_prefix_mask)) return 0;
    if (!protocol_match(protocol, rule->protocol)) return 0;
    switch (protocol)
    {
    case PROT_ICMP:
        break;
    
    case PROT_UDP:
        if (!port_match(src_port, rule->src_port)) return 0;
        if (!port_match(dst_port, rule->dst_port)) return 0;
        break;
    
    case PROT_TCP:        
        if (!port_match(src_port, rule->src_port)) return 0;
        if (!port_match(dst_port, rule->dst_port)) return 0;
        if (!ack_match(ack, rule->ack)) return 0;
        break;

    default:
        break;
    }
    //match
    return 1;
}

//device related

void rule_to_string(rule_t rule, char *line) 
{
    sprintf(line, "%s %x %d %d %d %d %d %d %d %x %d\n",rule.rule_name, 
    rule.direction, rule.src_ip, rule.src_prefix_size, rule.dst_ip, 
    rule.dst_prefix_size, rule.protocol, rule.src_port, rule.dst_port, 
    rule.ack, rule.action);
}

int assign_new_rule(char *str) 
{
    rule_t *rule;
    if (last_index == MAX_RULES) return 1;
    rule = &(table[last_index]);

    if (sscanf(str, "%s %u %u %hhu %u %hhu %hhu %hu %hu %u %hhu", 
    rule->rule_name, (unsigned int *)&(rule->direction), &(rule->src_ip), 
    &(rule->src_prefix_size), &(rule->dst_ip), &(rule->dst_prefix_size), 
    &(rule->protocol), &(rule->src_port), &(rule->dst_port), 
    (unsigned int *)&(rule->ack), &(rule->action)) != 11) return 1;
    
    //validation
    if (strlen(rule->rule_name) > 20) return 1;
    if (rule->direction > DIRECTION_ANY) return 1;
    if (rule->src_prefix_size > 32) return 1;
    if (rule->dst_prefix_size > 32) return 1;
    if ((rule->protocol != PROT_ANY) && (rule->protocol != PROT_OTHER) && (rule->protocol != PROT_ICMP) && 
        (rule->protocol != PROT_UDP) && (rule->protocol != PROT_TCP)) return 1;
    if (rule->src_port > PORT_ABOVE_1023) return 1;
    if (rule->dst_port > PORT_ABOVE_1023) return 1;
    if (rule->ack > ACK_ANY) return 1;
    if (rule->action > NF_ACCEPT) return 1;
    if (rule->src_prefix_size) rule->src_prefix_mask = htonl(~((1 << (32 - rule->src_prefix_size)) - 1));     //calculation that computes mask given size, works for every size except 0
    else rule->src_prefix_mask = 0;
    if (rule->dst_prefix_size) rule->dst_prefix_mask = htonl(~((1 << (32 - rule->dst_prefix_size)) - 1));     //converting to network order since ip is in network order as well
    else rule->dst_prefix_mask = 0;
    return 0;
}

//show
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
    int i;
    ssize_t len = 0;           //length of already written rules
    char line[81] = "";        //80 chars per line is enough, and also 81 * 50 < PAGE_SIZE 
                               //so we can write the whole rule table

    for (i = 0; i < last_index; i++) {
        rule_to_string(table[i], line);         //representing table[i] as a string
        len += scnprintf(buf + len, PAGE_SIZE - len, "%s", line);
    }
	return len;
}

//store
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
    char *line;
    char *buf_copy = kstrdup(buf, GFP_KERNEL);
    if (!buf_copy) return -1;
    last_index = 0;
          
    while ((line = strsep(&buf_copy, "\n")) != NULL)    //splitting to seperate lines
    {
        if (!strcmp(line, "")) continue;     //skip empty lines
        if (assign_new_rule(line)) 
        {   
            kfree(buf_copy);
            return -1;
        }
        last_index++;
    }
    kfree(buf_copy);
    return count;

}

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display_rules, modify_rules);

//initialization and cleanup

int init_rule_table(void)   //returns 0 for success, 1 otherwise
{
    last_index = 0;

    //create char device
    major_number = register_chrdev(0, DEVICE_NAME_RULES, &fops);
    if (major_number < 0)
    {
        return 1;
    }	
        
    //class already created in hw5secws
    if (!fw_class) 
    {
        unregister_chrdev(major_number, DEVICE_NAME_RULES);
        return 1;
    }

    //create sysfs device
    rules_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);	
    if (IS_ERR(rules_device))
    {
        unregister_chrdev(major_number, DEVICE_NAME_RULES);
        return 1;
    }

    //create sysfs file attributes	
    if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
    {
        device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
        unregister_chrdev(major_number, DEVICE_NAME_RULES);
        return 1;
    }

    return 0;
}

void release_rule_table(void) 
{
    device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
    device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
    unregister_chrdev(major_number, DEVICE_NAME_RULES);
}