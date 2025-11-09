#include "fw.h"

static struct nf_hook_ops* post_hook = NULL;
struct conn_entry *ftp_entry = NULL;
struct conn_entry *http_entry = NULL;

// Get ip of an interface given its name
__be32 get_interface_ip(const char *iface_name) {
    struct net_device *dev;
    struct in_device *in_dev;
    __be32 ip = 0;

    // Get the net_device structure for the interface
    dev = dev_get_by_name(&init_net, iface_name);
    if (!dev) {
        pr_err("Interface %s not found\n", iface_name);
        return 0;
    }

    // Get the in_device structure (for IPv4 addresses)
    in_dev = in_dev_get(dev);
    if (in_dev) {
        struct in_ifaddr *ifa;
        ifa = in_dev->ifa_list;
        if (ifa) {
            ip = ifa->ifa_address;  // Get the first assigned IPv4 address
        }
    }

    in_dev_put(in_dev);  // Release the device reference
    return ip;     // IP is in **network byte order**
}

//Fixing checksum after redirecting
int fix_checksum(struct sk_buff *skb)
{
    struct tcphdr *tcp_header;
    struct iphdr *ip_header;
    __u32 tcplen;

    ip_header = ip_hdr(skb);

    /* Fix IP header checksum */
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

    skb->ip_summed = CHECKSUM_NONE;
    skb->csum_valid = 0;

    /* Linearize the skb */
    if (skb_linearize(skb) < 0) return 1;

    /* Re-take headers. The linearize may change skb's pointers */
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    /* Fix TCP header checksum */
    tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));

    return 0;
}

int redirect_to_mitm(struct sk_buff *skb, direction_t direction)
{
    struct tcphdr *tcph;
    struct iphdr *iph;
    struct conn_entry *entry;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);

    switch (direction)
    {
    case DIRECTION_OUT:
        if ((tcph->dest == PORT_21) || (tcph->dest == PORT_80))
        {
            //handle special ports coming from client, send to proxy
            tcph->dest = (tcph->dest == PORT_21) ? PORT_210 : PORT_800;
            iph->daddr = get_interface_ip(IN_NET_DEVICE_NAME);
            if (fix_checksum(skb)) 
            {
                pr_err("could not fix checksum");
                return 1;
            }
        }
        break;
    
    case DIRECTION_IN:
        if ((tcph->source == PORT_21) || (tcph->source == PORT_80))
        {
            //handle special ports coming from server, send to proxy
            entry = get_conn_entry(iph->daddr, iph->saddr, tcph->dest, tcph->source);
            if (!entry) return 1;         //entry was deleted mid-session because of illegal value (e.g size > 100kB)
            iph->daddr = get_interface_ip(OUT_NET_DEVICE_NAME);
            tcph->dest = entry->proxy_port;
            if (fix_checksum(skb)) 
            {
                pr_err("could not fix checksum");
                return 1;
            }
        }
        break;

    default:
        break;
    }
    
    return 0;
}

// Simply redirects packet from proxy if necessary
static unsigned int post_hook_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) 
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct conn_entry *entry;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);      
    if (!iph) return NF_ACCEPT;

    if (!state->out) return NF_ACCEPT;
    if (iph->protocol != PROT_TCP) return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    
    if (!strcmp(state->out->name, OUT_NET_DEVICE_NAME))
    {
        //packet going to server
        if ((tcph->dest != PORT_21) && tcph->dest != PORT_80) return NF_ACCEPT;
        
        entry = (tcph->dest == PORT_21) ? ftp_entry : http_entry;
        if (!entry) return NF_DROP;     // if it doesn't exist, proxy deleted connection
        if (!(entry->proxy_port)) entry->proxy_port = tcph->source;

        //change source to client
        iph->saddr = entry->src_ip;
        tcph->source = entry->src_port;
    }

    else if (!strcmp(state->out->name, IN_NET_DEVICE_NAME))
    {
        // packet going to client, get connection entry made by client
        if ((tcph->source != PORT_210) && (tcph->source != PORT_800)) return NF_ACCEPT;

        entry = (tcph->source == PORT_210) ? ftp_entry : http_entry;
        
        if (!entry) return NF_DROP;     // if it doesn't exist, proxy deleted connection
        iph->saddr = entry->dst_ip;
        tcph->source = entry->dst_port;
    }
    else return NF_ACCEPT;

    if (fix_checksum(skb))
    {
        pr_err("could not fix checksum");
        return NF_DROP;
    }
    return NF_ACCEPT;
}


int init_post_hook(void) 
{   
    //initalizing hook
    post_hook = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (post_hook == NULL) return 1;
    
    //registering hook
    post_hook->hook = (nf_hookfn*)post_hook_handler;
    post_hook->hooknum = NF_INET_LOCAL_OUT;
    post_hook->pf = NFPROTO_IPV4;
    post_hook->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, post_hook);

    return 0;
}


void release_post_hook(void) 
{
	nf_unregister_net_hook(&init_net, post_hook);
    kfree(post_hook);
}

int init_mitm(void)
{
    return init_post_hook();
}

void release_mitm(void)
{
    release_post_hook();
}