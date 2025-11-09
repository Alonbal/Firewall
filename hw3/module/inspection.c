#include "fw.h"

static struct nf_hook_ops* inspection_hook = NULL;

//returns direction of a packet based on state (rather than ip addresses)
direction_t direction(const struct nf_hook_state *state)
{
    if (state->in)
    {
        if (!strcmp(state->in->name, LOOPBACK_NET_DEVICE_NAME)) return DIRECTION_LO;
        if (!strcmp(state->in->name, OUT_NET_DEVICE_NAME)) return DIRECTION_IN;     //packet comes from eth2 ( = enp0s9)
        if (!strcmp(state->in->name, IN_NET_DEVICE_NAME)) return DIRECTION_OUT;     //packet comes from eth1 ( = enp0s8)
    }
    if (state->out)
    {
        if (!strcmp(state->out->name, LOOPBACK_NET_DEVICE_NAME)) return DIRECTION_LO;
        if (!strcmp(state->out->name, OUT_NET_DEVICE_NAME)) return DIRECTION_OUT;   //packet goes to eth2 ( = enp0s9)
        if (!strcmp(state->out->name, IN_NET_DEVICE_NAME)) return DIRECTION_IN;     //packet goes to eth1 ( = enp0s8)
    }
    
    return DIRECTION_ANY;       //irrelevant direction
}

//hook handler
static unsigned int hook_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) 
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int i;
    rule_t pkt_data;    //for easily saving packet data

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);      //safe because hook is set only for ipv4, thus ipv6 packets will pass
    if (!iph) return NF_ACCEPT;
    
    pkt_data.direction = direction(state);
    if (pkt_data.direction == DIRECTION_LO) return NF_ACCEPT;       

    pkt_data.src_ip = iph->saddr;
    pkt_data.dst_ip = iph->daddr;
    pkt_data.protocol = iph->protocol;
    
    switch (iph->protocol)
    {
    case PROT_TCP:
        tcph = tcp_hdr(skb);
        if (tcph->fin && tcph->urg && tcph->psh)
        {
            add_log(iph->saddr, iph->daddr, tcph->source, tcph->dest, 
                PROT_TCP, NF_DROP, REASON_XMAS_PACKET);
            return NF_DROP;
        }
        pkt_data.src_port = tcph->source;
        pkt_data.dst_port = tcph->dest;
        pkt_data.ack = tcph->ack;
        break;
    
    case PROT_UDP:
        udph = udp_hdr(skb);
        pkt_data.src_port = udph->source;
        pkt_data.dst_port = udph->dest;
        pkt_data.ack = ACK_ANY;     //only for TCP
        break;

    case PROT_ICMP:     //initializing non-garbage data
        pkt_data.src_port = PORT_ANY;       //ICMP has no ports
        pkt_data.dst_port = PORT_ANY;
        pkt_data.ack = ACK_ANY;         //only for TCP
        break;

    default:        //non - TCP/UDP/ICMP
        return NF_ACCEPT;
    }

    //going over the rules, checking for match
    for (i = 0; i < MAX_RULES; i++)
    {
        if (rule_match(pkt_data.direction, pkt_data.src_ip, pkt_data.dst_ip, pkt_data.protocol, 
            pkt_data.src_port, pkt_data.dst_port, pkt_data.ack, i))         //match
        {   
            pkt_data.action = rule_action(i);
            add_log(pkt_data.src_ip, pkt_data.dst_ip, pkt_data.src_port, pkt_data.dst_port, 
                pkt_data.protocol, pkt_data.action, i);
            return pkt_data.action;
        }
    }
    //no match
    add_log(pkt_data.src_ip, pkt_data.dst_ip, pkt_data.src_port, pkt_data.dst_port, 
        pkt_data.protocol, NF_DROP, REASON_NO_MATCHING_RULE);
    return NF_DROP;    
}

//initialization and cleanup

int hook_init(void) 
{   
    //initalizing hook
    inspection_hook = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (inspection_hook == NULL) return 1;
    
    //registering hook
    inspection_hook->hook = (nf_hookfn*)hook_handler;
    inspection_hook->hooknum = NF_INET_FORWARD;
    inspection_hook->pf = NFPROTO_IPV4;
    inspection_hook->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, inspection_hook);

    return 0;
}

//after initializing all hooks
void release_hook(void) 
{
	nf_unregister_net_hook(&init_net, inspection_hook);
    kfree(inspection_hook);
}

int init_inspection(void)
{
    if (hook_init()) return 1;
    return 0;
}

void release_inspection(void)
{
    release_hook();
}