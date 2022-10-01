#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/genetlink.h>

// network byte format
#define HTTPS_PORT 47873

struct genl_info *cli_info = NULL;
int seq_number = 0; 

struct nav_payload {
	uint8_t mac[6];
	uint32_t saddr;
	uint32_t daddr;
	uint32_t sport;
	uint32_t dport;
};

struct nav_payload nav_payload_t;

enum {
	NAV_UNSPEC,
	NAV_MSG_RECV,
	NAV_MSG_SEND,
	__NAV_MAX
};
#define NAV_MAX (__NAV_MAX + 1)

static struct nla_policy nav_policy[NAV_MAX + 1] = {
	[NAV_MSG_RECV] = { .type = NLA_UNSPEC, .len = sizeof(struct nav_payload) }
};

static struct genl_family nav_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "NAVCM",
	.version = 1,
	.maxattr = NAV_MAX
};

static int recv_from_userspace(struct sk_buff *skb, struct genl_info *info){
	cli_info = kmalloc(sizeof(struct genl_info), GFP_KERNEL);
	if(!cli_info){
		printk("failed to create memory\n");
		return -1;
	}
	memset(cli_info, 0, sizeof(struct genl_info));
	memcpy(cli_info, info, sizeof(struct genl_info));
	return 0;
}

static int send_to_userspace(struct nav_payload *payload){
	struct sk_buff *skb;
	void *msg_hdr;
	if(!cli_info){
		printk("no subscriber to send\n");
		return -1;
	}
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if(!skb){
		printk("Failed to allocate nlmsg\n");
		return -1;
	}
	
	msg_hdr = genlmsg_put(skb, cli_info->snd_portid, seq_number, &nav_family, 0, NAV_MSG_SEND);
	if(!msg_hdr){
		printk("failed to create msg hdr\n");
		nlmsg_free(skb);
		return -1;
	}

	if(nla_put(skb, NAV_MSG_SEND, sizeof(struct nav_payload), payload)){
		printk("failed to put message\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_hdr);
	genlmsg_unicast(genl_info_net(cli_info), skb, cli_info->snd_portid);
	return 0;
}

static struct genl_ops nav_ops[] = {
	{
		.cmd = NAV_MSG_RECV,
		.doit = recv_from_userspace,
		.policy = nav_policy,
	}
};


static unsigned int packet_process_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct ethhdr *eth_h = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;

	if(!skb)
		return NF_ACCEPT;
	
	eth_h = eth_hdr(skb);
	if(!eth_h){
		return NF_ACCEPT;
	}

	iph = (struct iphdr*)skb_network_header(skb);
	if(!iph){
		return NF_ACCEPT;
	}
	// TCP Protocol
	if(iph->protocol == IPPROTO_TCP){
		tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
		if(!tcph){
			return NF_ACCEPT;
		}
		if(tcph->dest == HTTPS_PORT){
			//printk("connection: %pM6, %pI4, %pI4, %u\n", &eth_h->h_source, &iph->saddr, &iph->daddr, ntohs(tcph->dest));
			memset(&nav_payload_t, 0, sizeof(struct nav_payload));
			memcpy(nav_payload_t.mac, eth_h->h_source, 6);
			nav_payload_t.saddr = iph->saddr;
			nav_payload_t.daddr = iph->daddr;
			nav_payload_t.sport = tcph->source;
			nav_payload_t.dport = tcph->dest;
			send_to_userspace(&nav_payload_t);
			
		}
	}
	return NF_ACCEPT;
}	

static struct nf_hook_ops hook_ops = {
	.hook = packet_process_hook,.hook = packet_process_hook,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static int __init parental_control_init(void){
	int ret_val;
	printk("Parental control module init success\n");
	nf_register_hook(&hook_ops);
	printk("hook register success\n");
	ret_val = genl_register_family_with_ops(&nav_family, nav_ops);
	if(ret_val){
		printk("failed to register genl\n");
		return -1;
	}
	return 0;
}

static void __exit parental_control_exit(void){
	nf_unregister_hook(&hook_ops);
	genl_unregister_family(&nav_family);
	printk("Parental control module exit success\n");

}

module_init(parental_control_init);
module_exit(parental_control_exit);

MODULE_AUTHOR("G. Naveen Kumar");
MODULE_DESCRIPTION("Parental control module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
