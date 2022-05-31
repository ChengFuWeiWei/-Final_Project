#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/ktime.h>
#define SIZE 3
#define SIP_1 "192.168.42.143"
#define SIP_2 "192.168.42.111"
#define DIP "192.168.42.138"

static struct nf_hook_ops nfho;     // net filter hook option struct 
struct sk_buff *sock_buff;          // socket buffer used in linux kernel
struct udphdr *udp_header;          // udp header struct (not used)
struct iphdr *ip_header;            // ip header struct
struct ethhdr *mac_header;          // mac header struct
struct tcphdr *tcp_header;          // tcp header struct
unsigned int sport,dport;
ktime_t diff, prev = 0;
struct AP_Info{
    int index;
    unsigned int delay_table[SIZE];
    bool first_in;
    bool b_delay;

};
struct AP_Info AP1 = {
    .index = -1,
    .delay_table = {1600000000, 1600000000, 1600000000},
    .first_in = true,
    .b_delay = false
};
struct AP_Info AP2 = {
    .index = -1,
    .delay_table = {1600000000, 1600000000, 1600000000},
    .first_in = true,
    .b_delay = false
};

MODULE_DESCRIPTION("Monitor Packet");
MODULE_LICENSE("GPL");

void print_info(struct iphdr *ip_header, struct sk_buff *sock_buff ){
	printk(KERN_INFO "src_ip: %pI4 \n", &ip_header->saddr);
	printk(KERN_INFO "dst_ip: %pI4\n", &ip_header->daddr);
	printk(KERN_INFO"TCP ports: source: %d, dest: %d .\n",sport,dport);
	printk(KERN_INFO "ttl: %u \n", ip_header->ttl);
	printk(KERN_INFO "Time tamp: %lld ns\n",sock_buff->tstamp);
	return;
}
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff); //grab network header using accessor
        mac_header = (struct ethhdr *)skb_mac_header(sock_buff);
	tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);
	sport = ntohs((unsigned short int)tcp_header->source); //sport now has the source port
	dport = ntohs((unsigned short int)tcp_header->dest);   //dport now has the dest port
        if(!sock_buff) { return NF_DROP;}
	if(state->hook == NF_INET_PRE_ROUTING){
		if(ip_header->saddr == in_aton(SIP_1) && ip_header->daddr == in_aton(DIP)){
			__net_timestamp(sock_buff);
			if(AP1.first_in && AP1.index == -1 && prev == 0){
				printk(KERN_INFO "First packet input \n");
				print_info(ip_header,sock_buff);
				printk(KERN_INFO "---------------------------------------\n");
				prev = sock_buff->tstamp;
				AP1.index++;
				AP1.first_in = false;
				return NF_ACCEPT;
			}
			else if(AP1.index >= SIZE && !AP1.first_in){
				printk(KERN_INFO "First packet input \n");
				print_info(ip_header,sock_buff);
				printk(KERN_INFO "---------------------------------------\n");
				prev = sock_buff->tstamp;;
				AP1.index = 0;
				AP1.b_delay = false;
				return NF_ACCEPT;
			}
			
			print_info(ip_header,sock_buff);
			diff = sock_buff->tstamp - prev;
			printk(KERN_INFO "Differ Time tamp: %lld ns\n",diff);
			if(!AP1.b_delay && diff <= AP1.delay_table[AP1.index]){
				printk(KERN_INFO"Legal Delay \n");
				AP1.index++;
			}
			else if (diff > AP1.delay_table[AP1.index] || AP1.b_delay){
				printk(KERN_INFO"Illegal Delay and Drop it \n");
				AP1.b_delay = true;
				AP1.index++;
				return NF_DROP;
			}
			prev = sock_buff->tstamp;
			printk(KERN_INFO "---------------------------------------\n");	
		}
		else if(ip_header->saddr == in_aton(SIP_2) && ip_header->daddr == in_aton(DIP)){
			__net_timestamp(sock_buff);
			printk(KERN_INFO "Index: %d \n", AP2.index);
			if(AP2.first_in && AP2.index == -1 && prev == 0){
				printk(KERN_INFO "First packet input \n");
		
				print_info(ip_header,sock_buff);
				printk(KERN_INFO "---------------------------------------\n");
				prev = sock_buff->tstamp;
				AP2.index++;
				AP2.first_in = false;
				return NF_ACCEPT;
			}
			else if(AP2.index >= SIZE && !AP2.first_in){
				printk(KERN_INFO "First packet input \n");
				print_info(ip_header,sock_buff);
				printk(KERN_INFO "---------------------------------------\n");
				prev = sock_buff->tstamp;;
				AP2.index = 0;
				AP2.b_delay = false;
				return NF_ACCEPT;
			}
			
			print_info(ip_header,sock_buff);
			diff = sock_buff->tstamp - prev;
			printk(KERN_INFO "Differ Time tamp: %lld ns\n",diff);
			if(!AP2.b_delay && diff <= AP2.delay_table[AP2.index]){
				printk(KERN_INFO"Legal Delay \n");
				AP2.index++;
			}
			else if (diff > AP2.delay_table[AP2.index] || AP2.b_delay){
				printk(KERN_INFO"Illegal Delay and Drop it \n");
				AP2.b_delay = true;
				AP2.index++;
				return NF_DROP;
			}
			prev = sock_buff->tstamp;
			printk(KERN_INFO "---------------------------------------\n");
		}
			
	}	
      	
	
	return NF_ACCEPT;
}
 
int init_module()
{
        nfho.hook = hook_func;
        nfho.hooknum = NF_INET_PRE_ROUTING  ;             /* Get Time Stamp */
        nfho.pf = PF_INET;//IPV4 packets
        nfho.priority = NF_IP_PRI_FIRST;//set to highest priority over all other hook functions
        nf_register_net_hook(&init_net, &nfho);

        printk(KERN_INFO "---------------------------------------\n");
        printk(KERN_INFO "Loading kernel module...\n");
        return 0;
}
 
void cleanup_module()
{
	printk(KERN_INFO "Cleaning up module.\n");
        nf_unregister_net_hook(&init_net, &nfho);
}
