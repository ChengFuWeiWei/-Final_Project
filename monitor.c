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
#define SIZE 4
#define SIP_1 "192.168.20.2"
#define SIP_2 "192.168.42.111"
#define DIP "8.8.8.8"

static struct nf_hook_ops nfho;     // net filter hook option struct 
struct sk_buff *sock_buff;          // socket buffer used in linux kernel
struct udphdr *udp_header;          // udp header struct (not used)
struct iphdr *ip_header;            // ip header struct
struct ethhdr *mac_header;          // mac header struct
struct tcphdr *tcp_header;          // tcp header struct
unsigned int sport,dport;
ktime_t diff, prev = 0;
int FT = 10; //represent percent of fault-tolerant
struct AP_Info{
    int index;
    s64 delay_table[SIZE]; // pre-defined
	s64 legal_delay_low[SIZE]; // init in init_module
	s64 legal_delay_high[SIZE]; // init in init_module
};
struct AP_Info AP1 = {
    .index = -1,
    .delay_table = {300000000, 100000000, 200000000,100000000},
	.legal_delay_low = {0,0,0,0},
	.legal_delay_high = {0,0,0,0}
};
struct AP_Info AP2 = {
    .index = -1,
    .delay_table = {100000000, 100000000, 100000000, 100000000},
	.legal_delay_low = {0,0,0,0},
	.legal_delay_high = {0,0,0,0}
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
			if(AP1.index == -1){
				printk(KERN_INFO "First packet input \n");
				print_info(ip_header,sock_buff);
				printk(KERN_INFO "---------------------------------------\n");
				prev = sock_buff->tstamp;
				AP1.index++;
				return NF_ACCEPT;
			}
			
			print_info(ip_header,sock_buff);
			diff = sock_buff->tstamp - prev;
			prev = sock_buff->tstamp;
			printk(KERN_INFO "Differ Time tamp: %lld ns\n",diff);
			AP1.index = (AP1.index + 1)% SIZE;
			if( AP1.legal_delay_low[AP1.index] <=diff && diff <= AP1.legal_delay_high[AP1.index] ){
				printk(KERN_INFO"Legal Delay \n");
				printk(KERN_INFO "---------------------------------------\n");
			}
			else{
				printk(KERN_INFO"Illegal Delay and Drop it \n");
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			}
		}
		else if(ip_header->saddr == in_aton(SIP_2) && ip_header->daddr == in_aton(DIP)){
			__net_timestamp(sock_buff);
			if(AP2.index == -1){
				printk(KERN_INFO "First packet input \n");
				print_info(ip_header,sock_buff);
				printk(KERN_INFO "---------------------------------------\n");
				prev = sock_buff->tstamp;
				AP2.index++;
				return NF_ACCEPT;
			}
			
			print_info(ip_header,sock_buff);
			diff = sock_buff->tstamp - prev;
			prev = sock_buff->tstamp;
			printk(KERN_INFO "Differ Time tamp: %lld ns\n",diff);
			AP2.index = (AP2.index + 1)% SIZE;
			if( AP2.legal_delay_low[AP2.index] <=diff && diff <= AP2.legal_delay_high[AP2.index] ){
				printk(KERN_INFO"Legal Delay \n");
				printk(KERN_INFO "---------------------------------------\n");
			}
			else{
				printk(KERN_INFO"Illegal Delay and Drop it \n");
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			}
		}
			
	}	
	return NF_ACCEPT;
}
 
int init_module()
{
        int i;

		nfho.hook = hook_func;
        nfho.hooknum = NF_INET_PRE_ROUTING  ;             /* Get Time Stamp */
        nfho.pf = PF_INET;//IPV4 packets
        nfho.priority = NF_IP_PRI_FIRST;//set to highest priority over all other hook functions
        nf_register_net_hook(&init_net, &nfho);

		for(i=0;i<SIZE;i++){
			AP1.legal_delay_low[i] = AP1.delay_table[i]-AP1.delay_table[i]*FT/100;
			AP1.legal_delay_high[i] = AP1.delay_table[i]+AP1.delay_table[i]*FT/100;
			AP2.legal_delay_low[i] = AP2.delay_table[i]-AP2.delay_table[i]*FT/100;
			AP2.legal_delay_high[i] = AP2.delay_table[i]+AP2.delay_table[i]*FT/100;
		}
		
		for(i=0;i<SIZE;i++){
			printk(KERN_INFO"%lld %lld \n",AP1.legal_delay_low[i],AP1.legal_delay_high[i]);
		}

        printk(KERN_INFO "---------------------------------------\n");
        printk(KERN_INFO "Loading kernel module...\n");
        return 0;
}
 
void cleanup_module()
{
	printk(KERN_INFO "Cleaning up module.\n");
        nf_unregister_net_hook(&init_net, &nfho);
}
