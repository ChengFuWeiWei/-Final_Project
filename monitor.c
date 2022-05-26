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
#define SIP "192.168.42.143"
#define DIP "192.168.42.138"

static struct nf_hook_ops nfho;     // net filter hook option struct 
struct sk_buff *sock_buff;          // socket buffer used in linux kernel
struct udphdr *udp_header;          // udp header struct (not used)
struct iphdr *ip_header;            // ip header struct
struct ethhdr *mac_header;          // mac header struct
struct tcphdr *tcp_header;          // tcp header struct
unsigned int sport,dport;
ktime_t diff, prev = 0;
int index = -1;
unsigned int delay_table[SIZE - 1] = {1600000000, 1600000000, 1600000000};
unsigned int time_table[SIZE];
MODULE_DESCRIPTION("Print Packet Info");
MODULE_LICENSE("GPL");

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
		if(ip_header->saddr == in_aton(SIP) && ip_header->daddr == in_aton(DIP)){
			__net_timestamp(sock_buff);
			printk(KERN_INFO "src_ip: %pI4 \n", &ip_header->saddr);
			printk(KERN_INFO "dst_ip: %pI4\n", &ip_header->daddr);
			printk(KERN_INFO"TCP ports: source: %d, dest: %d .\n",sport,dport);
			printk(KERN_INFO "ttl: %u \n", ip_header->ttl);
			printk(KERN_INFO "Time tamp: %lld ns\n",sock_buff->tstamp);
			time_table[++index] = sock_buff->tstamp;
			
			if(index == (SIZE - 1)){
				int i;
				index = -1;
				for(i = 1 ;i < SIZE; i++){
					diff = time_table[i] - time_table[i- 1];
					if(diff <= delay_table[i - 1]){
						printk(KERN_INFO"Good Delay \n");	
					}
					else{
						printk(KERN_INFO"Bad Delay \n");
						//memset(time_table, 0, SIZE);
						//return NF_DROP;
					}
				}
				memset(time_table, 0, SIZE);
			}
			else{
				printk(KERN_INFO"Queue packet");
			}
			
			printk(KERN_INFO "---------------------------------------\n");	
		}
		
		
	}	
      	
	
	return NF_ACCEPT;
}
 
int init_module()
{
        nfho.hook = hook_func;
        //nfho.hooknum = 4; //NF_INET_PRE_ROUTING=0(capture ICMP Request.)  NF_INET_POST_ROUTING=4(capture ICMP reply.)
	//nfho.hooknum = NF_INET_POST_ROUTING;         /* received packets */
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