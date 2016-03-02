#define _KERNEL_
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/udp.h>

static struct nf_hook_ops netfilter_ops_in;
struct icmphdr *icmp_header;
struct sk_buff *sock_buff;
struct iphdr *ip_header;
static unsigned char *ws_ip = "192.168.10.3";//webserver IP address 
static unsigned char *h1_ip = "192.168.10.1";//host1 IP
static unsigned char *h2_ip = "192.168.10.2";//host2 IP


struct udphdr *udp_header;
struct tcphdr *tcp_header;

unsigned int main_hook(const struct nf_hook_ops *ops,
struct sk_buff *skb,
const struct net_device *in,
const struct net_device *out,
int (*okfn)(struct sk_buff*))
{
	char source[16];
	char dest[16];
	int src_port,dest_port;
	sock_buff=skb;
	if(sock_buff){
		ip_header=(struct iphdr *)skb_network_header(sock_buff);
		snprintf(source, 16, "%pI4", &ip_header->saddr);
		snprintf(dest, 16, "%pI4", &ip_header->daddr);
	}
	else
	{
		printk(KERN_INFO "Some error in Line :%d.\n",__LINE__);
		return NF_ACCEPT;
	}
	if(!sock_buff)
		return NF_ACCEPT;

	//Rule 1
	if(ip_header->protocol == IPPROTO_ICMP){
		icmp_header=(struct icmphdr *)(ip_header+1);
		if(icmp_header){
			/* Rule1 says forward all icmp packets coming from outside going to webserver. */
			/* This inclues icmp packets other than echo request and reply. */
			/* But allow only echo request and replies from webserver to client. */
			if(strcmp(dest,ws_ip)==0)
				return NF_ACCEPT;
			if(icmp_header->type==0){
				//echo reply
				return NF_ACCEPT;
			}else if(icmp_header->type==8){
				//echo request
				//local host should be able to ping outside, assuming localhosts include webserver. 
				if(strcmp(source,ws_ip)==0||strcmp(source,h1_ip)==0||strcmp(source,h2_ip)==0){
					return NF_ACCEPT;
				}else{
					printk(KERN_INFO "DROP: cause: icmp, interface %s, dest %s\n", in->name,dest);
					return NF_DROP;
				}
			}else{
				//other icmp types,drop
				printk(KERN_INFO "DROP: cause: icmp, interface %s, dest %s\n", in->name,dest);
				return NF_DROP;
			}
			
		}else
			return NF_DROP;
	}
	

	if(ip_header->protocol==IPPROTO_TCP){
		//tcp_header = (struct tcphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); 
		src_port = htons(tcp_header->source);
		dest_port = htons(tcp_header->dest);
		//if the packets are coming from eth0, keep them, we dont want to lose connection. 
		if(dest_port==22&&strcmp(in->name,"eth0")!=0){
			printk(KERN_INFO "DROP: cause: ssh, interface %s, dest %s\n", in->name,dest);
			return NF_DROP;
		}
		if(strcmp(dest,ws_ip)!=0){
			//Rule 3
			if(dest_port==80){
				printk(KERN_INFO "DROP: cause: http, interface %s, dest %s\n", in->name,dest);
				return NF_DROP;
			}
		}
	}
	
	return NF_ACCEPT;
}



int init_module(){
printk(KERN_INFO "===========initilize module==========\n");
netfilter_ops_in.hook = main_hook;
netfilter_ops_in.pf = PF_INET;
netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
netfilter_ops_in.priority = NF_IP_PRI_FIRST;

nf_register_hook(&netfilter_ops_in);
return 0;
}
void cleanup_module(){
printk(KERN_INFO "=============unload module==============\n");
nf_unregister_hook(&netfilter_ops_in);
}

