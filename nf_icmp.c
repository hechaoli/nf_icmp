#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;         //struct holding set of hook function options

uint16_t cal_checksum(const uint8_t *buf, uint32_t len) {
	const uint16_t *w = (uint16_t *)buf;
	uint16_t answer;
	int sum = 0;
	int nleft = len;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(((*w) & 0xFF) << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

unsigned int hook_func(void *priv, struct sk_buff *skb,
  					   const struct nf_hook_state *state)
{
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  if (ip_header->protocol != IPPROTO_ICMP) {
  	return NF_ACCEPT;
  }
  struct icmphdr *icmp_header = (struct icmphdr *)(ip_header + 1);
  if (!icmp_header || icmp_header->type != ICMP_ECHOREPLY) {
  	return NF_ACCEPT;
  }
  unsigned int data_size = skb->len - sizeof(struct iphdr) - sizeof(struct icmphdr);
  if (data_size == 0) {
    return NF_ACCEPT;
  }
  uint8_t* data = (uint8_t *)(icmp_header + 1);
  printk(KERN_INFO "Received ICMP packet: id = %d, seq = %d, data_size = %d\n",
  		 icmp_header->un.echo.id, icmp_header->un.echo.sequence, data_size);
  //icmp_header->un.echo.sequence = htons(123);
  (*data)++;
  icmp_header->checksum = 0;
  icmp_header->checksum = cal_checksum((uint8_t *)icmp_header, skb->len - sizeof(struct iphdr));
  return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{
  printk(KERN_INFO "Loading ICMP hook module\n");
  nfho.hook = hook_func;           //Function to call when conditions below met
  nfho.hooknum = 4;				   //NF_IP_POST_ROUTING (For some reason the macro is not found)
  nfho.pf = PF_INET;               //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST; //set to highest priority over all other hook functions
  nf_register_net_hook(&init_net, &nfho);

  printk(KERN_INFO "Loaded ICMP hook module\n");
  return 0;                             //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  printk(KERN_INFO "Removing ICMP hook module\n");
  nf_unregister_net_hook(&init_net, &nfho);
  printk(KERN_INFO "Removed ICMP hook module\n");
}
