#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// Netfilter hook ops struct
static struct nf_hook_ops nfho_in;   // incoming packets

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cemal BOLAT");
MODULE_DESCRIPTION("A simple packet filter from one to another.");

static int procfs_mask = 0;
static struct net_device *dev_in;
static struct net_device *dev_out;
static unsigned long total_bytes = 0;
static unsigned long total_packets = 0;
static unsigned long last_time = 0;
static struct timer_list throughput_timer;

#define IN_INT "enp0s1"
#define OUT_INT "enxf8e43b0f80b3"
#define PROCFS_FILTERS "filter_status_netfilter" // Name of the procfs entry for filters
#define PROCFS_DIR "filter_ctech_netfilter"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file_mask;

#define NO_PASS (0) // Bitmask for no filter (0)
#define TCP_PASS (1 << 0) // Bitmask for TCP filter (1)
#define UDP_PASS (1 << 1) // Bitmask for UDP filter (2)
#define ICMP_PASS (1 << 2) // Bitmask for ICMP filter (4)

static ssize_t proc_read_mask(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
    /*
        I want to give the information table to user about my filter mask.
    */

    char msg[1024] = {0};

    snprintf(msg, sizeof(msg),
            "New filter mask set to %d\n"
            "----Masks----\n"
            "Filter Mask:\n"
            "No Pass: (0) %d\n"
            "TCP Pass: (1) %d\n"
            "UDP Pass: (2) %d\n"
            "ICMP Pass: (4) %d\n",
             procfs_mask,
             procfs_mask == NO_PASS,
             (procfs_mask & TCP_PASS) ? 1 : 0,
             (procfs_mask & UDP_PASS) ? 1 : 0,
             (procfs_mask & ICMP_PASS) ? 1 : 0);

    // Use simple_read_from_buffer instead of manual copy_to_user
    return simple_read_from_buffer(buffer, count, offset, msg, strlen(msg));
}

static ssize_t proc_write_mask(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
    int new_mask;
    char msg[1024] = {0};
    if (kstrtoint_from_user(buffer, count, 10, &new_mask) < 0)
        return -EFAULT;

    int valid_datas[] = {
        NO_PASS,
        TCP_PASS,
        UDP_PASS,
        ICMP_PASS,
    };

    int is_valid = 0;

    for (int i = 0; i < sizeof(valid_datas) / sizeof(valid_datas[0]); i++) {
        if (new_mask == valid_datas[i]) {
            is_valid = 1;
            break;
        }
    }

    if (!is_valid) {
        pr_err("Invalid filter mask value: %d\n", new_mask);
        return -EINVAL;
    }

    procfs_mask = new_mask;
    snprintf(msg, sizeof(msg), 
        "New filter mask set to %d\n"
        "----New Masks----\n"
        "No Pass: (0) %d\n"
        "TCP Pass: (1) %d\n"
        "UDP Pass: (2) %d\n"
        "ICMP Pass: (4) %d\n",
        procfs_mask,
             (procfs_mask == NO_PASS),
             (procfs_mask & TCP_PASS) ? 1 : 0,
             (procfs_mask & UDP_PASS) ? 1 : 0,
             (procfs_mask & ICMP_PASS) ? 1 : 0);

    pr_info("Filter mask set to %d\n", procfs_mask);
    return count;
}

static void log_packet(struct sk_buff *skb) {
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *ip_header;

    if (eth) {
        pr_info("Packet logged:\n");
        pr_info("  Source MAC: %pM\n", eth->h_source);
        pr_info("  Destination MAC: %pM\n", eth->h_dest);
        pr_info("  EtherType: 0x%04X\n", ntohs(eth->h_proto));

        // Check if the packet is an IP packet
        if (skb->protocol == htons(ETH_P_IP)) {
            ip_header = ip_hdr(skb);
            pr_info("  Source IP: %pI4\n", &ip_header->saddr);
            pr_info("  Destination IP: %pI4\n", &ip_header->daddr);
            pr_info("  Protocol: %u\n", ip_header->protocol);
            pr_info("  Device Name: %s\n", skb->dev->name);
            if (ip_header->protocol == IPPROTO_TCP){
                pr_info("  TCP Source Port: %u\n", ntohs(tcp_hdr(skb)->source));
                pr_info("  TCP Destination Port: %u\n", ntohs(tcp_hdr(skb)->dest));
            }
            if (ip_header->protocol == IPPROTO_UDP) {
                pr_info("  UDP Source Port: %u\n", ntohs(udp_hdr(skb)->source));
                pr_info("  UDP Destination Port: %u\n", ntohs(udp_hdr(skb)->dest));
            }
        } else {
            pr_info("  Not an IP packet\n");
        }
    }
}


static const struct proc_ops proc_fops_mask = {
    .proc_read  = proc_read_mask,
    .proc_write = proc_write_mask,
};

static void throughput_timer_callback(struct timer_list *t)
{
    unsigned long now = jiffies;
    unsigned long elapsed_jiffies = now - last_time;
    unsigned long elapsed_ms = jiffies_to_msecs(elapsed_jiffies);

    if (elapsed_ms > 0) {
        unsigned long bytes_per_sec = (total_bytes * 1000) / elapsed_ms;
        unsigned long pkts_per_sec  = (total_packets * 1000) / elapsed_ms;

        unsigned long bit_per_sec = (bytes_per_sec * 8);

        unsigned long kbit_total = bit_per_sec / 1000;          // total kbits
        unsigned long mbit_total = bit_per_sec / 1000000;        // total mbits (1000 * 1000)
        unsigned long gbit_total = mbit_total / 1000;            // total gbits (1000 * 1000 * 1000)

        unsigned long mbit_frac = (bit_per_sec % 1000000) / 100000; // tenths of a Mbit
        unsigned long kbit_frac = (bit_per_sec % 1000) / 100;       // tenths of a Kbit
        unsigned long gbit_frac = (bit_per_sec % 1000000000) / 100000000; // tenths of a Gbit

        /* Primary line: Mbit with one decimal (fallback to Kbit if < 1 Mbit) */
        if (gbit_total > 0) {
            pr_info("[Throughput] %lu.%lu Gbit/sec (%lu.%lu Mbit/sec, %lu.%lu Kbit/sec, %lu bit/sec) pkts=%lu pps=%lu\n",
                gbit_total, gbit_frac,
                mbit_total, mbit_frac,
                kbit_total, kbit_frac,
                bit_per_sec,
                total_packets, pkts_per_sec);
        } else if (kbit_total > 0) {
            pr_info("[Throughput] %lu.%lu Kbit/sec (%lu bit/sec) pkts=%lu pps=%lu\n",
                kbit_total, kbit_frac,
                bit_per_sec,
                total_packets, pkts_per_sec);
        } else {
            pr_info("[Throughput] %lu bit/sec pkts=%lu pps=%lu\n",
                bit_per_sec, total_packets, pkts_per_sec);
        }

        // Reset counters for next interval
        total_bytes = 0;
        total_packets = 0;
        last_time = now;
    }

    // Reschedule timer for next second
    mod_timer(&throughput_timer, jiffies + msecs_to_jiffies(1000));
}


static unsigned int packet_filter_hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    /*
        NF_DROP: Drop the packet
        NF_ACCEPT: Accept the packet
        NF_STOP: Stop processing the packet
        NF_STOLEN: The packet has been taken over by another handler
        NF_QUEUE: Queue the packet for later processing
    */

    struct iphdr *ip_header = NULL;
    struct ethhdr *eth = NULL;

    int can_pass = 0;

    if (!skb)
        return NF_DROP;
    eth = eth_hdr(skb);

    if (!eth)
        return NET_RX_DROP; // if no ethernet header

    if (state->in && strcmp(state->in->name, "lo") == 0){
        total_bytes += skb->len; // Increment total bytes for loopback
        total_packets++; // Increment total packets for loopback
        return NF_ACCEPT;
    }

    // Check if the packet is an IP packet
    if (skb->protocol == htons(ETH_P_IP)) { // ipv4
        ip_header = ip_hdr(skb);
    }

    if (ip_header) {
        if (ip_header->protocol == IPPROTO_TCP) {
            can_pass = (procfs_mask & TCP_PASS) ? 1 : 0;
            if (ntohs(tcp_hdr(skb)->dest) == 22 || ntohs(tcp_hdr(skb)->source) == 22) {
                return NF_ACCEPT;
            }
        } else if (ip_header->protocol == IPPROTO_UDP) {
            can_pass = (procfs_mask & UDP_PASS) ? 1 : 0;
            if (ntohs(udp_hdr(skb)->dest) == 22 || ntohs(udp_hdr(skb)->source) == 22) {
                return NF_ACCEPT;
            }
        } else if (ip_header->protocol == IPPROTO_ICMP) {
            can_pass = (procfs_mask & ICMP_PASS) ? 1 : 0;
        }
    }

    if (state->in && state->in == dev_in){
        if (can_pass == 0) {
            return NF_DROP;
        }
    }

    if (state->in && state->in == dev_out){
        log_packet(skb);
        return NF_ACCEPT; // Allow the packet to be processed normally
    }

    if (can_pass) {
        struct sk_buff *clone = skb_clone(skb, GFP_KERNEL);
        if (!clone) {
            pr_err("Failed to clone skb\n");
            return -ENOMEM;
        }
        clone->dev = dev_out; // Set the output device
        dev_queue_xmit(clone); // Transmit the packet
    }

    return NF_ACCEPT;

}

static int __init packetgger_init(void) {
    // init procfs
    proc_dir = proc_mkdir(PROCFS_DIR, NULL);
    if (!proc_dir) {
        pr_err("Failed to create /proc/%s\n", PROCFS_DIR);
        return -ENOMEM;
    }
    proc_file_mask = proc_create(PROCFS_FILTERS, 0666, proc_dir, &proc_fops_mask);
    if (!proc_file_mask) {
        pr_err("Failed to create /proc/%s/%s\n", PROCFS_DIR, PROCFS_FILTERS);
        proc_remove(proc_dir);
        return -ENOMEM;
    }

    dev_in = dev_get_by_name(&init_net, "enp0s1");
    if (!dev_in){
        proc_remove(proc_file_mask);
        proc_remove(proc_file_mask);
    }
    dev_out = dev_get_by_name(&init_net, "enxf8e43b0f80b3");
    if (!dev_out){
        proc_remove(proc_file_mask);
        proc_remove(proc_file_mask);
        dev_put(dev_in);
        return -ENODEV;
    }
    nfho_in.hook = packet_filter_hook_in;
    nfho_in.hooknum = NF_INET_PRE_ROUTING; // Incoming packets
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FILTER; 

    nf_register_net_hook(&init_net, &nfho_in);

    last_time = jiffies;
    timer_setup(&throughput_timer, throughput_timer_callback, 0);
    mod_timer(&throughput_timer, jiffies + msecs_to_jiffies(1000));
    pr_info("Packet logger module loaded.\n");
    return 0;
}


static void __exit packetgger_exit(void) {
    del_timer_sync(&throughput_timer);
    nf_unregister_net_hook(&init_net, &nfho_in);
    dev_put(dev_in);
    dev_put(dev_out);

    if (proc_file_mask)
        proc_remove(proc_file_mask);
    if (proc_dir)
        proc_remove(proc_dir);

    pr_info("Packet logger module unloaded.\n");
}

module_init(packetgger_init);
module_exit(packetgger_exit);
