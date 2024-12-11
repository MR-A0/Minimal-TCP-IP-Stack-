#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>

// Ethernet Header
struct ethhdr {
    unsigned char h_dest[6];  // Destination MAC
    unsigned char h_source[6]; // Source MAC
    unsigned short h_proto;   // Protocol (e.g., 0x0800 for IP)
};

// Pseudo header for TCP checksum
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

// Construct Ethernet header
void construct_ethhdr(struct ethhdr *eth, unsigned char *src_mac, unsigned char *dst_mac, unsigned short proto) {
    memcpy(eth->h_source, src_mac, 6);
    memcpy(eth->h_dest, dst_mac, 6);
    eth->h_proto = htons(proto); // Convert protocol to network byte order
}

// Construct IP header
void construct_iphdr(struct iphdr *ip, int data_len, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol) {
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + data_len);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64; // Time to live
    ip->protocol = protocol;
    ip->check = 0; // Set to 0 before checksum
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = checksum(ip, sizeof(struct iphdr));
}

// Construct TCP header
void construct_tcphdr(struct tcphdr *tcp, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags) {
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5; // Header size
    tcp->fin = (flags & 0x01) != 0;
    tcp->syn = (flags & 0x02) != 0;
    tcp->rst = (flags & 0x04) != 0;
    tcp->psh = (flags & 0x08) != 0;
    tcp->ack = (flags & 0x10) != 0;
    tcp->urg = (flags & 0x20) != 0;
    tcp->window = htons(5840); // Window size
    tcp->check = 0; // Checksum (calculated later)
    tcp->urg_ptr = 0;
}

// Calculate TCP checksum
unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int tcp_len) {
    struct pseudo_header psh;
    psh.source_address = ip->saddr;
    psh.dest_address = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = ip->protocol;
    psh.tcp_length = htons(tcp_len);

    int psize = sizeof(struct pseudo_header) + tcp_len;
    unsigned char *pseudogram = malloc(psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, tcp_len);

    unsigned short result = checksum(pseudogram, psize);
    free(pseudogram);
    return result;
}

int main() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Define MAC addresses
    unsigned char src_mac[6] = {0x04, 0x40, 0x47, 0x4d, 0x44, 0x44}; // Replace with your source MAC
    unsigned char dst_mac[6] = {0x67, 0x67, 0x46, 0x46, 0x45, 0x66}; // Broadcast MAC //destination MAC

    // Define IP addresses
    uint32_t src_ip = inet_addr("192.168.11.111 "); // Replace with your IP
    uint32_t dst_ip = inet_addr("192.168.11.121"); // Destination IP

    // Define ports and sequence numbers
    uint16_t src_port = 14545; //source port 
    uint16_t dst_port = 90; // destination port
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0x02; // SYN flag

    // Construct headers
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;

    construct_ethhdr(&eth, src_mac, dst_mac, ETH_P_IP);
    construct_iphdr(&ip, sizeof(struct tcphdr), src_ip, dst_ip, IPPROTO_TCP);
    construct_tcphdr(&tcp, src_port, dst_port, seq, ack, flags);
    tcp.check = tcp_checksum(&ip, &tcp, sizeof(struct tcphdr));

    // Prepare packet
    unsigned char packet[65536];
    memcpy(packet, &eth, sizeof(struct ethhdr));
    memcpy(packet + sizeof(struct ethhdr), &ip, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), &tcp, sizeof(struct tcphdr));

    // Send the packet
    struct sockaddr_ll saddr = {0};
    saddr.sll_ifindex = if_nametoindex("eth0"); // Replace with your interface
    saddr.sll_halen = ETH_ALEN;
    memcpy(saddr.sll_addr, dst_mac, 6);

    if (sendto(sock, packet, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
               (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("Packet send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Packet sent successfully!\n");

    close(sock);
    return 0;
}
