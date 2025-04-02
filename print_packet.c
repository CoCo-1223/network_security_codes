#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "header.h"

/* TCP Packet Capture */ 
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
			      const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if(ntohs(eth -> ether_type) == 0x0800) { // 0x0800 is IP type 
      struct ipheader * ip = (struct ipheader *)
	      (packet + sizeof(struct ethheader));
      if(ip->iph_protocol == IPPROTO_TCP) { // check TCP Packet 
	int ip_header_len = ip->iph_ihl * 4;
	struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
	
	// Print Ethernet Header(shost/dhost)
	printf("Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
	    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
	    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
	    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
	    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        // print IP Header(srcip/dstip)
        printf("IP: %s -> %s \n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
	// print TCP Header(tcp_sport, tcp_dport)
	printf("TCP: %d -> %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));
  	
	// print Message 
	const u_char *data = packet + sizeof(struct ethheader) + ip_header_len + tcp->tcp_offset * 4; // calculate message 
	int data_len = header->caplen - (data-packet);
	printf("Message (%d bytest): ", data_len);
	for(int i = 0; i < data_len; i++) {
		printf("%c", isprint(data[i]) ? data[i]: '.');
	}
	printf("\n");

      }
  }
}	

int main() {
   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program fp;
   bpf_u_int32 net;

   // Step1: Open live pcap session on NIC with name enp0s1
   handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);

   // Step2: Compile filter_exp into BPF pseudo-code
   char filter_exp[] = "tcp port 80";

   // Step3: Capture packets
   pcap_loop(handle, -1, got_packet, NULL);
   pcap_close(handle); // Close the handle
   return 0;
}


