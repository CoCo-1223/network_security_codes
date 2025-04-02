/* ethernet header */
struct ethheader {
    u_char ether_dhost[6]; // Destination MAC
    u_char ether_shost[6]; // Source MAC
    u_short ether_type;
};

/* ip header */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4; // header length(4bit), version(4bit)
    unsigned char iph_tos; // type of service
    unsigned short int iph_len; // length
    unsigned short int iph_ident; // identifier
    unsigned short int iph_flag:3, iph_offset:13; // flags(3bit), offsest(13bit)
    unsigned char iph_ttl; // time-to-live
    unsigned char iph_protocol; // upper-layer protocol
    unsigned short int iph_chksum; // header checksum
    struct in_addr iph_sourceip; // source ip address
    struct in_addr iph_destip; // destination ip address 
};

/* tcp header */
struct tcpheader {
    u_short tcp_sport;  // source port 
    u_short tcp_dport;  // destination port
    u_int tcp_seq;      // sequence number
    u_int tcp_ack;      // acknowledgement number 
    u_char tcp_offset:4, tcp_reserved:4;  // data offset, rsvd
    u_char tcp_flags;
    u_short tcp_win;    // window
    u_short tcp_chksum; // checksum
    u_short tcp_urgptr; // urgent pointer 
};

