#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

//#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
struct sniff_ip{
	u_char ip_vhl, ip_tos;
	u_short ip_len, ip_id, ip_off;
	u_char ip_ttl, ip_p;
	u_short ip_sum;

	struct in_addr ip_src, ip_dst;
};

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
struct sniff_tcp{
	u_short th_sport, th_dport;
	tcp_seq th_seq, th_ack;
	u_char th_offx2, th_flags;
	u_short th_win, th_sum, th_urp;
};

void usage();
bool checkPacket(const u_char *packet, char *pattern);
void updateTcpChecksum(const u_char *packet);
void updateIpChecksum(const u_char *packet);
u_int sum8(u_int x, u_int y);

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

    char *interface = argv[1];
    char *pattern = argv[2];
    
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

    while(1){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2){
			printf("pacap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        if(checkPacket(packet, pattern)){
            printf("!\n");

            struct sniff_ethernet *ethernet = (struct sniff_ethernet*)packet;
            if(ethernet->ether_type != 0x0008) return 0;

            struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
            if(ip->ip_p != 0x06) return 0;
            u_int size_ip = IP_HL(ip)*4;
            u_short ip_len = ip->ip_len;

            struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            u_int size_tcp = TH_OFF(tcp)*4;

            char *payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            int payload_len = ntohs(ip_len) - (size_ip + size_tcp);

            tcp->th_flags |= 4;

            int originalDataSize = payload_len;

            payload[0] = '\0';
            payload_len = strlen(payload);
            ip->ip_len = htons(size_ip + size_tcp + payload_len);
            header->caplen = 14 + size_ip + size_tcp + payload_len;
            tcp->th_seq = ntohl(htonl(tcp->th_seq) + originalDataSize);

            updateIpChecksum(packet);
            updateTcpChecksum(packet);

            int res = pcap_sendpacket(handle, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                continue;
            }


            tcp->th_flags &= tcp->th_flags^4;
            tcp->th_flags |= 1;

            strcpy(payload, "blocked!!!");
            payload_len = strlen(payload);
            ip->ip_len = htons(size_ip + size_tcp + payload_len);
            header->caplen = 14 + size_ip + size_tcp + payload_len;
            {
            tcp_seq tmp = tcp->th_seq;
            tcp->th_seq = tcp->th_ack;
            tcp->th_ack = tmp;
            }{
/*        	u_char tmp[ETHER_ADDR_LEN];
            strncpy(tmp, ethernet->ether_dhost, ETHER_ADDR_LEN);
            strncpy(ethernet->ether_dhost, ethernet->ether_shost, ETHER_ADDR_LEN);
            strncpy(ethernet->ether_shost, tmp, ETHER_ADDR_LEN);*/
            for(int i=0; i<ETHER_ADDR_LEN; i++){
                u_char tmp = ethernet->ether_dhost[i];
                ethernet->ether_dhost[i] = ethernet->ether_shost[i];
                ethernet->ether_shost[i] = tmp;
            }
            }{
        	struct in_addr tmp = ip->ip_dst;
            ip->ip_dst = ip->ip_src;
            ip->ip_src = tmp;
            }{
        	u_short tmp = tcp->th_dport;
            tcp->th_dport = tcp->th_sport;
            tcp->th_sport = tmp;
            }
            updateIpChecksum(packet);
            updateTcpChecksum(packet);

            res = pcap_sendpacket(handle, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                continue;
            }


            printf("!!\n");


        }

    }

    return 0;
}

void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool checkPacket(const u_char *packet, char *pattern)
{
	struct sniff_ethernet *ethernet = (struct sniff_ethernet*)packet;
    if(ethernet->ether_type != 0x0008) return 0;

	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    if(ip->ip_p != 0x06) return 0;
    u_int size_ip = IP_HL(ip)*4;
    u_short ip_len = ip->ip_len;

	struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    u_int size_tcp = TH_OFF(tcp)*4;

	char *payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	int payload_len = ntohs(ip_len) - (size_ip + size_tcp);

    int pattern_size = strlen(pattern);
    for(int i=0; i<payload_len; i++){
        if(strncmp(payload+i, pattern, pattern_size) == 0){
//            payload[0] = 'W';
/*            for(int j=0; j<payload_len; j++){
                printf("%c", payload[j]);
            }
            printf("\nend...\n");*/
            return true;
        }
    }

    return false;
}

void updateTcpChecksum(const u_char *packet)
{
	struct sniff_ethernet *ethernet = (struct sniff_ethernet*)packet;
    if(ethernet->ether_type != 0x0008) return;

	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    if(ip->ip_p != 0x06) return;
    u_int size_ip = IP_HL(ip)*4;
    u_short ip_len = ip->ip_len;

	struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    u_int size_tcp = TH_OFF(tcp)*4;

	char *payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	int payload_len = ntohs(ip_len) - (size_ip + size_tcp);

    u_int sum1 = 0;
    sum1 = sum8(sum1, ip->ip_src.s_addr >> 16);
    sum1 = sum8(sum1, ip->ip_src.s_addr & 0xffff);
    sum1 = sum8(sum1, ip->ip_dst.s_addr >> 16);
    sum1 = sum8(sum1, ip->ip_dst.s_addr & 0xffff);
    sum1 = sum8(sum1, ip->ip_p << 8);
    sum1 = sum8(sum1, htons(size_tcp + payload_len));

    u_int sum2 = 0;
    tcp->th_sum = 0;
    uint8_t *data = (uint8_t *)tcp;
    for(int i=0; i<size_tcp+payload_len; i+=2){
        sum2 = sum8(sum2, (data[i]) + (data[i+1]<<8));
    }

    tcp->th_sum = sum8(sum1, sum2) ^ 0xffff;
}

void updateIpChecksum(const u_char *packet)
{
	struct sniff_ethernet *ethernet = (struct sniff_ethernet*)packet;
    if(ethernet->ether_type != 0x0008) return;

	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    if(ip->ip_p != 0x06) return;
    u_int size_ip = IP_HL(ip)*4;
    u_short ip_len = ip->ip_len;

	struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    u_int size_tcp = TH_OFF(tcp)*4;

	char *payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	int payload_len = ntohs(ip_len) - (size_ip + size_tcp);

    u_int sum = 0;
    ip->ip_sum = 0;
    uint8_t *data = (uint8_t *)ip;
    for(int i=0; i<size_ip; i+=2){
        sum = sum8(sum, (data[i]) + (data[i+1]<<8));
    }

    ip->ip_sum = sum ^ 0xffff;
}

u_int sum8(u_int x, u_int y)
{
    u_int ans = x+y;
    if(ans > 0xffff) ans += 1;
    ans &= 0xffff;

    return ans;
}