#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void print_information(const u_char *packet,int length){
	struct ether_header *ETH=(struct ether_header *)packet;
	printf("Src MAC : ");
	for(int i=0;i<ETH_ALEN;i++){
		if(i!=0)printf(":");
		printf("%02x",ETH->ether_shost[i]);
	}
	printf("\n");
	printf("Dst MAC : ");
        for(int i=0;i<ETH_ALEN;i++){
                if(i!=0)printf(":");
                printf("%02x",ETH->ether_dhost[i]);
        }        
	printf("\n");

	if(ntohs(ETH->ether_type)==ETHERTYPE_IP){
		length-=sizeof(struct ether_header);
        	packet+=sizeof(struct ether_header);
		struct ip *IP=(struct ip *)packet;
		printf("Src IP : %s\n",inet_ntoa(IP->ip_src));
		printf("Dst IP : %s\n",inet_ntoa(IP->ip_dst));
		if(IP->ip_p==IPPROTO_TCP){
			packet+=IP->ip_hl*4;
			length-=IP->ip_hl*4;
			struct tcphdr *TCP=(struct tcphdr *)packet;
			printf("Src Port : %d\n",ntohs(TCP->th_sport));
			printf("Dst Port : %d\n",ntohs(TCP->th_dport));
			unsigned char *DATA=(unsigned char *)((unsigned char *)TCP+TCP->doff*4);
			length-=TCP->doff*4;
			printf("Data Length : %d\n",length);
			if(length>32)length=32;
			printf("Data : ");
			for(int i=0;i<length;i++)
				printf("%02x ",DATA[i]);
		}
	}
	printf("\n\n");
}
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    print_information(packet,header->caplen);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
