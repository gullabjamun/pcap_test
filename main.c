#include <pcap.h>
#include "protocol_information.h"
#include "printfunc.h"
    #include <stdio.h>
#include <arpa/inet.h>


     int main(int argc, char *argv[])
     {
        pcap_t *handle;			/* Session handle */
        char *dev;			/* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
        struct bpf_program fp;		/* The compiled filter */
        char filter_exp[] = "port 80";	/* The filter expression */
        bpf_u_int32 mask;		/* Our netmask */
        bpf_u_int32 net;		/* Our IP */
        struct pcap_pkthdr *header;	/* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */

	u_short datalength;
	u_char tcpoff;
	u_char ipoff;
	char ip_dst_str[16];
	char ip_src_str[16];
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	struct sniff_data *data;

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
	while(1)
	{
	      	int res;
		 /* Grab a packet */
      		res=pcap_next_ex(handle, &header,&packet);
      	        if(res==0 || res==-1) continue;
		else if(res==-2) break;
		/* Print its length */

		ethernet=(struct sniff_ethernet*)packet;
		printf("이더넷 목적지 맥주소 : ");
		printinfo((*ethernet).ether_dhost,6);
		printf("이더넷 출발지 맥주소 : ");
		printinfo((*ethernet).ether_shost,6);


	
	if(ntohs((*ethernet).ether_type)==0x0800)
	{
		ip=(struct sniff_ip*)(packet+14);
		
		inet_ntop(AF_INET,&(*ip).ip_src,ip_src_str,16);
		inet_ntop(AF_INET,&(*ip).ip_dst,ip_dst_str,16);
		printf("ip 출발지 주소 : ");
		printf("%s\n",ip_src_str);
		printf("ip 목적지 주소 : ");
		printf("%s\n",ip_dst_str);
		
		ipoff=(*ip).ip_vhl;
		ipoff=ipoff & 0x0F;
		ipoff=ipoff*4;
		


	

		if(ip->ip_p==IPPROTO_TCP)
		{
			tcp=(struct sniff_tcp*)(packet+14+ipoff);
			
			
			printf("출발지 포트 : ");
			printinfo((*tcp).th_sport,2);
			printf("목적지 포트 : ");
			printinfo((*tcp).th_dport,2);
		

			tcpoff=(*tcp).th_offx2;
 			tcpoff = tcpoff >>4;
			tcpoff=tcpoff*4;
			data=(struct sniff_data*)(packet+14+ipoff+tcpoff);
			printf("데이터 값 : ");

			datalength=(*ip).ip_len-ipoff-tcpoff;
			if(datalength>0)
			printinfo((*data).datavalue,datalength > 16 ? 16 : datalength);
			else 
			printf("no data");

	

			printf("\n");
		}
	}	

        /* And close the session */
	}

        pcap_close(handle);
        return(0);
     }
