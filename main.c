#include <pcap.h>
#include "protocol_information.h"
#include "printfunc.h"
    #include <stdio.h>

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

	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;

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
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
        if(res==0) continue;
	/* Print its length */
        printf("Jacked a packet with length of [%d]\n", (*header).len);
	printf("packet first value %x %x %x %x \n", *packet,*(packet+1),*(packet+2),*(packet+3));

	ethernet=(struct sniff_ethernet*)packet;
	printf("이더넷 목적지 맥주소 : ");
	printinfo((*ethernet).ether_dhost,6);
	printf("이더넷 출발지 맥주소 : ");
	printinfo((*ethernet).ether_shost,6);
	
	if((*ethernet).ether_type==0x8)
	{
		ip=(struct sniff_ip*)(packet+14);
		printf("ip 출발지 주소 : ");
		printinfo((*ip).ip_src,4);
		printf("ip 목적지 주소 : ");
		printinfo((*ip).ip_dst,4);
	}	

        /* And close the session */
	}

        pcap_close(handle);
        return(0);
     }
