#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <netinet/ip.h> 
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>


void get_devices(){
    // Print available devices 
    pcap_if_t *devs,*tmp;
    char error[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&devs,error) == -1) {
        printf("No device found.\n%s", error);
        return;
    }
    for(tmp=devs; tmp; tmp=tmp->next){
        printf("%s\n", tmp->name);
    }
}
pcap_t *session_start(char *dev, char *filter_exp) {
    pcap_t *descr;                  // Session descriptor
    struct bpf_program filter_dev;  // Structure for filtering 
    bpf_u_int32 mask;		        // Netmask
	bpf_u_int32 net;                // Device IP
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer
    
    // Find netmask
    pcap_lookupnet(dev,&net,&mask,errbuf);
    // Open session
    descr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if(descr == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(2);
    }
    // Compile filter string
    if(pcap_compile(descr, &filter_dev, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile(): Error occured while compiling.\n");
        exit(2);
    }
    // Set filter
    if(pcap_setfilter(descr, &filter_dev) == -1) {
        fprintf(stderr, "pcap_setfilter(): Error occured while setting filter up.\n");
        exit(2);
    }

    return descr;
}

void print_pkt(const u_char *packet, int caplen) 
{
    int cnt_bytes = 0, cnt_line = 0, line_number = 0;
    bool last_print = false;
    
    printf("0x0000:  ");

    for(int i=0; i<caplen; i++) {
        cnt_bytes ++;
        cnt_line ++;

        if(cnt_line == 16)
            i -= cnt_bytes; // Decrement i to print ascii after hexa

        if(cnt_line > 16 || last_print) {
            // Print ascii
            if(isprint(packet[i]))
                printf("%c", packet[i]);
            else
                printf(".");
        } else {
            // Print hexa
            printf("%02X ", packet[i]);
        }

        if(cnt_bytes == 16) {
            printf(" ");
            cnt_bytes = 0;
        } else if(cnt_bytes == 8 && !last_print)
            printf(" ");
              
        if(cnt_line == 32) {
            line_number ++;
            printf("\n");
            printf("0x%04d:  ", line_number*10);
            cnt_line = 0;
        }
        if(i == caplen-1 && !last_print) {
            last_print = true;
            i -= cnt_bytes;
        }
    }
    printf("\n");
}

void handle(u_char *args,const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
    struct ip *iph;
    iph = (struct ip *)(packet + 14); //Add header length

    // Set time
    char time_buff[50];
    time_t rawtime;
    time(&rawtime);
    struct tm *timeinfo;
    timeinfo = localtime(&rawtime);
    strftime(time_buff, 50, "%Y-%m-%dT%X", timeinfo);
    struct timeval time;
    gettimeofday(&time, NULL);
   
    if(iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph;
        tcph = (struct tcphdr *)(iph + 4 * iph->ip_hl);
        printf("%s.%d+01:00 ", time_buff, (int)(time.tv_usec / 1000)); //Print time
       
        printf("%s : %d > ", inet_ntoa(iph->ip_src), ntohs(tcph->source));
        printf("%s : %d, ", inet_ntoa(iph->ip_dst), ntohs(tcph->dest));

        printf("length %d bytes\n", pkthdr->caplen); //Print packet length

        // Print packet data
        print_pkt(packet, pkthdr->caplen);

    } else if(iph->ip_p == IPPROTO_UDP) {
        struct tcphdr *udph;
        udph = (struct udphdr *)(iph + 4 * iph->ip_hl);        
        printf("%s.%d+01:00 ", time_buff, (int)(time.tv_usec / 1000)); //Print time
        
        printf("%s : %d > ", inet_ntoa(iph->ip_src), ntohs(udph->source));
        printf("%s : %d, ", inet_ntoa(iph->ip_dst), ntohs(udph->dest));

        printf("length %d bytes\n", pkthdr->caplen); //Print packet length
        
        // Print packet data
        print_pkt(packet, pkthdr->caplen);
    }

}

int main(int argc, char *argv[])
{
    if(argc == 1)
        return 0;

    char *options[] = {"-i", "--interface", "-p", "--tcp", "-t", "--udp", "-u", "--arp", "--icmp", "-n"};
    char *dev;
    int num_packets = 1; //Implicit value

    char filter_expr[100] = "";
    char port_filter[10] = "port ";
    
    for(int i=1; i<argc; i++) {
        if(strcmp(argv[i], "-i")==0 || strcmp(argv[i], "--interface")==0) {
            if(i+1 == argc) { //End of arguments
                get_devices();
                return 0;
            }
            for(int j=0; j<10; j++) {
                if(strcmp(argv[i+1], options[j]) == 0) {
                    get_devices();
                    return 0;
                }
            }
            dev = argv[i+1];
            i++;
        } else if(strcmp(argv[i], "-n")==0 && i+1 < argc) {
            num_packets = atoi(argv[i+1]);
            i++;
        } else if(strcmp(argv[i], "-p")==0 && i+1 < argc) {
            strcat(port_filter, argv[i]);        
        } else if(strcmp(argv[i], "-t")==0 || strcmp(argv[i], "--tcp")==0) {
            strcat(filter_expr, "tcp ");
        } else if(strcmp(argv[i], "-u")==0 || strcmp(argv[i], "--udp")==0) {
            strcat(filter_expr, "udp ");
        } else if(strcmp(argv[i], "-u")==0 || strcmp(argv[i], "--udp")==0) {
            strcat(filter_expr, "udp ");
        } else {
            fprintf(stderr, "Invalid argument found.\n");
            return 1;
        }
    }

    if(strcmp(port_filter, "port ")!=0)
        strcat(filter_expr, port_filter);

    pcap_t *descr = session_start(dev, "");
    if (pcap_datalink(descr) != DLT_EN10MB) { //Header size=14
        fprintf(stderr, "Ethernet headers are not supported on a given device.\n");
        exit(1);
    }   
    pcap_loop(descr, num_packets, handle, 0);

    return 0;
}