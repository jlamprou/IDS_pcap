#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>


typedef struct tcphdr tcphdr;

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main() {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open capture file for offline processing
    descr = pcap_open_offline("ADD_YOUR_FILE.pcap", errbuf);
    if (descr == NULL) {
        printf("pcap_open_live() failed: %s", errbuf);
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed: %s", pcap_geterr(descr));
        return 1;
    }

    printf("capture finished");

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort,filesourcePort, filedestPort;
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char* fileSRCIP,*fileDESTIP;
    char *fileHeader;
    char *message;
    int i = 0;

    fp = fopen("alert.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);


    ethernetHeader = (struct ether_header *) packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *) (packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            while ((read = getline(&line, &len, fp)) != -1) {
                i=0;
                char *token = strtok(line, "\"");
                fileHeader = token;
                token = strtok(NULL, "\"");
                message = token;
                token = strtok(fileHeader," ");
                while (token){
                    if (i==0)
                        fileSRCIP=token;
                    else if(i==1)
                        filesourcePort= atoi(token);
                    else if(i==2)
                        fileDESTIP=token;
                    else if (i==3)
                        filedestPort= atoi(token);
                    token = strtok(NULL, " ");
                    i++;
                }
                if (strcmp(sourceIp,fileSRCIP)==0 && sourcePort==filesourcePort && strcmp(destIp,fileDESTIP)==0 && destPort==filedestPort)
                    printf("ALERT: %s\n",message);
            }

        }
//        // print the results
//        printf("%s : %d -> %s : %d\n", sourceIp, sourcePort, destIp, destPort);
    }
}

