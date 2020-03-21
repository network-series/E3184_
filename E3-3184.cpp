#define HAVE_REMOTE
#define WIN32
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
typedef struct ip_header 
{
	u_char ver_ihl; // Version (4 bits) + Internet header length(4 bits) 
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset(13 bits) 
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;
typedef struct udp_header
{
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
}udp_header;
int count = 0;
struct timeval old_ts = { 0,0 };
time_t timep;
struct tm *p;
time_t oldtime;
int all_len = 0;
int old_time;
void packet_handler(u_char *param, const struct pcap_pkthdr
	*header, const u_char *pkt_data);
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	u_int netmask;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "ip and udp";
	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs,errbuf) == -1) 
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n",
			errbuf);
		exit(1);
	}
	/* Print the list */
	for (d = alldevs; d; d = d->next) 
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) 
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i) 
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) 
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;
	if (pcap_compile(adhandle, &fcode, "ip", 1, netmask) < 0) 
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0) 
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	time(&timep);
	p = localtime(&timep);
	oldtime = timep;
	old_time = time(&oldtime);
	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);
	pcap_loop(adhandle, 0, packet_handler, NULL);
	system("pause");
	return 0;
}
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	mac_header *mh;
	ip_header *ih;
	time(&timep);
	p = localtime(&timep); 
	printf("%d-%d-%d ", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday);
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("%s ,", timestr);
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header *)(pkt_data + sizeof(mac_header)); //length of ethernet header
	for (int i = 0; i < 6; i++) 
	{
		printf("%02X ", mh->dest_addr[i]);
	}
	printf(",");
	for (int i = 0; i < 4; i++) 
	{
		printf("%d.", ih->saddr[i]);
	}
	printf(",");
	for (int i = 0; i < 6; i++) 
	{
		printf("%02X ", mh->src_addr[i]);
	}
	printf(",");
	for (int i = 0; i < 4; i++)
	{
		printf("%d.", ih->daddr[i]);
	}
	printf(",len:%d\n", header->len);
	printf("\n");
	u_int delay;
	LARGE_INTEGER Bps, Pps;

	/* 以毫秒计算上一次采样的延迟时间 */
	/* 这个值通过采样到的时间戳获得 */
	all_len += header->len;
	if (count != 0)
	{
		if (time(&timep) - old_time > 1) 
		{
			Bps.QuadPart = all_len / (time(&timep) - old_time) * 8;
			printf("BPS=%I64u \n", Bps.QuadPart);
			if (Bps.QuadPart > 1500)
			{
				printf("[");
				printf("%d-%d-%d ", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday);
				printf("%s ", timestr);
				strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
				printf("] ");
				printf("[");
				for (int i = 0; i < 6; i++)
				{
					printf("%02X ", mh->src_addr[i]);
				}
				for (int i = 0; i < 4; i++)
				{
					printf("%d.", ih->saddr[i]);
				}
				printf("] SEND ");
				printf("%I64u", Bps.QuadPart);
				printf(" bytes out of limits\n");

				printf("[");
				printf("%d-%d-%d ", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday);
				printf("%s ", timestr);
				strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
				printf("] ");
				printf("[");
				for (int i = 0; i < 6; i++)
				{
					printf("%02X ", mh->dest_addr[i]);
				}
				for (int i = 0; i < 4; i++)
				{
					printf("%d.", ih->daddr[i]);
				}
				printf("] RECV ");
				printf("%I64u", Bps.QuadPart);
				printf(" bytes out of limits\n");
			}
			all_len = 0;
			old_time = time(&timep);
		}
	}
	old_ts.tv_sec = header->ts.tv_sec;
	old_ts.tv_usec = header->ts.tv_usec;
	count++;
}
