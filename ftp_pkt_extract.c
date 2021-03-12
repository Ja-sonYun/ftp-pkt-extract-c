#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_S 2000
#define File_statue_okay "150"
#define PORT "PORT"
#define TCP_PROTOCOL 6
#define FTP_PORT 0x1500
#define RAISE_ERR(str) { printf("*** ERR: "str"\n"); return 1; }
#define DATA_PORT_DEL ','

int sock_raw;
int pckt_l = 0;
struct sockaddr_in src, dst;

uint32_t last_src_addr = 0;
int data_port[7]; // RFC959 DATA PORT, last is calculated port number
int got_port = 0;

void parse_data_port(char *buf)
{
	char ascii_num[3];

	buf += 5; // PORT FF,FF,FF...
		  //      ^-- move pointer to here
	int s_s = 0;
	int field = 0;

	while (field < 6)
	{
		if (buf[0] == DATA_PORT_DEL || s_s == 3)
		{
			data_port[field] = atoi(ascii_num);
			memset(ascii_num, 0, 3);
			s_s = 0;
			field++;
		}
		else
		{
			ascii_num[s_s] = buf[0];
			s_s++;
		}
		buf++;
	}

	data_port[6] = data_port[5] * 4 + data_port[4] * 255;
}

void proc_pckt(unsigned char *buffer, int size)
{
	struct iphdr *iph = (struct iphdr*)buffer;
	unsigned short iphdr_l = iph->ihl * 4;
	unsigned char *payload;
	struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_l);

	pckt_l++;

	if (iph->protocol != TCP_PROTOCOL) // filtering tcp
		return;

	payload = buffer + iphdr_l + tcph->doff * 4;
	if (tcph->dest == FTP_PORT)
	{
		char prtcl_code[4];
		memcpy(prtcl_code, payload, 4);
		if (!strncmp(prtcl_code, File_statue_okay, 3)) // compare status code
		{
			printf("someone trying to download from ftp server with code %s\n", prtcl_code);
			last_src_addr = iph->saddr;
		}
		else if (!strcmp(prtcl_code, PORT) && !got_port)
		{
			parse_data_port(payload);
			printf("got port for data communication. %d.%d.%d.%d, %d:%d, rp:%d\n", data_port[0], data_port[1],
					data_port[2], data_port[3], data_port[4], data_port[5], data_port[6]);
		}
	}

	if (last_src_addr)
	{
		memset(&src, 0, sizeof(src));
		memset(&dst, 0, sizeof(dst));
		src.sin_addr.s_addr = iph->saddr;
		dst.sin_addr.s_addr = iph->daddr;
	}
}

int main()
{
	int saddr_size, data_size;
	struct sockaddr sckaddr;
	struct in_addr inaddr;

	unsigned char *buffer = (unsigned char*)malloc(2000);

	printf("running..\n");

	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock_raw < 0)
		RAISE_ERR("socket()");

	for (;;)
	{
		saddr_size = sizeof(sckaddr);

		data_size = recvfrom(sock_raw, buffer, BUF_S, 0, &sckaddr, &saddr_size);
		if (data_size < 0)
			RAISE_ERR("recvfrom()");
		proc_pckt(buffer, data_size);
	}
}

