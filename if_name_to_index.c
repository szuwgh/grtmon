#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s [interface name]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	unsigned int if_index;
	if_index = if_nametoindex(argv[1]);
	if (if_index == 0)
	{
		fprintf(stderr, "Interface %s : No such device\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	printf("Interface %s : %d\n", argv[1], if_index);

	///* 待转化的整数IP */
	int IP1_Addr, IP2_Addr;
	IP1_Addr = -2097174336;
	IP2_Addr = -2097174336;

	// 法1：提取IP：位移操作
	int addr1_1 = IP1_Addr >> 24; // 提取第一部分IP地址
	IP1_Addr = IP1_Addr << 8;
	int addr1_2 = IP1_Addr >> 24; // 提取第二部分IP地址
	IP1_Addr = IP1_Addr << 8;
	int addr1_3 = IP1_Addr >> 24; // 提取第三部分IP地址
	IP1_Addr = IP1_Addr << 8;
	int addr1_4 = IP1_Addr >> 24; // 提取第四部分IP地址

	// 打印IP地址:结果为"10.67.83.11"
	printf("IP地址(位移操作)为:%d.%d.%d.%d\n", addr1_1, addr1_2, addr1_3, addr1_4);

	// // 法2：提取IP：求余取整
	// int addr2_4 = IP2_Addr % 256; // 提取第一部分IP地址
	// IP2_Addr = IP2_Addr / 256;
	// int addr2_3 = IP2_Addr % 256; // 提取第一部分IP地址
	// IP2_Addr = IP2_Addr / 256;
	// int addr2_2 = IP2_Addr % 256; // 提取第一部分IP地址
	// IP2_Addr = IP2_Addr / 256;
	// int addr2_1 = IP2_Addr % 256; // 提取第一部分IP地址

	// // 打印IP地址:结果为"10.67.83.11"
	// printf("IP地址(求余取整)为:%d.%d.%d.%d\n", addr2_1, addr2_2, addr2_3, addr2_4);

	struct in_addr daddr;
	inet_pton(AF_INET, "192.168.255.130", &daddr);
	printf("192.168.255.130 to %u\n", daddr.s_addr);

	exit(EXIT_SUCCESS);
}
