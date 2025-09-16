#include "interface.hpp"

#include <endian.h>
#include <fmt/format.h>
#include <memory>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

Interface::Interface(std::string_view name_interface) :
    m_raw_interface{pcap_open_live(name_interface.data(), BUFSIZ, 1, 1000, m_error.data()), pcap_close} {

    if (!m_raw_interface) {
        throw std::runtime_error(::fmt::format("Не удалось открыть устройство {}: {}", name_interface, m_error.data()));
    }

    ::fmt::print("Open device: {}\n", name_interface);
}
void packet_handler(u_char *, pcap_pkthdr const *pkthdr, u_char const *packet) {
    ::fmt::print("===== INFO PACKET L2 =====\n", pkthdr->len);
    ::fmt::print("Packet bytes: {}\n", pkthdr->len);

    auto const l2_header = reinterpret_cast<ether_header const *>(packet);

    uint16_t ether_type = be16toh(l2_header->ether_type);
    ::fmt::print("ether_type: {:#06x}\n", ether_type);

    std::array<uint8_t, 6> mac_src{};
    memcpy(mac_src.data(), l2_header->ether_shost, sizeof l2_header->ether_shost);
    ::fmt::print("MAC SRC: ");
    for (auto const &byte: mac_src) {
        ::fmt::print("{:02x}", byte);
        if (&byte != &mac_src.back()) {
            ::fmt::print(":");
        }
    }
    ::fmt::print("\n");

    std::array<uint8_t, 6> mac_dst{};
    memcpy(mac_dst.data(), l2_header->ether_dhost, sizeof l2_header->ether_dhost);
    ::fmt::print("MAC DST: ");
    for (auto &byte: mac_dst) {
        ::fmt::print("{:02x}", byte);
        if (&byte != &mac_dst.back()) {
            ::fmt::print(":");
        }
    }
    ::fmt::print("\n");

    ::fmt::print("===== END L2 =====\n");


    if (ether_type == ETHERTYPE_IP) {
        ::fmt::print("===== INFO PACKET L3 =====\n", pkthdr->len);

        auto const ip_header = reinterpret_cast<ip const *>(packet + sizeof(ether_header));
        ::fmt::print("Version: {}\n", ip_header->ip_v);
        ::fmt::print("IP header length: {}\n", ip_header->ip_hl * 4);
        ::fmt::print("Type of service: {}\n", ip_header->ip_tos);
        ::fmt::print("Total length: {}\n", be16toh(ip_header->ip_len));
        ::fmt::print("Identification: {}\n", be16toh(ip_header->ip_id));
        ::fmt::print("TTL: {}\n", ip_header->ip_ttl);
        ::fmt::print("Protocol: {}\n", ip_header->ip_p);
        ::fmt::print("Header checksum: {}\n", be16toh(ip_header->ip_sum));

        auto fragment_field = be16toh(ip_header->ip_off);
        bool reserved_flag = (fragment_field & IP_RF) != 0;
        bool dont_fragment_flag = (fragment_field & IP_DF) != 0;
        bool more_fragments_flag = (fragment_field & IP_MF) != 0;
        ::fmt::print("RF[{}] DF[{}] MF[{}]\n", reserved_flag, dont_fragment_flag, more_fragments_flag);

        ::fmt::print("IP SRC: {}\n", inet_ntoa(ip_header->ip_src));
        ::fmt::print("IP DST: {}\n", inet_ntoa(ip_header->ip_dst));

        ::fmt::print("===== END L3 =====\n");
    }
    if (ether_type == ETHERTYPE_ARP) {
        ::fmt::print("(ARP) ether_type: {:#06x}\n", ether_type);
    }
}

void Interface::read() { pcap_loop(m_raw_interface.get(), 0, packet_handler, NULL); }
void Interface::write(IPacket const &packet) {}
