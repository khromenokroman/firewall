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

    auto l2_header = (ether_header *) packet;
    uint16_t ether_type = be16toh(l2_header->ether_type);

    if (ether_type == ETHERTYPE_IP) {
        ::fmt::print("(IP) ether_type: {:#06x}\n", ether_type);
    }
    if (ether_type == ETHERTYPE_ARP) {
        ::fmt::print("(ARP) ether_type: {:#06x}\n", ether_type);
    }

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

}

void Interface::read() { pcap_loop(m_raw_interface.get(), 0, packet_handler, NULL); }
void Interface::write(IPacket const &packet) {}
