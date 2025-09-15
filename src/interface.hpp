#pragma once

#include <array>
#include <memory>
#include <pcap/pcap.h>
#include <string_view>


#include "interfaces/interface.hpp"

class Interface final : public IInterface {
public:
    explicit Interface(std::string_view name_interface);
     ~Interface() override = default;

    IPacket read() override;
    void write(IPacket const &packet) override;

private:
    std::array<char, PCAP_ERRBUF_SIZE> m_error{}; // 256
    std::unique_ptr<pcap_t, void (*)(pcap_t *)> m_raw_interface; // 16

    static_assert(sizeof m_error == 256);
    static_assert(sizeof m_raw_interface == 16);
};
