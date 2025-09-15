#include "interface.hpp"

#include <fmt/format.h>
#include <memory>
#include <pcap/pcap.h>

Interface::Interface(std::string_view name_interface) :
    m_raw_interface{pcap_open_live(name_interface.data(), BUFSIZ, 1, 1000, m_error.data()), pcap_close} {

    if (m_raw_interface) {
        throw std::runtime_error(::fmt::format("Не удалось открыть устройство {}: {}", name_interface, m_error.data()));
    }

    ::fmt::print("Open device: {}\n", name_interface);
}
IPacket Interface::read() {}
void Interface::write(IPacket const &packet) {}
