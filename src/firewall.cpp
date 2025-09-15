#include "firewall.hpp"

Firewall::Firewall(std::shared_ptr<IInterface> interface_input, std::shared_ptr<IInterface> interface_output) :
    m_interface_input{std::move(interface_input)}, m_interface_output{std::move(interface_output)} {}
