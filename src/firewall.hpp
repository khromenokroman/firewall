#pragma once
#include <memory>

#include "interfaces/interface.hpp"

class Firewall {
public:
    Firewall(std::shared_ptr<IInterface> interface_input, std::shared_ptr<IInterface> interface_output);
    ~Firewall() = default;

private:
    std::shared_ptr<IInterface> m_interface_input;
    std::shared_ptr<IInterface> m_interface_output;
};
