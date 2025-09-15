#include <fmt/printf.h>
#include "firewall.hpp"
#include "interface.hpp"


int main() {
    ::fmt::print("Start FIREWALL!\n");

    std::shared_ptr<IInterface> input_interface = std::make_unique<Interface>("wlp0s20f3");
    std::shared_ptr<IInterface> output_interface = std::make_unique<Interface>("wlp0s20f3");

    Firewall firewall(input_interface, output_interface);


    return 0;
}
