#include <fmt/printf.h>
#include "firewall.hpp"
#include "interface.hpp"


int main() {

    auto input_interface = std::make_shared<Interface>("wlp0s20f3");
    auto output_interface = std::make_shared<Interface>("br-ed92c8c0f7c9");

    Firewall firewall(input_interface, output_interface);
    firewall.run();


    return 0;
}
