#pragma once
#include <cstddef>

class IPacket {
public:
    virtual ~IPacket() = default;

protected:
    IPacket() = default;
};

class IInterface {
public:
    virtual ~IInterface() = default;

    // virtual IPacket read() = 0;
    virtual void read() = 0;
    virtual void write(IPacket const &packet) = 0;

protected:
    IInterface() = default;
};
