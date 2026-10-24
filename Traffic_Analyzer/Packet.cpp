#include "Packet.h"

#include "Ethernet.h"
#include "IPv4.h"
#include "TCP.h"
#include "UDP.h"

#include <iomanip>
#include <iostream>
#include <stdexcept>

Packet::Packet() = default;

Packet::Packet(const std::vector<std::uint8_t>& bytes)
    : data_(bytes) {
}

Packet::Packet(const std::uint8_t* bytes, std::size_t length) {
    if (bytes == nullptr && length != 0) {
        throw std::invalid_argument(
            "Packet: указатель на данные равен nullptr"
        );
    }

    if (length != 0) {
        data_.assign(bytes, bytes + length);
    }
}

Packet::Packet(const Packet& other)
    : data_(other.data_) {
}

Packet& Packet::operator=(const Packet& other) {
    if (this != &other) {
        data_ = other.data_;
    }
    return *this;
}

Packet::~Packet() = default;

std::size_t Packet::getLength() const noexcept {
    return data_.size();
}

const std::vector<std::uint8_t>& Packet::getData() const noexcept {
    return data_;
}

void Packet::setData(const std::vector<std::uint8_t>& bytes) {
    data_ = bytes;
}

void Packet::printHex(std::ostream& output) const {
    const auto oldFlags = output.flags();
    const char oldFill = output.fill();

    output << std::uppercase << std::hex << std::setfill('0');

    for (std::size_t row = 0; row < data_.size(); row += 16) {
        output << std::setw(8) << row << "  ";

        for (std::size_t column = 0; column < 16; ++column) {
            const std::size_t index = row + column;

            if (index < data_.size()) {
                output << std::setw(2)
                    << static_cast<unsigned int>(data_[index]) << ' ';
            }
            else {
                output << "   ";
            }
        }

        output << " |";

        for (std::size_t column = 0; column < 16; ++column) {
            const std::size_t index = row + column;
            if (index >= data_.size()) {
                break;
            }

            const std::uint8_t byte = data_[index];
            const bool printable = byte >= 0x20 && byte <= 0x7E;
            output << (printable ? static_cast<char>(byte) : '.');
        }

        output << "|\n";
    }

    output.flags(oldFlags);
    output.fill(oldFill);
}

void Packet::printHex() const {
    printHex(std::cout);
}

void Packet::printDecoded(std::ostream& output) const {
    if (data_.size() < 14) {
        output << "Packet: недостаточно данных для Ethernet-заголовка.\n";
        return;
    }

    Ethernet ethernet;
    if (!ethernet.decode(data_)) {
        output << "Packet: не удалось декодировать Ethernet-заголовок.\n";
        return;
    }

    ethernet.printDecoded(output);

    if (ethernet.getEtherType() != 0x0800) {
        return;
    }

    IPv4 ipv4;
    const std::size_t ipv4Offset = ethernet.getHeaderLength();
    if (!ipv4.decode(data_, ipv4Offset)) {
        output << "IPv4: заголовок отсутствует или повреждён.\n";
        return;
    }

    ipv4.printDecoded(output);

    const std::size_t ipHeaderLength = ipv4.getHeaderLength();
    const std::size_t transportOffset = ipv4Offset + ipHeaderLength;

    if (ipv4.getProtocol() == 6) {
        TCP tcp;
        if (tcp.decode(data_, transportOffset)) {
            tcp.printDecoded(output);
        }
    } else if (ipv4.getProtocol() == 17) {
        UDP udp;
        if (udp.decode(data_, transportOffset)) {
            udp.printDecoded(output);
        }
    }
}

void Packet::printDecoded() const {
    printDecoded(std::cout);
}
