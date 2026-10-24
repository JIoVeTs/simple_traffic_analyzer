#include "Ethernet.h"

#include <iomanip>
#include <iostream>
#include <ostream>

namespace {

    void printMacAddress(std::ostream& output,
        const Ethernet::MacAddress& address) {
        const auto oldFlags = output.flags();
        const char oldFill = output.fill();

        output << std::hex << std::uppercase << std::setfill('0');
        for (std::size_t i = 0; i < address.size(); ++i) {
            if (i != 0) {
                output << ':';
            }
            output << std::setw(2) << static_cast<unsigned int>(address[i]);
        }

        output.flags(oldFlags);
        output.fill(oldFill);
    }

    const char* etherTypeName(std::uint16_t etherType) {
        switch (etherType) {
        case 0x0800:
            return "IPv4";
        case 0x0806:
            return "ARP";
        case 0x86DD:
            return "IPv6";
        default:
            return "Unknown";
        }
    }

} // namespace

Ethernet::Ethernet()
    : destination_{},
    source_{},
    etherType_(0),
    valid_(false) {
}

Ethernet::Ethernet(const MacAddress& destination,
    const MacAddress& source,
    std::uint16_t etherType)
    : destination_(destination),
    source_(source),
    etherType_(etherType),
    valid_(true) {
}

Ethernet::Ethernet(const Ethernet& other) = default;

Ethernet& Ethernet::operator=(const Ethernet& other) = default;

Ethernet::~Ethernet() = default;

bool Ethernet::decode(const std::vector<std::uint8_t>& bytes,
    std::size_t offset) noexcept {
    constexpr std::size_t ethernetHeaderSize = 14;

    if (offset > bytes.size() || bytes.size() - offset < ethernetHeaderSize) {
        valid_ = false;
        return false;
    }

    for (std::size_t i = 0; i < destination_.size(); ++i) {
        destination_[i] = bytes[offset + i];
        source_[i] = bytes[offset + 6 + i];
    }

    etherType_ = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset + 12]) << 8) |
        static_cast<std::uint16_t>(bytes[offset + 13]));

    valid_ = true;
    return true;
}

void Ethernet::printDecoded(std::ostream& output) const {
    if (!valid_) {
        output << "Ethernet: заголовок отсутствует или повреждён.\n";
        return;
    }

    output << "Ethernet II\n  MAC назначения: ";
    printMacAddress(output, destination_);
    output << "\n  MAC источника:  ";
    printMacAddress(output, source_);

    const auto oldFlags = output.flags();
    const char oldFill = output.fill();
    output << "\n  EtherType:      0x"
        << std::hex << std::uppercase << std::setfill('0')
        << std::setw(4) << etherType_
        << " (" << etherTypeName(etherType_) << ")\n";
    output.flags(oldFlags);
    output.fill(oldFill);
}

void Ethernet::printDecoded() const {
    printDecoded(std::cout);
}

const Ethernet::MacAddress& Ethernet::getDestination() const noexcept {
    return destination_;
}

const Ethernet::MacAddress& Ethernet::getSource() const noexcept {
    return source_;
}

std::uint16_t Ethernet::getEtherType() const noexcept {
    return etherType_;
}

std::size_t Ethernet::getHeaderLength() const noexcept {
    return 14;
}

bool Ethernet::isValid() const noexcept {
    return valid_;
}

void Ethernet::setDestination(const MacAddress& address) noexcept {
    destination_ = address;
}

void Ethernet::setSource(const MacAddress& address) noexcept {
    source_ = address;
}

void Ethernet::setEtherType(std::uint16_t etherType) noexcept {
    etherType_ = etherType;
}
