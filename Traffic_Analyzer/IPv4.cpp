#include "IPv4.h"

#include <iomanip>
#include <iostream>
#include <ostream>

namespace {

    std::uint16_t readBigEndian16(const std::vector<std::uint8_t>& bytes,
        std::size_t offset) noexcept {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[offset]) << 8) |
            static_cast<std::uint16_t>(bytes[offset + 1]));
    }

    const char* protocolName(std::uint8_t protocol) noexcept {
        switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 58:
            return "ICMPv6";
        default:
            return "Unknown";
        }
    }

    void printIPv4Address(std::ostream& output, const IPv4::Address& address) {
        output << static_cast<unsigned int>(address[0]) << '.'
            << static_cast<unsigned int>(address[1]) << '.'
            << static_cast<unsigned int>(address[2]) << '.'
            << static_cast<unsigned int>(address[3]);
    }

} // namespace

IPv4::IPv4()
    : version_(0),
    headerLengthWords_(0),
    dscpEcn_(0),
    totalLength_(0),
    identification_(0),
    flagsAndFragmentOffset_(0),
    ttl_(0),
    protocol_(0),
    headerChecksum_(0),
    source_{},
    destination_{},
    valid_(false) {
}

IPv4::IPv4(const Address& source,
    const Address& destination,
    std::uint8_t protocol,
    std::uint16_t totalLength)
    : version_(4),
    headerLengthWords_(5),
    dscpEcn_(0),
    totalLength_(totalLength),
    identification_(0),
    flagsAndFragmentOffset_(0),
    ttl_(0),
    protocol_(protocol),
    headerChecksum_(0),
    source_(source),
    destination_(destination),
    valid_(true) {
}

IPv4::IPv4(const IPv4& other) = default;

IPv4& IPv4::operator=(const IPv4& other) = default;

IPv4::~IPv4() = default;

bool IPv4::decode(const std::vector<std::uint8_t>& bytes,
    std::size_t offset) noexcept {
    constexpr std::size_t minimumHeaderLength = 20;

    valid_ = false;
    if (offset > bytes.size() || bytes.size() - offset < minimumHeaderLength) {
        return false;
    }

    const std::uint8_t versionAndLength = bytes[offset];
    version_ = static_cast<std::uint8_t>(versionAndLength >> 4);
    headerLengthWords_ = static_cast<std::uint8_t>(versionAndLength & 0x0F);

    const std::size_t headerLength =
        static_cast<std::size_t>(headerLengthWords_) * 4;

    if (version_ != 4 || headerLengthWords_ < 5 ||
        headerLength > bytes.size() - offset) {
        return false;
    }

    dscpEcn_ = bytes[offset + 1];
    totalLength_ = readBigEndian16(bytes, offset + 2);
    identification_ = readBigEndian16(bytes, offset + 4);
    flagsAndFragmentOffset_ = readBigEndian16(bytes, offset + 6);
    ttl_ = bytes[offset + 8];
    protocol_ = bytes[offset + 9];
    headerChecksum_ = readBigEndian16(bytes, offset + 10);

    for (std::size_t i = 0; i < source_.size(); ++i) {
        source_[i] = bytes[offset + 12 + i];
        destination_[i] = bytes[offset + 16 + i];
    }

    if (totalLength_ < headerLength) {
        return false;
    }

    valid_ = true;
    return true;
}

void IPv4::printDecoded(std::ostream& output) const {
    if (!valid_) {
        output << "IPv4: заголовок отсутствует или повреждён.\n";
        return;
    }

    output << "Протокол IPv4\n"
        << "  Версия:                  " << static_cast<unsigned int>(version_)
        << "\n"
        << "  Длина заголовка:         " << getHeaderLength() << " байт\n"
        << "  DSCP/ECN:                "
        << static_cast<unsigned int>(dscpEcn_) << "\n"
        << "  Общая длина:            " << totalLength_ << " байт\n";

    const auto oldFlags = output.flags();
    const char oldFill = output.fill();
    output << "  Идентификатор:           0x"
        << std::hex << std::uppercase << std::setfill('0')
        << std::setw(4) << identification_ << "\n"
        << "  Флаги/смещение:         0x"
        << std::setw(4) << flagsAndFragmentOffset_ << "\n";
    output.flags(oldFlags);
    output.fill(oldFill);

    output << "  TTL:                    " << static_cast<unsigned int>(ttl_)
        << "\n"
        << "  Протокол:               "
        << static_cast<unsigned int>(protocol_) << " ("
        << protocolName(protocol_) << ")\n"
        << "  Контрольная сумма:      ";

    output.flags(oldFlags);
    output.fill('0');
    output << "0x" << std::hex << std::uppercase << std::setw(4)
        << headerChecksum_ << std::dec << "\n";
    output.flags(oldFlags);
    output.fill(oldFill);

    output << "  Источник:               ";
    printIPv4Address(output, source_);
    output << "\n  Назначение:             ";
    printIPv4Address(output, destination_);
    output << '\n';
}

void IPv4::printDecoded() const {
    printDecoded(std::cout);
}

std::uint8_t IPv4::getVersion() const noexcept {
    return version_;
}

std::size_t IPv4::getHeaderLength() const noexcept {
    return static_cast<std::size_t>(headerLengthWords_) * 4;
}

std::uint8_t IPv4::getDscpEcn() const noexcept {
    return dscpEcn_;
}

std::uint16_t IPv4::getTotalLength() const noexcept {
    return totalLength_;
}

std::uint16_t IPv4::getIdentification() const noexcept {
    return identification_;
}

std::uint16_t IPv4::getFlagsAndFragmentOffset() const noexcept {
    return flagsAndFragmentOffset_;
}

std::uint8_t IPv4::getTTL() const noexcept {
    return ttl_;
}

std::uint8_t IPv4::getProtocol() const noexcept {
    return protocol_;
}

std::uint16_t IPv4::getHeaderChecksum() const noexcept {
    return headerChecksum_;
}

const IPv4::Address& IPv4::getSource() const noexcept {
    return source_;
}

const IPv4::Address& IPv4::getDestination() const noexcept {
    return destination_;
}

bool IPv4::isValid() const noexcept {
    return valid_;
}

void IPv4::setDscpEcn(std::uint8_t value) noexcept {
    dscpEcn_ = value;
}

void IPv4::setTotalLength(std::uint16_t value) noexcept {
    totalLength_ = value;
}

void IPv4::setIdentification(std::uint16_t value) noexcept {
    identification_ = value;
}

void IPv4::setFlagsAndFragmentOffset(std::uint16_t value) noexcept {
    flagsAndFragmentOffset_ = value;
}

void IPv4::setTTL(std::uint8_t value) noexcept {
    ttl_ = value;
}

void IPv4::setProtocol(std::uint8_t value) noexcept {
    protocol_ = value;
}

void IPv4::setHeaderChecksum(std::uint16_t value) noexcept {
    headerChecksum_ = value;
}

void IPv4::setSource(const Address& address) noexcept {
    source_ = address;
}

void IPv4::setDestination(const Address& address) noexcept {
    destination_ = address;
}
