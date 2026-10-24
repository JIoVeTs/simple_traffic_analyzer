#include "UDP.h"

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

} // namespace

UDP::UDP()
    : sourcePort_(0),
      destinationPort_(0),
      length_(0),
      checksum_(0),
      valid_(false) {
}

UDP::UDP(std::uint16_t sourcePort,
         std::uint16_t destinationPort,
         std::uint16_t length,
         std::uint16_t checksum)
    : sourcePort_(sourcePort),
      destinationPort_(destinationPort),
      length_(length),
      checksum_(checksum),
      valid_(length >= 8) {
}

UDP::UDP(const UDP& other) = default;

UDP& UDP::operator=(const UDP& other) = default;

UDP::~UDP() = default;

bool UDP::decode(const std::vector<std::uint8_t>& bytes,
                 std::size_t offset) noexcept {
    constexpr std::size_t udpHeaderLength = 8;
    valid_ = false;

    if (offset > bytes.size() || bytes.size() - offset < udpHeaderLength) {
        return false;
    }

    sourcePort_ = readBigEndian16(bytes, offset);
    destinationPort_ = readBigEndian16(bytes, offset + 2);
    length_ = readBigEndian16(bytes, offset + 4);
    checksum_ = readBigEndian16(bytes, offset + 6);

    if (length_ < udpHeaderLength) {
        return false;
    }

    valid_ = true;
    return true;
}

void UDP::printDecoded(std::ostream& output) const {
    if (!valid_) {
        output << "UDP: заголовок отсутствует или повреждён.\n";
        return;
    }

    output << "Протокол UDP (User Datagram Protocol)\n"
            << "  Порт источника:      " << sourcePort_ << "\n"
            << "  Порт назначения:     " << destinationPort_ << "\n"
            << "  Длина:               " << length_ << " байт\n";

    const auto oldFlags = output.flags();
    const char oldFill = output.fill();
    output << "  Контрольная сумма:   0x"
            << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << checksum_ << "\n";
    output.flags(oldFlags);
    output.fill(oldFill);
}

void UDP::printDecoded() const {
    printDecoded(std::cout);
}

std::uint16_t UDP::getSourcePort() const noexcept { return sourcePort_; }
std::uint16_t UDP::getDestinationPort() const noexcept { return destinationPort_; }
std::uint16_t UDP::getLength() const noexcept { return length_; }
std::uint16_t UDP::getChecksum() const noexcept { return checksum_; }
std::size_t UDP::getHeaderLength() const noexcept { return 8; }
bool UDP::isValid() const noexcept { return valid_; }

void UDP::setSourcePort(std::uint16_t value) noexcept { sourcePort_ = value; }
void UDP::setDestinationPort(std::uint16_t value) noexcept { destinationPort_ = value; }
void UDP::setLength(std::uint16_t value) noexcept {
    length_ = value;
    valid_ = length_ >= 8;
}
void UDP::setChecksum(std::uint16_t value) noexcept { checksum_ = value; }
