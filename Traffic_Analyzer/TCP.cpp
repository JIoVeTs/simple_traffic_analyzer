#include "TCP.h"

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

std::uint32_t readBigEndian32(const std::vector<std::uint8_t>& bytes,
                              std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

} // namespace

TCP::TCP()
    : sourcePort_(0),
      destinationPort_(0),
      sequenceNumber_(0),
      acknowledgmentNumber_(0),
      dataOffsetWords_(0),
      flags_(0),
      windowSize_(0),
      checksum_(0),
      urgentPointer_(0),
      valid_(false) {
}

TCP::TCP(std::uint16_t sourcePort,
         std::uint16_t destinationPort,
         std::uint32_t sequenceNumber,
         std::uint32_t acknowledgmentNumber,
         std::uint16_t flags,
         std::uint16_t windowSize)
    : sourcePort_(sourcePort),
      destinationPort_(destinationPort),
      sequenceNumber_(sequenceNumber),
      acknowledgmentNumber_(acknowledgmentNumber),
      dataOffsetWords_(5),
      flags_(flags),
      windowSize_(windowSize),
      checksum_(0),
      urgentPointer_(0),
      valid_(true) {
}

TCP::TCP(const TCP& other) = default;

TCP& TCP::operator=(const TCP& other) = default;

TCP::~TCP() = default;

bool TCP::decode(const std::vector<std::uint8_t>& bytes,
                 std::size_t offset) noexcept {
    constexpr std::size_t minimumHeaderLength = 20;
    valid_ = false;

    if (offset > bytes.size() || bytes.size() - offset < minimumHeaderLength) {
        return false;
    }

    dataOffsetWords_ = static_cast<std::uint8_t>(bytes[offset + 12] >> 4);
    const std::size_t headerLength =
        static_cast<std::size_t>(dataOffsetWords_) * 4;
    if (dataOffsetWords_ < 5 || headerLength > bytes.size() - offset) {
        return false;
    }

    sourcePort_ = readBigEndian16(bytes, offset);
    destinationPort_ = readBigEndian16(bytes, offset + 2);
    sequenceNumber_ = readBigEndian32(bytes, offset + 4);
    acknowledgmentNumber_ = readBigEndian32(bytes, offset + 8);
    flags_ = static_cast<std::uint16_t>(
        ((bytes[offset + 12] & 0x01u) << 8) | bytes[offset + 13]);
    windowSize_ = readBigEndian16(bytes, offset + 14);
    checksum_ = readBigEndian16(bytes, offset + 16);
    urgentPointer_ = readBigEndian16(bytes, offset + 18);

    valid_ = true;
    return true;
}

void TCP::printDecoded(std::ostream& output) const {
    if (!valid_) {
        output << "TCP: заголовок отсутствует или повреждён.\n";
        return;
    }

    output << "Протокол TCP (Transmission Control Protocol)\n"
            << "  Порт источника:        " << sourcePort_ << "\n"
            << "  Порт назначения:       " << destinationPort_ << "\n"
            << "  Номер последовательности: " << sequenceNumber_ << "\n"
            << "  Номер подтверждения:   " << acknowledgmentNumber_ << "\n"
            << "  Длина заголовка:       " << getHeaderLength() << " байт\n"
            << "  Флаги:                 ";

    bool first = true;
    const auto printFlag = [&](std::uint16_t mask, const char* name) {
        if ((flags_ & mask) != 0) {
            if (!first) {
                output << ", ";
            }
            output << name;
            first = false;
        }
    };

    printFlag(0x100, "NS");
    printFlag(0x080, "CWR");
    printFlag(0x040, "ECE");
    printFlag(0x020, "URG");
    printFlag(0x010, "ACK");
    printFlag(0x008, "PSH");
    printFlag(0x004, "RST");
    printFlag(0x002, "SYN");
    printFlag(0x001, "FIN");
    if (first) {
        output << "нет";
    }

    output << "\n"
            << "  Размер окна:          " << windowSize_ << "\n";

    const auto oldFlags = output.flags();
    const char oldFill = output.fill();
    output << "  Контрольная сумма:     0x"
            << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << checksum_ << "\n"
            << "  Указатель срочности:  0x"
            << std::setw(4) << urgentPointer_ << "\n";
    output.flags(oldFlags);
    output.fill(oldFill);
}

void TCP::printDecoded() const {
    printDecoded(std::cout);
}

std::uint16_t TCP::getSourcePort() const noexcept { return sourcePort_; }
std::uint16_t TCP::getDestinationPort() const noexcept { return destinationPort_; }
std::uint32_t TCP::getSequenceNumber() const noexcept { return sequenceNumber_; }
std::uint32_t TCP::getAcknowledgmentNumber() const noexcept { return acknowledgmentNumber_; }
std::size_t TCP::getHeaderLength() const noexcept {
    return static_cast<std::size_t>(dataOffsetWords_) * 4;
}
std::uint16_t TCP::getFlags() const noexcept { return flags_; }
std::uint16_t TCP::getWindowSize() const noexcept { return windowSize_; }
std::uint16_t TCP::getChecksum() const noexcept { return checksum_; }
std::uint16_t TCP::getUrgentPointer() const noexcept { return urgentPointer_; }
bool TCP::isValid() const noexcept { return valid_; }

void TCP::setSourcePort(std::uint16_t value) noexcept { sourcePort_ = value; }
void TCP::setDestinationPort(std::uint16_t value) noexcept { destinationPort_ = value; }
void TCP::setSequenceNumber(std::uint32_t value) noexcept { sequenceNumber_ = value; }
void TCP::setAcknowledgmentNumber(std::uint32_t value) noexcept { acknowledgmentNumber_ = value; }
void TCP::setFlags(std::uint16_t value) noexcept { flags_ = value; }
void TCP::setWindowSize(std::uint16_t value) noexcept { windowSize_ = value; }
void TCP::setChecksum(std::uint16_t value) noexcept { checksum_ = value; }
void TCP::setUrgentPointer(std::uint16_t value) noexcept { urgentPointer_ = value; }
