#include "PacketSequence.h"

#include "Ethernet.h"
#include "IPv4.h"

#include <array>
#include <iostream>
#include <limits>
#include <utility>

namespace {

constexpr std::size_t pcapGlobalHeaderSize = 24;
constexpr std::size_t pcapRecordHeaderSize = 16;
constexpr std::uint32_t maximumCapturedPacketSize = 64u * 1024u * 1024u;

} // namespace

PacketSequence::PacketSequence()
    : littleEndian_(true),
      nanosecondTimestamps_(false),
      globalHeaderRead_(false),
      pcapVersionMajor_(0),
      pcapVersionMinor_(0),
      snapshotLength_(0),
      linkType_(0),
      ipv4Count_(0),
      tcpCount_(0),
      udpCount_(0),
      minimumLength_(0),
      maximumLength_(0),
      totalLength_(0) {
}

PacketSequence::PacketSequence(const std::string& filePath)
    : PacketSequence() {
    if (open(filePath)) {
        readAll();
    }
}

// Поток ifstream нельзя копировать. Копия получает уже прочитанные данные,
// но открытый файл ей не передаётся.
PacketSequence::PacketSequence(const PacketSequence& other)
    : filePath_(other.filePath_),
      littleEndian_(other.littleEndian_),
      nanosecondTimestamps_(other.nanosecondTimestamps_),
      globalHeaderRead_(other.globalHeaderRead_),
      pcapVersionMajor_(other.pcapVersionMajor_),
      pcapVersionMinor_(other.pcapVersionMinor_),
      snapshotLength_(other.snapshotLength_),
      linkType_(other.linkType_),
      packets_(other.packets_),
      ipv4Count_(other.ipv4Count_),
      tcpCount_(other.tcpCount_),
      udpCount_(other.udpCount_),
      minimumLength_(other.minimumLength_),
      maximumLength_(other.maximumLength_),
      totalLength_(other.totalLength_) {
}

PacketSequence::~PacketSequence() {
    close();
}

bool PacketSequence::open(const std::string& filePath) {
    close();
    packets_.clear();
    resetStatistics();
    filePath_ = filePath;
    globalHeaderRead_ = false;

    file_.open(filePath_, std::ios::binary);
    if (!file_.is_open()) {
        return false;
    }

    if (!readGlobalHeader()) {
        close();
        return false;
    }
    return true;
}

bool PacketSequence::readAll() {
    if (!file_.is_open() || !globalHeaderRead_) {
        return false;
    }

    packets_.clear();
    resetStatistics();
    file_.clear();
    file_.seekg(static_cast<std::streamoff>(pcapGlobalHeaderSize),
                std::ios::beg);
    if (!file_) {
        return false;
    }

    while (true) {
        std::array<std::uint8_t, pcapRecordHeaderSize> record{};
        file_.read(reinterpret_cast<char*>(record.data()),
                   static_cast<std::streamsize>(record.size()));
        const std::streamsize bytesRead = file_.gcount();

        if (bytesRead == 0 && file_.eof()) {
            return true;
        }
        if (bytesRead != static_cast<std::streamsize>(record.size())) {
            return false; // неполный заголовок записи
        }

        const std::uint32_t capturedLength = decodeUInt32(record.data() + 8);
        const std::uint32_t originalLength = decodeUInt32(record.data() + 12);
        if (capturedLength > maximumCapturedPacketSize ||
            (snapshotLength_ != 0 && capturedLength > snapshotLength_)) {
            return false;
        }

        std::vector<std::uint8_t> bytes(capturedLength);
        if (capturedLength != 0) {
            file_.read(reinterpret_cast<char*>(bytes.data()),
                       static_cast<std::streamsize>(capturedLength));
            if (file_.gcount() != static_cast<std::streamsize>(capturedLength)) {
                return false; // файл закончился внутри пакета
            }
        }

        packets_.emplace_back(bytes);
        const std::size_t packetLength = bytes.size();
        if (packets_.size() == 1 || packetLength < minimumLength_) {
            minimumLength_ = packetLength;
        }
        if (packetLength > maximumLength_) {
            maximumLength_ = packetLength;
        }
        totalLength_ += packetLength;
        countProtocols(bytes);

        // originalLength читается и проверяется форматом, но статистика
        // длины пакета считается по реально сохранённым capturedLength байтам.
        (void)originalLength;
    }
}

void PacketSequence::close() noexcept {
    if (file_.is_open()) {
        file_.close();
    }
}

void PacketSequence::printStatistics() const {
    std::cout << "Файл: " << (filePath_.empty() ? "(не задан)" : filePath_)
              << '\n';
    if (!globalHeaderRead_) {
        std::cout << "Заголовок pcap не прочитан.\n";
        return;
    }

    std::cout << "Формат: classic pcap, версия " << pcapVersionMajor_ << '.'
              << pcapVersionMinor_ << '\n'
              << "Длина снимка (snaplen): " << snapshotLength_ << " байт\n"
              << "Тип канального уровня: " << linkType_;
    if (linkType_ == 1) {
        std::cout << " (Ethernet)";
    }
    std::cout << '\n'
              << "Количество пакетов: " << packets_.size() << '\n'
              << "Минимальная длина: " << minimumLength_ << " байт\n"
              << "Максимальная длина: " << maximumLength_ << " байт\n"
              << "Средняя длина: " << getAverageLength() << " байт\n"
              << "Пакетов IPv4: " << ipv4Count_ << '\n'
              << "Пакетов TCP: " << tcpCount_ << '\n'
              << "Пакетов UDP: " << udpCount_ << '\n';
}

const Packet* PacketSequence::getPacketByNumber(
    std::size_t packetNumber) const noexcept {
    if (packetNumber == 0 || packetNumber > packets_.size()) {
        return nullptr;
    }
    return &packets_[packetNumber - 1];
}

bool PacketSequence::isOpen() const noexcept { return file_.is_open(); }
std::size_t PacketSequence::getPacketCount() const noexcept {
    return packets_.size();
}
std::size_t PacketSequence::getIPv4Count() const noexcept { return ipv4Count_; }
std::size_t PacketSequence::getTCPCount() const noexcept { return tcpCount_; }
std::size_t PacketSequence::getUDPCount() const noexcept { return udpCount_; }
std::size_t PacketSequence::getMinimumLength() const noexcept {
    return minimumLength_;
}
std::size_t PacketSequence::getMaximumLength() const noexcept {
    return maximumLength_;
}
double PacketSequence::getAverageLength() const noexcept {
    if (packets_.empty()) {
        return 0.0;
    }
    return static_cast<double>(totalLength_) /
           static_cast<double>(packets_.size());
}
std::uint16_t PacketSequence::getPcapVersionMajor() const noexcept {
    return pcapVersionMajor_;
}
std::uint16_t PacketSequence::getPcapVersionMinor() const noexcept {
    return pcapVersionMinor_;
}
std::uint32_t PacketSequence::getSnapshotLength() const noexcept {
    return snapshotLength_;
}
std::uint32_t PacketSequence::getLinkType() const noexcept { return linkType_; }
bool PacketSequence::usesNanosecondTimestamps() const noexcept {
    return nanosecondTimestamps_;
}

bool PacketSequence::readGlobalHeader() {
    std::array<std::uint8_t, pcapGlobalHeaderSize> header{};
    file_.read(reinterpret_cast<char*>(header.data()),
               static_cast<std::streamsize>(header.size()));
    if (file_.gcount() != static_cast<std::streamsize>(header.size())) {
        return false;
    }

    // По magic number определяем порядок байтов и точность timestamp.
    if (header[0] == 0xD4 && header[1] == 0xC3 &&
        header[2] == 0xB2 && header[3] == 0xA1) {
        littleEndian_ = true;
        nanosecondTimestamps_ = false;
    } else if (header[0] == 0xA1 && header[1] == 0xB2 &&
               header[2] == 0xC3 && header[3] == 0xD4) {
        littleEndian_ = false;
        nanosecondTimestamps_ = false;
    } else if (header[0] == 0x4D && header[1] == 0x3C &&
               header[2] == 0xB2 && header[3] == 0xA1) {
        littleEndian_ = true;
        nanosecondTimestamps_ = true;
    } else if (header[0] == 0xA1 && header[1] == 0xB2 &&
               header[2] == 0x3C && header[3] == 0x4D) {
        littleEndian_ = false;
        nanosecondTimestamps_ = true;
    } else {
        return false;
    }

    pcapVersionMajor_ = decodeUInt16(header.data() + 4);
    pcapVersionMinor_ = decodeUInt16(header.data() + 6);
    snapshotLength_ = decodeUInt32(header.data() + 16);
    linkType_ = decodeUInt32(header.data() + 20);
    globalHeaderRead_ = true;
    return true;
}

void PacketSequence::countProtocols(
    const std::vector<std::uint8_t>& bytes) noexcept {
    // Эта учебная версия декодирует Ethernet II (pcap link type 1).
    if (linkType_ != 1 || bytes.size() < 14) {
        return;
    }

    Ethernet ethernet;
    if (!ethernet.decode(bytes)) {
        return;
    }

    // Поддерживаем обычный Ethernet II без VLAN-тегов.
    if (ethernet.getEtherType() != 0x0800) {
        return;
    }

    IPv4 ipv4;
    if (!ipv4.decode(bytes, 14)) {
        return;
    }

    ++ipv4Count_;
    if (ipv4.getProtocol() == 6) {
        ++tcpCount_;
    } else if (ipv4.getProtocol() == 17) {
        ++udpCount_;
    }
}

std::uint16_t PacketSequence::decodeUInt16(
    const std::uint8_t* bytes) const noexcept {
    if (littleEndian_) {
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[0]) |
            (static_cast<std::uint16_t>(bytes[1]) << 8));
    }
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[0]) << 8) |
        static_cast<std::uint16_t>(bytes[1]));
}

std::uint32_t PacketSequence::decodeUInt32(
    const std::uint8_t* bytes) const noexcept {
    if (littleEndian_) {
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8) |
               (static_cast<std::uint32_t>(bytes[2]) << 16) |
               (static_cast<std::uint32_t>(bytes[3]) << 24);
    }
    return (static_cast<std::uint32_t>(bytes[0]) << 24) |
           (static_cast<std::uint32_t>(bytes[1]) << 16) |
           (static_cast<std::uint32_t>(bytes[2]) << 8) |
           static_cast<std::uint32_t>(bytes[3]);
}

void PacketSequence::resetStatistics() noexcept {
    ipv4Count_ = 0;
    tcpCount_ = 0;
    udpCount_ = 0;
    minimumLength_ = 0;
    maximumLength_ = 0;
    totalLength_ = 0;
}
