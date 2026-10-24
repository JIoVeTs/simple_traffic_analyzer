#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <vector>

// Декодирует заголовок TCP.
class TCP {
public:
    TCP();
    TCP(std::uint16_t sourcePort,
        std::uint16_t destinationPort,
        std::uint32_t sequenceNumber,
        std::uint32_t acknowledgmentNumber,
        std::uint16_t flags,
        std::uint16_t windowSize);

    TCP(const TCP& other);
    TCP& operator=(const TCP& other);
    ~TCP();

    // offset указывает на начало TCP-заголовка в массиве bytes.
    bool decode(const std::vector<std::uint8_t>& bytes,
                std::size_t offset) noexcept;

    void printDecoded(std::ostream& output) const;
    void printDecoded() const;

    std::uint16_t getSourcePort() const noexcept;
    std::uint16_t getDestinationPort() const noexcept;
    std::uint32_t getSequenceNumber() const noexcept;
    std::uint32_t getAcknowledgmentNumber() const noexcept;
    std::size_t getHeaderLength() const noexcept;
    std::uint16_t getFlags() const noexcept;
    std::uint16_t getWindowSize() const noexcept;
    std::uint16_t getChecksum() const noexcept;
    std::uint16_t getUrgentPointer() const noexcept;
    bool isValid() const noexcept;

    void setSourcePort(std::uint16_t value) noexcept;
    void setDestinationPort(std::uint16_t value) noexcept;
    void setSequenceNumber(std::uint32_t value) noexcept;
    void setAcknowledgmentNumber(std::uint32_t value) noexcept;
    void setFlags(std::uint16_t value) noexcept;
    void setWindowSize(std::uint16_t value) noexcept;
    void setChecksum(std::uint16_t value) noexcept;
    void setUrgentPointer(std::uint16_t value) noexcept;

private:
    std::uint16_t sourcePort_;
    std::uint16_t destinationPort_;
    std::uint32_t sequenceNumber_;
    std::uint32_t acknowledgmentNumber_;
    std::uint8_t dataOffsetWords_;
    std::uint16_t flags_;
    std::uint16_t windowSize_;
    std::uint16_t checksum_;
    std::uint16_t urgentPointer_;
    bool valid_;
};
