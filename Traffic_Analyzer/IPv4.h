#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <vector>

// Декодирует заголовок IPv4 внутри массива байтов пакета.
class IPv4 {
public:
    using Address = std::array<std::uint8_t, 4>;

    IPv4();
    IPv4(const Address& source,
        const Address& destination,
        std::uint8_t protocol,
        std::uint16_t totalLength);

    IPv4(const IPv4& other);
    IPv4& operator=(const IPv4& other);
    ~IPv4();

    // offset указывает на начало IPv4-заголовка в bytes.
    // Возвращает false при некорректном или неполном заголовке.
    bool decode(const std::vector<std::uint8_t>& bytes,
        std::size_t offset) noexcept;

    void printDecoded(std::ostream& output) const;
    void printDecoded() const;

    std::uint8_t getVersion() const noexcept;
    std::size_t getHeaderLength() const noexcept;
    std::uint8_t getDscpEcn() const noexcept;
    std::uint16_t getTotalLength() const noexcept;
    std::uint16_t getIdentification() const noexcept;
    std::uint16_t getFlagsAndFragmentOffset() const noexcept;
    std::uint8_t getTTL() const noexcept;
    std::uint8_t getProtocol() const noexcept;
    std::uint16_t getHeaderChecksum() const noexcept;
    const Address& getSource() const noexcept;
    const Address& getDestination() const noexcept;
    bool isValid() const noexcept;

    void setDscpEcn(std::uint8_t value) noexcept;
    void setTotalLength(std::uint16_t value) noexcept;
    void setIdentification(std::uint16_t value) noexcept;
    void setFlagsAndFragmentOffset(std::uint16_t value) noexcept;
    void setTTL(std::uint8_t value) noexcept;
    void setProtocol(std::uint8_t value) noexcept;
    void setHeaderChecksum(std::uint16_t value) noexcept;
    void setSource(const Address& address) noexcept;
    void setDestination(const Address& address) noexcept;

private:
    std::uint8_t version_;
    std::uint8_t headerLengthWords_;
    std::uint8_t dscpEcn_;
    std::uint16_t totalLength_;
    std::uint16_t identification_;
    std::uint16_t flagsAndFragmentOffset_;
    std::uint8_t ttl_;
    std::uint8_t protocol_;
    std::uint16_t headerChecksum_;
    Address source_;
    Address destination_;
    bool valid_;
};
