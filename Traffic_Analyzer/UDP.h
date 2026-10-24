#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <vector>

// Декодирует заголовок UDP.
class UDP {
public:
    UDP();
    UDP(std::uint16_t sourcePort,
        std::uint16_t destinationPort,
        std::uint16_t length,
        std::uint16_t checksum);

    UDP(const UDP& other);
    UDP& operator=(const UDP& other);
    ~UDP();

    // offset указывает на начало UDP-заголовка в массиве bytes.
    bool decode(const std::vector<std::uint8_t>& bytes,
                std::size_t offset) noexcept;

    void printDecoded(std::ostream& output) const;
    void printDecoded() const;

    std::uint16_t getSourcePort() const noexcept;
    std::uint16_t getDestinationPort() const noexcept;
    std::uint16_t getLength() const noexcept;
    std::uint16_t getChecksum() const noexcept;
    std::size_t getHeaderLength() const noexcept;
    bool isValid() const noexcept;

    void setSourcePort(std::uint16_t value) noexcept;
    void setDestinationPort(std::uint16_t value) noexcept;
    void setLength(std::uint16_t value) noexcept;
    void setChecksum(std::uint16_t value) noexcept;

private:
    std::uint16_t sourcePort_;
    std::uint16_t destinationPort_;
    std::uint16_t length_;
    std::uint16_t checksum_;
    bool valid_;
};
