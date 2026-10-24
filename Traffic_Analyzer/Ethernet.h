#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <vector>

// Декодирует заголовок Ethernet II.
class Ethernet {
public:
    using MacAddress = std::array<std::uint8_t, 6>;

    Ethernet();
    Ethernet(const MacAddress& destination,
        const MacAddress& source,
        std::uint16_t etherType);

    Ethernet(const Ethernet& other);
    Ethernet& operator=(const Ethernet& other);
    ~Ethernet();

    // Читает 14-байтовый заголовок начиная с offset.
    // Возвращает false, если данных недостаточно.
    bool decode(const std::vector<std::uint8_t>& bytes,
        std::size_t offset = 0) noexcept;

    void printDecoded(std::ostream& output) const;
    void printDecoded() const;

    const MacAddress& getDestination() const noexcept;
    const MacAddress& getSource() const noexcept;
    std::uint16_t getEtherType() const noexcept;
    std::size_t getHeaderLength() const noexcept;
    bool isValid() const noexcept;

    void setDestination(const MacAddress& address) noexcept;
    void setSource(const MacAddress& address) noexcept;
    void setEtherType(std::uint16_t etherType) noexcept;

private:
    MacAddress destination_;
    MacAddress source_;
    std::uint16_t etherType_;
    bool valid_;
};