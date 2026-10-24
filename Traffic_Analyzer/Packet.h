#pragma once


#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <vector>


class Packet {
public:
    Packet();
    explicit Packet(const std::vector<std::uint8_t>& bytes);
    Packet(const std::uint8_t* bytes, std::size_t length);


    Packet(const Packet& other);
    Packet& operator=(const Packet& other);
    ~Packet();


    std::size_t getLength() const noexcept;
    const std::vector<std::uint8_t>& getData() const noexcept;


    void setData(const std::vector<std::uint8_t>& bytes);


    void printHex(std::ostream& output) const;
    void printHex() const;


    // Декодирование протоколов добавим после классов Ethernet, IPv4, TCP и UDP.
    void printDecoded(std::ostream& output) const;
    void printDecoded() const;


private:
    std::vector<std::uint8_t> data_;
};