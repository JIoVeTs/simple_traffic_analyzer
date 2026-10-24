#pragma once

#include "Packet.h"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

// Класс управляет файлом формата classic pcap, хранит прочитанные пакеты
// и собирает по ним статистику.
class PacketSequence {
public:
    // Конструкторы и деструктор.
    PacketSequence();
    explicit PacketSequence(const std::string& filePath);
    PacketSequence(const PacketSequence& other);
    ~PacketSequence();

    // Открывает classic pcap-файл и считывает его глобальный заголовок.
    // Возвращает false, если файл не удалось открыть или формат не распознан.
    bool open(const std::string& filePath);

    // Считывает все записи пакетов из уже открытого файла.
    // Возвращает false при ошибке или повреждённой записи.
    bool readAll();

    // Закрывает файл. Уже прочитанные пакеты остаются в объекте.
    void close() noexcept;

    // Печатает сводную статистику в стандартный поток вывода.
    void printStatistics() const;

    // Возвращает пакет по его номеру, считая нумерацию с 1.
    // Возвращает nullptr, если номер некорректен.
    const Packet* getPacketByNumber(std::size_t packetNumber) const noexcept;

    // Информация о состоянии и статистике.
    bool isOpen() const noexcept;
    std::size_t getPacketCount() const noexcept;
    std::size_t getIPv4Count() const noexcept;
    std::size_t getTCPCount() const noexcept;
    std::size_t getUDPCount() const noexcept;
    std::size_t getMinimumLength() const noexcept;
    std::size_t getMaximumLength() const noexcept;
    double getAverageLength() const noexcept;

    // Информация из глобального заголовка pcap.
    std::uint16_t getPcapVersionMajor() const noexcept;
    std::uint16_t getPcapVersionMinor() const noexcept;
    std::uint32_t getSnapshotLength() const noexcept;
    std::uint32_t getLinkType() const noexcept;
    bool usesNanosecondTimestamps() const noexcept;

private:
    // Считывает и проверяет 24-байтовый глобальный заголовок pcap.
    bool readGlobalHeader();

    // Считает протоколы одного Ethernet-пакета по его байтам.
    void countProtocols(const std::vector<std::uint8_t>& bytes) noexcept;

    // Декодирует целые числа из файла с учётом порядка байтов pcap.
    std::uint16_t decodeUInt16(const std::uint8_t* bytes) const noexcept;
    std::uint32_t decodeUInt32(const std::uint8_t* bytes) const noexcept;

    // Обнуляет статистику перед повторным чтением файла.
    void resetStatistics() noexcept;

private:
    std::ifstream file_;
    std::string filePath_;

    bool littleEndian_;
    bool nanosecondTimestamps_;
    bool globalHeaderRead_;

    std::uint16_t pcapVersionMajor_;
    std::uint16_t pcapVersionMinor_;
    std::uint32_t snapshotLength_;
    std::uint32_t linkType_;

    std::vector<Packet> packets_;

    std::size_t ipv4Count_;
    std::size_t tcpCount_;
    std::size_t udpCount_;
    std::size_t minimumLength_;
    std::size_t maximumLength_;
    std::uint64_t totalLength_;
};
