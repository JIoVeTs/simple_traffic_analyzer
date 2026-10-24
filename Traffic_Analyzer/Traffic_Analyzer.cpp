#include "PacketSequence.h"

#include <clocale>
#include <iostream>
#include <limits>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::setlocale(LC_ALL, ".UTF8");

    std::cout << "===== Анализатор сетевого трафика classic pcap =====\n"
              << "Введите путь к .pcap файлу: ";

    std::string filePath;
    std::getline(std::cin, filePath);
    if (filePath.empty()) {
        std::cerr << "Путь к файлу не задан.\n";
        return 1;
    }

    PacketSequence sequence;
    if (!sequence.open(filePath)) {
        std::cerr << "Не удалось открыть файл или формат pcap не распознан.\n";
        return 1;
    }

    if (!sequence.readAll()) {
        std::cerr << "Ошибка чтения pcap: файл повреждён или содержит "
                  << "неподдерживаемый размер пакета.\n";
        sequence.close();
        return 1;
    }

    std::cout << "\n===== Статистика файла =====\n";
    sequence.printStatistics();

    std::cout << "\n===== Просмотр пакета =====\n"
              << "Введите номер пакета для просмотра (1.." << sequence.getPacketCount()
              << ", 0 — выход): ";

    while (true) {
        std::size_t packetNumber = 0;
        if (!(std::cin >> packetNumber)) {
            std::cerr << "Нужно ввести целое неотрицательное число.\n";
            return 1;
        }
        if (packetNumber == 0) {
            break;
        }

        const Packet* packet = sequence.getPacketByNumber(packetNumber);
        if (packet == nullptr) {
            std::cout << "Пакета с таким номером нет. Допустимый диапазон: 1.."
                      << sequence.getPacketCount() << ".\n";
            std::cout << "Введите номер пакета для просмотра (1.." << sequence.getPacketCount()
                      << ", 0 — выход): ";
            continue;
        }

        std::cout << "\n===== Пакет " << packetNumber
                  << ": шестнадцатеричное представление =====\n";
        packet->printHex(std::cout);
        std::cout << "\n===== Декодированные заголовки =====\n";
        packet->printDecoded(std::cout);
        std::cout << "\nВведите номер пакета для просмотра (1.." << sequence.getPacketCount()
                  << ", 0 — выход): ";
    }

    sequence.close();
    std::cout << "\nФайл закрыт. Программа завершена.\n";
    return 0;
}
