#pragma once

#include <cstdint>
#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace rs2fix::pe {

struct ImportSymbol {
    bool byOrdinal{};
    std::uint16_t ordinal{};
    std::string name;
    std::uint32_t iatRva{};
};

struct ImportModule {
    std::string name;
    std::vector<ImportSymbol> symbols;
};

struct ExportSymbol {
    std::string name;
    std::uint32_t ordinal{};
    std::uint32_t rva{};
    std::string forwarder;
};

struct Section {
    std::string name;
    std::uint32_t virtualAddress{};
    std::uint32_t virtualSize{};
    std::uint32_t rawOffset{};
    std::uint32_t rawSize{};
    std::uint32_t characteristics{};
};
struct DataDirectory {
    std::uint32_t virtualAddress{};
    std::uint32_t size{};
};

struct Image {
    std::uint16_t machine{};
    std::uint16_t characteristics{};
    std::uint16_t optionalMagic{};
    std::uint16_t dllCharacteristics{};
    std::uint32_t coffTimestamp{};
    std::uint32_t sizeOfImage{};
    std::uint32_t checksum{};
    std::uint32_t tlsDirectoryRva{};
    std::uint32_t tlsDirectorySize{};
    std::uint64_t imageBase{};
    std::uint32_t entryPointRva{};
    std::uint32_t sizeOfHeaders{};
    std::array<DataDirectory, 16> dataDirectories{};
    std::uint32_t exportFunctionCount{};
    std::vector<ImportModule> normalImports;
    std::vector<ImportModule> delayImports;
    std::vector<ExportSymbol> exports;
    std::vector<Section> sections;
    std::vector<std::uint8_t> rawBytes;
};

bool ReadPeImage(
    const wchar_t* path,
    Image* image,
    std::string* error);

// Byte input is copied only on success. Failed parses always clear the output.
bool ReadPeBytes(const std::vector<std::uint8_t>& bytes, Image* image,
                 std::string* error);
const Section* FindSection(const Image& image, std::uint32_t rva,
                           std::size_t size) noexcept;
bool MapImageRva(const Image& image, std::uint32_t rva, std::size_t size,
                 std::size_t* rawOffset) noexcept;
bool ReadImageRva(const Image& image, std::uint32_t rva, std::size_t size,
                  std::vector<std::uint8_t>* bytes, std::string* error);

} // namespace rs2fix::pe
