#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rs2fix::pe {

struct ImportSymbol {
    bool byOrdinal{};
    std::uint16_t ordinal{};
    std::string name;
};

struct ImportModule {
    std::string name;
    std::vector<ImportSymbol> symbols;
};

struct ExportSymbol {
    std::string name;
    std::uint32_t ordinal{};
};

struct Image {
    std::uint16_t machine{};
    std::uint16_t characteristics{};
    std::uint16_t optionalMagic{};
    std::uint16_t dllCharacteristics{};
    std::uint32_t exportFunctionCount{};
    std::vector<ImportModule> imports;
    std::vector<ExportSymbol> exports;
};

bool ReadPeImage(
    const wchar_t* path,
    Image* image,
    std::string* error);

} // namespace rs2fix::pe
