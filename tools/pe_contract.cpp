#include "pe_reader.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string LowerAscii(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

bool StartsWith(
    const std::string_view value,
    const std::string_view prefix) noexcept {
    return value.size() >= prefix.size() &&
           value.substr(0, prefix.size()) == prefix;
}

bool IsDynamicRuntime(const std::string& moduleName) {
    const std::string lowered = LowerAscii(moduleName);
    return StartsWith(lowered, "vcruntime") ||
           StartsWith(lowered, "msvcp") ||
           StartsWith(lowered, "concrt") ||
           StartsWith(lowered, "api-ms-win-crt-") ||
           lowered == "ucrtbase.dll";
}

void Require(
    const bool condition,
    const char* description,
    bool* success) {
    if (!condition) {
        std::cerr << "FAIL\t" << description << '\n';
        *success = false;
    }
}

bool IsAllowedModule(
    const std::string& moduleName,
    const std::vector<std::string_view>& allowed) {
    const std::string lowered = LowerAscii(moduleName);
    return std::find(allowed.begin(), allowed.end(), lowered) !=
           allowed.end();
}

void CheckCommon(
    const rs2fix::pe::Image& image,
    const bool requireDll,
    bool* success) {
    Require(
        image.machine == IMAGE_FILE_MACHINE_AMD64,
        "machine is not AMD64",
        success);
    Require(
        image.optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        "optional header is not PE32+",
        success);
    Require(
        ((image.characteristics & IMAGE_FILE_DLL) != 0) == requireDll,
        requireDll ? "image is not a DLL" : "image is unexpectedly a DLL",
        success);
    Require(
        (image.dllCharacteristics &
         IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
        "ASLR flag is absent",
        success);
    Require(
        (image.dllCharacteristics &
         IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        "NX compatibility flag is absent",
        success);
    Require(
        (image.dllCharacteristics &
         IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0,
        "high-entropy VA flag is absent",
        success);

    for (const rs2fix::pe::ImportModule& module : image.imports) {
        const std::string lowered = LowerAscii(module.name);
        Require(
            !IsDynamicRuntime(module.name),
            "dynamic Visual C++ runtime import is present",
            success);
        Require(
            lowered != "dbghelp.dll",
            "dbghelp.dll import is present",
            success);
    }
}

void CheckExactExport(
    const rs2fix::pe::Image& image,
    const char* expectedName,
    const std::uint32_t expectedOrdinal,
    const bool requireOrdinal,
    bool* success) {
    Require(
        image.exportFunctionCount == 1,
        "export function count is not one",
        success);
    Require(
        image.exports.size() == 1,
        "named export count is not one",
        success);
    if (image.exports.size() == 1) {
        Require(
            image.exports[0].name == expectedName,
            "named export does not match",
            success);
        if (requireOrdinal) {
            Require(
                image.exports[0].ordinal == expectedOrdinal,
                "export ordinal does not match",
                success);
        }
    }
}

void PrintEvidence(const rs2fix::pe::Image& image) {
    std::cout << "machine=0x" << std::hex << std::uppercase
              << image.machine << std::dec << '\n';
    std::cout << "characteristics=0x" << std::hex << std::uppercase
              << image.characteristics << std::dec << '\n';
    std::cout << "dll_characteristics=0x" << std::hex
              << std::uppercase << image.dllCharacteristics
              << std::dec << '\n';
    for (const rs2fix::pe::ImportModule& module : image.imports) {
        std::cout << "import_module=" << module.name << '\n';
        for (const rs2fix::pe::ImportSymbol& symbol : module.symbols) {
            if (symbol.byOrdinal) {
                std::cout << "import_symbol=" << module.name
                          << "!#" << symbol.ordinal << '\n';
            } else {
                std::cout << "import_symbol=" << module.name
                          << '!' << symbol.name << '\n';
            }
        }
    }
    for (const rs2fix::pe::ExportSymbol& symbol : image.exports) {
        std::cout << "export_symbol=" << symbol.name
                  << " ordinal=" << symbol.ordinal << '\n';
    }
}

void CheckBootstrap(
    const rs2fix::pe::Image& image,
    bool* success) {
    CheckCommon(image, true, success);
    CheckExactExport(image, "ReportFault", 13, true, success);
    const std::vector<std::string_view> allowed{"kernel32.dll"};
    for (const rs2fix::pe::ImportModule& module : image.imports) {
        Require(
            IsAllowedModule(module.name, allowed),
            "bootstrap has a disallowed direct import module",
            success);
        Require(
            LowerAscii(module.name) != "rs2serverfix.dll",
            "bootstrap statically imports the companion",
            success);
    }
}

void CheckCompanion(
    const rs2fix::pe::Image& image,
    bool* success) {
    CheckCommon(image, true, success);
    CheckExactExport(
        image,
        "RS2ServerFix_InitializeV1",
        0,
        false,
        success);
    const std::vector<std::string_view> allowed{
        "kernel32.dll", "bcrypt.dll"};
    for (const rs2fix::pe::ImportModule& module : image.imports) {
        Require(
            IsAllowedModule(module.name, allowed),
            "companion has a disallowed direct import module",
            success);
    }
}

void CheckHarness(
    const rs2fix::pe::Image& image,
    bool* success) {
    CheckCommon(image, false, success);
    bool foundFaultrep = false;
    for (const rs2fix::pe::ImportModule& module : image.imports) {
        if (LowerAscii(module.name) != "faultrep.dll") {
            continue;
        }
        foundFaultrep = true;
        Require(
            module.symbols.size() == 1,
            "harness faultrep import count is not one",
            success);
        if (module.symbols.size() == 1) {
            Require(
                !module.symbols[0].byOrdinal,
                "harness imports ReportFault by ordinal",
                success);
            Require(
                module.symbols[0].name == "ReportFault",
                "harness faultrep import name does not match",
                success);
        }
    }
    Require(
        foundFaultrep,
        "harness has no faultrep.dll import",
        success);
}

} // namespace

int wmain(const int argumentCount, wchar_t** arguments) {
    if (argumentCount != 3 || arguments == nullptr) {
        std::cerr << "usage: rs2_pe_contract <bootstrap|companion|harness> <path>\n";
        return 2;
    }

    rs2fix::pe::Image image{};
    std::string parseError;
    if (!rs2fix::pe::ReadPeImage(arguments[2], &image, &parseError)) {
        std::cerr << "FAIL\tparse\t" << parseError << '\n';
        return 1;
    }
    PrintEvidence(image);

    bool success = true;
    const std::wstring_view mode(arguments[1]);
    if (mode == L"bootstrap") {
        CheckBootstrap(image, &success);
    } else if (mode == L"companion") {
        CheckCompanion(image, &success);
    } else if (mode == L"harness") {
        CheckHarness(image, &success);
    } else {
        std::cerr << "FAIL\tunknown mode\n";
        return 2;
    }

    if (!success) {
        return 1;
    }
    std::cout << "contract=pass\n";
    return 0;
}
