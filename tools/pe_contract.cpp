#include "pe_contract_lib.h"
#include "tool_paths.h"
#include <iostream>
#include <string_view>
namespace {
void Help() {
    std::cout << "rs2_pe_contract --kind <bootstrap|companion|companion-passive|companion-active|harness|fixture-bootstrap|fixture-companion-passive|fixture-companion-active|missing-genuine-bootstrap|startup-fixture> --file <absolute existing plain file>\n"
        "Sole --help prints this grammar. Options must occur exactly once.\n";
}
void Imports(const char* kind, const std::vector<rs2fix::pe::ImportModule>& modules) {
    for (const auto& module : modules) {
        std::cout << kind << "_import_module=" << module.name << '\n';
        for (const auto& symbol : module.symbols) {
            std::cout << kind << "_import_symbol=" << module.name << '!';
            if (symbol.byOrdinal) std::cout << '#' << symbol.ordinal;
            else std::cout << symbol.name;
            std::cout << " iat_rva=0x" << std::hex << symbol.iatRva << std::dec << '\n';
        }
    }
}
}
int wmain(int count, wchar_t** arguments) {
    using namespace rs2fix::tooling;
    if (arguments && count == 2 && std::wstring_view(arguments[1]) == L"--help") { Help(); return 0; }
    if (!arguments || count != 5) { Help(); return 2; }
    std::wstring_view kindText;
    const wchar_t* file = nullptr;
    for (int index = 1; index < count; index += 2) {
        const std::wstring_view option(arguments[index]);
        if (option == L"--kind" && kindText.empty()) kindText = arguments[index + 1];
        else if (option == L"--file" && !file) file = arguments[index + 1];
        else { Help(); return 2; }
    }
    ArtifactKind kind{};
    if (!ParseArtifactKind(kindText, &kind) || !IsAbsoluteToolPath(file)) { Help(); return 2; }
    std::wstring normalized;
    std::string pathError;
    if (!RequireAbsolutePlainFile(file, &normalized, &pathError)) { std::cerr << "usage_error=" << pathError << '\n'; return 2; }
    ContractReport report;
    CheckArtifactContract(normalized.c_str(), kind, &report);
    const auto& image = report.image;
    std::cout << std::hex << std::uppercase << "machine=0x" << image.machine << "\noptional_magic=0x" << image.optionalMagic
        << "\ncharacteristics=0x" << image.characteristics << "\ndll_characteristics=0x" << image.dllCharacteristics
        << "\ncoff_timestamp=0x" << image.coffTimestamp << "\nchecksum=0x" << image.checksum
        << "\ntls_rva=0x" << image.tlsDirectoryRva << std::dec << "\ntls_size=" << image.tlsDirectorySize
        << "\nsize_of_image=" << image.sizeOfImage << '\n';
    Imports("normal", image.normalImports); Imports("delay", image.delayImports);
    for (const auto& symbol : image.exports)
        std::cout << "export_symbol=" << symbol.name << " ordinal=" << symbol.ordinal << " rva=0x" << std::hex << symbol.rva
            << std::dec << " forwarder=" << symbol.forwarder << '\n';
    const auto narrow = [](const std::wstring& value) {
        if (value.empty()) return std::string{};
        const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0) return std::string("<invalid-utf16>");
        std::string bytes(static_cast<std::size_t>(required), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            bytes.data(), required, nullptr, nullptr) != required) return std::string("<invalid-utf16>");
        return bytes;
    };
    std::cout << "version_company=" << narrow(report.version.companyName) << "\nversion_product=" << narrow(report.version.productName)
        << "\nversion_description=" << narrow(report.version.fileDescription) << "\nversion_original_filename=" << narrow(report.version.originalFilename)
        << "\nversion_file=" << narrow(report.version.fileVersionText) << "\nversion_product_version=" << narrow(report.version.productVersionText) << '\n';
    for (const auto& finding : report.findings) std::cout << "finding=" << finding << '\n';
    std::cout << "contract=" << (report.passed ? "pass" : "fail") << '\n';
    return report.passed ? 0 : 1;
}
