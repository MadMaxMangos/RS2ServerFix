// Build-time generator for our own EXE only. It never executes an input.
#include "pe_contract_lib.h"
#include "tool_paths.h"
#include "companion/sha256.h"
#include "shared/digest.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <sstream>

namespace {
using Bytes = std::vector<std::uint8_t>;
std::string Array(const std::uint8_t* bytes, std::size_t size) {
    std::ostringstream out;
    out << '{';
    for (std::size_t i = 0; i < size; ++i) {
        if (i) out << ',';
        out << "0x" << std::hex << static_cast<unsigned>(bytes[i]);
    }
    out << '}';
    return out.str();
}
bool Emit(const wchar_t* path, const std::string& text) {
    // An explicit CMake-generated output, never an arbitrary game path.
    const std::filesystem::path output(path);
    std::wstring parent;
    std::string error;
    if (output.filename() != L"fixture_profile.h" ||
        !rs2fix::tooling::RequireAbsolutePlainDirectory(output.parent_path().c_str(), &parent, &error))
        return false;
    const DWORD attributes = GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return false;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written{};
    const bool ok = text.size() <= MAXDWORD &&
        WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) &&
        written == text.size() && FlushFileBuffers(file);
    const bool closed = CloseHandle(file) != FALSE;
    return ok && closed;
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;
    rs2fix::tooling::ContractReport contract;
    if (!rs2fix::tooling::CheckArtifactContract(argv[1],
            rs2fix::tooling::ArtifactKind::StartupFixture, &contract)) {
        for (const auto& finding : contract.findings) std::fprintf(stderr, "%s\n", finding.c_str());
        return 3;
    }
    const auto& image = contract.image;
    std::map<std::string, std::uint32_t> symbols;
    for (const auto& symbol : image.exports) {
        if (!symbol.forwarder.empty() || !symbols.emplace(symbol.name, symbol.rva).second) return 4;
    }
    constexpr const char* required[]{"FixtureState", "FixtureInitializerSlot",
        "FixtureInitializerThunk", "FixtureInitialize", "FixtureReturn", "FixtureInitializeEnd",
        "FixtureRecon", "FixtureReconLoad", "FixtureReconEnd", "FixtureBadConstant", "FixtureGoodConstant"};
    for (const auto* name : required) if (!symbols.count(name)) return 5;
    const auto fn = symbols.at("FixtureRecon"), end = symbols.at("FixtureReconEnd");
    const auto load = symbols.at("FixtureReconLoad"), constant = symbols.at("FixtureGoodConstant");
    const auto wrapper = symbols.at("FixtureInitialize"), returnRva = symbols.at("FixtureReturn");
    const auto wrapperEnd = symbols.at("FixtureInitializeEnd");
    if (end <= fn || end - fn > 1024 || load < fn || load + 12 > end || (load & 3) ||
        returnRva <= wrapper + 6 || wrapperEnd <= returnRva || wrapperEnd - wrapper > 1024) return 6;
    Bytes function, vector, slot, wrapperBytes, thunkBytes, entryBytes;
    std::string error;
    if (!rs2fix::pe::ReadImageRva(image, fn, end - fn, &function, &error) ||
        !rs2fix::pe::ReadImageRva(image, constant, 16, &vector, &error) ||
        !rs2fix::pe::ReadImageRva(image, symbols.at("FixtureInitializerSlot"), 8, &slot, &error) ||
        !rs2fix::pe::ReadImageRva(image, wrapper, wrapperEnd - wrapper, &wrapperBytes, &error) ||
        !rs2fix::pe::ReadImageRva(image, symbols.at("FixtureInitializerThunk"), 16, &thunkBytes, &error) ||
        !rs2fix::pe::ReadImageRva(image, image.entryPointRva, 16, &entryBytes, &error)) return 7;
    std::uint64_t pointer{};
    std::memcpy(&pointer, slot.data(), sizeof(pointer));
    if (pointer != image.imageBase + symbols.at("FixtureInitializerThunk")) return 8;
    const std::size_t offset = load - fn;
    constexpr std::uint8_t instruction[]{0xF3,0x0F,0x10,0x15};
    constexpr std::uint8_t nop[]{0x0F,0x1F,0x40,0x00};
    if (std::memcmp(function.data() + offset, instruction, 4) ||
        std::memcmp(function.data() + offset + 8, nop, 4)) return 9;
    std::int32_t oldDisplacement{};
    std::memcpy(&oldDisplacement, function.data() + offset + 4, 4);
    if (static_cast<std::int64_t>(load) + 8 + oldDisplacement != symbols.at("FixtureBadConstant")) return 10;
    const auto newDistance = static_cast<std::int64_t>(constant) - load - 8;
    if (newDistance < INT32_MIN || newDistance > INT32_MAX) return 11;
    const auto newDisplacement = static_cast<std::int32_t>(newDistance);
    for (std::size_t i = 0; i < 16; ++i)
        if (vector[i] != (i % 4 == 3 ? 0x38 : 0)) return 12;
    const auto callOffset = returnRva - wrapper - 6;
    if (wrapperBytes[callOffset] != 0xFF || wrapperBytes[callOffset + 1] != 0x15) return 13;
    std::int32_t iatDistance{};
    std::memcpy(&iatDistance, wrapperBytes.data() + callOffset + 2, 4);
    bool validIat{};
    for (const auto& module : image.normalImports)
        for (const auto& symbol : module.symbols)
            if (symbol.name == "X3DAudioInitialize" && !symbol.byOrdinal &&
                static_cast<std::int64_t>(returnRva) + iatDistance == symbol.iatRva) validIat = true;
    if (!validIat) return 14;
    rs2fix::Sha256Digest host{}, original{}, corrected{};
    if (!rs2fix::HashBytesSha256(image.rawBytes.data(), image.rawBytes.size(), &host) ||
        !rs2fix::HashBytesSha256(function.data(), function.size(), &original)) return 15;
    Bytes post = function;
    std::memcpy(post.data() + offset + 4, &newDisplacement, 4);
    if (!rs2fix::HashBytesSha256(post.data(), post.size(), &corrected)) return 16;
    std::ostringstream out;
    out << "#pragma once\n#include \"shared/startup_profile.h\"\n#include \"companion/recon_profile.h\"\n"
        "namespace rs2fix {\ninline constexpr char kFixtureOnlySignature[] = \"RS2-OWN-CODE-FIXTURE-NOT-FOR-DEPLOYMENT\";\n";
    const Bytes spans[]{entryBytes, thunkBytes, wrapperBytes};
    const std::uint32_t rvas[]{image.entryPointRva, symbols.at("FixtureInitializerThunk"), wrapper};
    for (unsigned i = 0; i < 3; ++i)
        out << "inline constexpr std::uint8_t kFixtureSpan" << i << "[]" << Array(spans[i].data(), spans[i].size()) << ";\n";
    out << "inline constexpr ByteSpan kFixtureSpans[]{\n";
    for (unsigned i = 0; i < 3; ++i)
        out << '{' << rvas[i] << ",sizeof(kFixtureSpan" << i << "),kFixtureSpan" << i << "},\n";
    out << "};\ninline constexpr StartupProfile kFixtureStartupProfile{" << image.sizeOfImage << ',' << image.coffTimestamp
        << ",{ " << image.checksum << ",0},1," << image.entryPointRva << ',' << returnRva << ','
        << symbols.at("FixtureState") << ",1," << symbols.at("FixtureInitializerSlot") << ','
        << symbols.at("FixtureInitializerThunk") << ",kFixtureSpans,3};\n";
    out << "inline constexpr ReconProfile kFixtureReconProfile{" << fn << ',' << end - fn << ',' << load << ',' << load + 4
        << ',' << constant << ',' << static_cast<std::uint32_t>(oldDisplacement) << 'u' << ','
        << static_cast<std::uint32_t>(newDisplacement) << "u," << Array(function.data() + offset, 12) << ','
        << Array(vector.data(), vector.size()) << ',' << Array(host.data(), host.size()) << ','
        << Array(original.data(), original.size()) << ',' << Array(corrected.data(), corrected.size()) << "};\n}\n";
    if (!Emit(argv[2], out.str())) return 17;
    std::printf("fixture_host_sha256=%s function_size=%zu generated=true\n",
        rs2fix::FormatSha256Upper(host).data(), function.size());
    return 0;
}
