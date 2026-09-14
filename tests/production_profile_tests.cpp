#include "test_framework.h"
#include "pe_reader.h"
#include "tool_paths.h"
#include "companion/sha256.h"
#include "companion/recon_profile.h"
#include "shared/production_startup.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#if !defined(RS2_CURRENT_FULLDUMP_PATH) || !defined(RS2_CURRENT_STOCK_PATH) || !defined(RS2_SOURCE_DIR)
#error Production profile evidence tests require explicit preserved file and source paths.
#endif

namespace rs2fix::testcases {
namespace {
using Bytes = std::vector<std::uint8_t>;
struct RecordedSpan {
    const wchar_t* file;
    std::uint32_t rva;
    std::size_t size;
    std::size_t raw;
    const char* digest;
};
// Independent physical extraction locations, not values borrowed from a compiled profile.
constexpr RecordedSpan kRecordedSpans[]{
    {L"pr3-startup-0.hex", 0xD27C90, 18, 0xD27090, "46768C7EB1ACC8317A65635FF5C203248A4D1C20FEF3DA0D79F2C9BBA5D571B7"},
    {L"pr3-startup-1.hex", 0xD27CA4, 319, 0xD270A4, "BD045D2050024598F1A5AC391B7684F67D71FE9795629AF1679402333FC80F8D"},
    {L"pr3-startup-2.hex", 0xD27DE3, 5, 0xD271E3, "F525C4F4CAD6696EBBE7CEC324CE542ACB188F2624183AE57439260733C5C790"},
    {L"pr3-startup-3.hex", 0xD281A6, 6, 0xD275A6, "D570B0F42A3A12E854D7CEC57C234F742B84B2E6F975467BAE0AA6613EF440B8"},
    {L"pr3-startup-4.hex", 0xE72D30, 12, 0xE72130, "582AC744C0D5FD213258CFC2A77ACCBF54E992AB3E612A1ADF5EEAD0BFC497B7"},
    {L"pr3-startup-5.hex", 0xA69EF0, 31, 0xA692F0, "4B7B3B63133F0C77DD76E73FA39F850CE09A0ED51B8D27CAE42C6CF215439D7E"}
};
constexpr const char* kFullDumpHash = "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393";
constexpr const char* kStockHash = "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3";
constexpr const char* kOriginalHash = "E58CE150747B01ED9A6BC21223061AA94F56430CEDD996D7D727B6310968BDEE";
constexpr const char* kCorrectedHash = "F402D3262D39EC73E9B33E14CC4F74B06EC981ECDE94D59ADF67D905CC1DA2D5";

bool ReadText(const wchar_t* leaf, std::string* text) {
    const std::wstring path = std::wstring(RS2_SOURCE_DIR) + L"/tests/evidence/" + leaf;
    std::wstring normalized; std::string error;
    if (!tooling::RequireAbsolutePlainFile(path.c_str(), &normalized, &error)) {
        std::cerr << "profile evidence missing: " << error << '\n'; return false;
    }
    const HANDLE file = CreateFileW(normalized.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    BY_HANDLE_FILE_INFORMATION identity{};
    bool okay = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 16384 &&
        GetFileInformationByHandle(file, &identity) &&
        (identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    text->clear();
    if (okay) {
        text->resize(static_cast<std::size_t>(size.QuadPart));
        std::size_t cursor = 0;
        while (cursor < text->size()) {
            DWORD read = 0;
            if (!ReadFile(file, text->data() + cursor, static_cast<DWORD>(text->size() - cursor), &read, nullptr) || !read) {
                okay = false; break;
            }
            cursor += read;
        }
    }
    if (!CloseHandle(file)) okay = false;
    if (!okay) text->clear();
    return okay;
}
bool ReadHex(const wchar_t* file, std::size_t expectedSize, Bytes* bytes) {
    std::string text;
    if (!ReadText(file, &text)) return false;
    bytes->clear();
    int high = -1;
    for (char character : text) {
        if (character == '\r' || character == '\n') {
            if (high != -1) return false;
            continue;
        }
        const int nibble = character >= '0' && character <= '9' ? character - '0' :
            character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1;
        if (nibble == -1) return false;
        if (high == -1) high = nibble;
        else { bytes->push_back(static_cast<std::uint8_t>((high << 4) | nibble)); high = -1; }
        if (bytes->size() > expectedSize) return false;
    }
    return high == -1 && bytes->size() == expectedSize;
}
Sha256Digest Digest(const Bytes& bytes) {
    Sha256Digest digest{};
    RS2_CHECK(HashBytesSha256(bytes.data(), bytes.size(), &digest));
    return digest;
}
std::string HashText(const Bytes& bytes) { return FormatSha256Upper(Digest(bytes)).data(); }
Bytes ReadRange(const pe::Image& image, std::uint32_t rva, std::size_t size) {
    Bytes bytes; std::string error;
    const bool read = pe::ReadImageRva(image, rva, size, &bytes, &error);
    if (!read) std::cerr << "profile read failed: " << error << '\n';
    RS2_CHECK(read);
    return bytes;
}
template<class T> bool At(const Bytes& bytes, std::size_t offset, T* value) {
    if (!value || offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
    std::memcpy(value, bytes.data() + offset, sizeof(T));
    return true;
}
template<class T> T ReadValue(const pe::Image& image, std::uint32_t rva) {
    const auto bytes = ReadRange(image, rva, sizeof(T));
    T value{}; RS2_CHECK(At(bytes, 0, &value)); return value;
}
std::uint32_t RelativeTarget(const pe::Image& image, std::uint32_t start,
    std::size_t instructionSize, std::size_t displacementOffset) {
    const auto bytes = ReadRange(image, start, instructionSize);
    std::int32_t displacement{};
    if (!At(bytes, displacementOffset, &displacement)) { RS2_CHECK(false); return 0; }
    const auto result = static_cast<std::int64_t>(start) + static_cast<std::int64_t>(instructionSize) + displacement;
    RS2_CHECK(result >= 0 && result <= UINT32_MAX);
    return result >= 0 && result <= UINT32_MAX ? static_cast<std::uint32_t>(result) : 0;
}
bool Overlap(std::uint32_t left, std::size_t leftSize, std::uint32_t right, std::size_t rightSize) {
    return left < static_cast<std::uint64_t>(right) + rightSize && right < static_cast<std::uint64_t>(left) + leftSize;
}
struct RelocationAudit { bool complete{}; std::size_t slotDir64{}, criticalOverlaps{}; };
RelocationAudit AuditRelocations(const pe::Image& image) {
    RelocationAudit audit{};
    const auto& directory = image.dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!directory.virtualAddress || directory.size < sizeof(IMAGE_BASE_RELOCATION)) return audit;
    const auto bytes = ReadRange(image, directory.virtualAddress, directory.size);
    if (bytes.size() != directory.size) return audit;
    std::size_t cursor = 0, nonPadding = 0;
    while (cursor < bytes.size()) {
        IMAGE_BASE_RELOCATION block{};
        if (!At(bytes, cursor, &block) || block.SizeOfBlock < sizeof(block) ||
            block.SizeOfBlock > bytes.size() - cursor || (block.SizeOfBlock - sizeof(block)) % sizeof(WORD) != 0 ||
            (block.VirtualAddress & 0xFFF) != 0) return audit;
        const auto end = cursor + block.SizeOfBlock;
        for (std::size_t entry = cursor + sizeof(block); entry < end; entry += sizeof(WORD)) {
            WORD encoded{};
            if (!At(bytes, entry, &encoded)) return audit;
            const unsigned type = encoded >> 12;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            // All relocation records in these exact AMD64 inputs are audited;
            // an unfamiliar format must fail rather than silently skip bytes.
            if (type != IMAGE_REL_BASED_DIR64) return audit;
            const std::uint64_t target64 = static_cast<std::uint64_t>(block.VirtualAddress) + (encoded & 0xFFF);
            if (target64 >= image.sizeOfImage || sizeof(std::uint64_t) > image.sizeOfImage - target64) return audit;
            const auto target = static_cast<std::uint32_t>(target64);
            if (!pe::FindSection(image, target, sizeof(std::uint64_t))) return audit;
            ++nonPadding;
            if (Overlap(target, 8, 0xE9E950, 8)) {
                if (target != 0xE9E950) return audit;
                ++audit.slotDir64;
            }
            if (Overlap(target, 8, 0xB452D0, 641) || Overlap(target, 8, 0xB45328, 4) ||
                Overlap(target, 8, 0x12891B0, 16)) ++audit.criticalOverlaps;
            for (const auto& span : kRecordedSpans)
                if (Overlap(target, 8, span.rva, span.size)) ++audit.criticalOverlaps;
        }
        cursor = end;
    }
    audit.complete = cursor == bytes.size() && nonPadding != 0;
    return audit;
}
void CheckSection(const pe::Image& image, std::uint32_t rva, std::size_t size,
                   const char* name, DWORD required, DWORD forbidden) {
    const auto* section = pe::FindSection(image, rva, size);
    RS2_CHECK(section != nullptr);
    if (!section) return;
    RS2_CHECK(section->name == name && (section->characteristics & required) == required &&
        (section->characteristics & forbidden) == 0);
}
std::string Hex(std::uint64_t value, int width = 8) {
    std::ostringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << value;
    return stream.str();
}
struct SourceEvidence {
    std::string digest;
    std::uint64_t fileSize{}, imageBase{}, slotValue{};
    std::uint16_t machine{}, magic{};
    std::uint32_t timestamp{}, imageSize{}, checksum{}, entry{}, x3Iat{};
    RelocationAudit relocations;
};
bool CheckSource(const wchar_t* path, bool fullDump, const Bytes& recordedFunction,
    const Bytes& recordedConstant, const std::array<Bytes, 6>& spans, SourceEvidence* evidence) {
    pe::Image image; std::string error;
    const bool parsed = pe::ReadPeImage(path, &image, &error);
    if (!parsed) std::cerr << "preserved profile input parse failed: " << error << '\n';
    RS2_CHECK(parsed);
    if (!parsed) return false;
    const auto hash = HashText(image.rawBytes);
    RS2_CHECK(hash == (fullDump ? kFullDumpHash : kStockHash));
    // Do not interpret a different executable as qualified evidence.
    if (hash != (fullDump ? kFullDumpHash : kStockHash)) return false;
    RS2_CHECK(image.rawBytes.size() == 23994880);
    RS2_CHECK(image.machine == IMAGE_FILE_MACHINE_AMD64 && image.optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    RS2_CHECK((image.characteristics & IMAGE_FILE_DLL) == 0);
    RS2_CHECK(image.coffTimestamp == 0x6A8E3C02 && image.sizeOfImage == 0x01A12000);
    RS2_CHECK(image.checksum == (fullDump ? 0x016EF965U : 0x016EF765U));
    RS2_CHECK(image.imageBase == 0x140000000ULL && image.entryPointRva == 0xD27C90);
    RS2_CHECK(image.tlsDirectoryRva == 0 && image.tlsDirectorySize == 0);
    RS2_CHECK(kProductionStartupProfile.imageSize == image.sizeOfImage && kProductionStartupProfile.timestamp == image.coffTimestamp);
    RS2_CHECK(kProductionStartupProfile.checksums[fullDump ? 0 : 1] == image.checksum &&
        kProductionStartupProfile.entryRva == image.entryPointRva);
    for (std::size_t index = 0; index < std::size(kRecordedSpans); ++index) {
        const auto& recorded = kRecordedSpans[index];
        const auto physical = ReadRange(image, recorded.rva, recorded.size);
        RS2_CHECK(physical == spans[index]);
        RS2_CHECK(HashText(physical) == recorded.digest);
        std::size_t raw = 0;
        RS2_CHECK(pe::MapImageRva(image, recorded.rva, recorded.size, &raw) && raw == recorded.raw);
        CheckSection(image, recorded.rva, recorded.size, ".text", IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE);
    }
    const auto function = ReadRange(image, 0xB452D0, 641);
    const auto constant = ReadRange(image, 0x12891B0, 16);
    RS2_CHECK(function == recordedFunction && constant == recordedConstant);
    RS2_CHECK(HashText(function) == kOriginalHash);
    std::size_t raw = 0;
    RS2_CHECK(pe::MapImageRva(image, 0xB452D0, 641, &raw) && raw == 0xB446D0);
    RS2_CHECK(pe::MapImageRva(image, 0xB45328, 4, &raw) && raw == 0xB44728);
    RS2_CHECK(pe::MapImageRva(image, 0x12891B0, 16, &raw) && raw == 0x12881B0);
    CheckSection(image, 0xB452D0, 641, ".text", IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE);
    CheckSection(image, 0x12891B0, 16, ".rdata", IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE);
    CheckSection(image, 0xE9E950, 8, ".rdata", IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE);
    CheckSection(image, 0x17E64C8, 4, ".data", IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE);
    const auto slot = ReadValue<std::uint64_t>(image, 0xE9E950);
    RS2_CHECK(slot == image.imageBase + 0xE72D30);
    RS2_CHECK(slot - image.imageBase == kProductionStartupProfile.initializerRva);
    RS2_CHECK(0xE9E950 >= 0xE95710 && 0xE9E950 + 8 <= 0xE9FBC8 && ((0xE9E950 - 0xE95710) % 8) == 0);
    // Fixed instruction fields establish the table/caller/stage relationships;
    // every containing instruction is also covered by independent raw bytes.
    RS2_CHECK(RelativeTarget(image, 0xD27C9D, 5, 1) == 0xD27CA4);
    RS2_CHECK(RelativeTarget(image, 0xD27D4A, 7, 3) == 0xE9FBC8);
    RS2_CHECK(RelativeTarget(image, 0xD27D51, 7, 3) == 0xE95710);
    RS2_CHECK(RelativeTarget(image, 0xD27D58, 5, 1) == 0xD281A6);
    RS2_CHECK(RelativeTarget(image, 0xD27D0A, 10, 2) == 0x17E64C8);
    RS2_CHECK(ReadValue<std::uint32_t>(image, 0xD27D10) == 1);
    RS2_CHECK(RelativeTarget(image, 0xD27D5D, 10, 2) == 0x17E64C8);
    RS2_CHECK(ReadValue<std::uint32_t>(image, 0xD27D63) == 2);
    RS2_CHECK(RelativeTarget(image, 0xD27DE3, 5, 1) == 0xA74840);
    RS2_CHECK(RelativeTarget(image, 0xE72D37, 5, 1) == 0xA69EF0);
    const auto x3Iat = RelativeTarget(image, 0xA69F09, 6, 2);
    RS2_CHECK(x3Iat == 0xE95470 && 0xA69F09 + 6 == kProductionStartupProfile.returnRva);
    std::size_t x3Imports = 0, inittermImports = 0;
    const auto inittermIat = RelativeTarget(image, 0xD281A6, 6, 2);
    for (const auto& module : image.normalImports) {
        std::string name = module.name;
        for (char& ch : name) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
        for (const auto& symbol : module.symbols) {
            if (name == "x3daudio1_7.dll") {
                ++x3Imports;
                RS2_CHECK(!symbol.byOrdinal && symbol.name == "X3DAudioInitialize" && symbol.iatRva == x3Iat);
            }
            if (symbol.name == "_initterm" && !symbol.byOrdinal && symbol.iatRva == inittermIat) ++inittermImports;
        }
    }
    RS2_CHECK(x3Imports == 1 && inittermImports == 1);
    const auto relocations = AuditRelocations(image);
    RS2_CHECK(relocations.complete && relocations.slotDir64 == 1 && relocations.criticalOverlaps == 0);
    *evidence = {hash, image.rawBytes.size(), image.imageBase, slot, image.machine, image.optionalMagic,
        image.coffTimestamp, image.sizeOfImage, image.checksum, image.entryPointRva, x3Iat, relocations};
    return true;
}
std::string Metadata(const SourceEvidence& full, const SourceEvidence& stock) {
    std::ostringstream out;
    out << "schema=1\nsource=preserved-physical-pe-read-only\n";
    const std::pair<const char*, const SourceEvidence*> sources[]{{"full_dump", &full}, {"stock", &stock}};
    for (const auto& source : sources) {
        const auto& value = *source.second;
        const std::string prefix = std::string(source.first) + ".";
        out << prefix << "sha256=" << value.digest << '\n'
            << prefix << "file_size=" << value.fileSize << '\n'
            << prefix << "machine=" << Hex(value.machine, 4) << '\n'
            << prefix << "optional_magic=" << Hex(value.magic, 4) << '\n'
            << prefix << "timestamp=" << Hex(value.timestamp) << '\n'
            << prefix << "size_of_image=" << Hex(value.imageSize) << '\n'
            << prefix << "checksum=" << Hex(value.checksum) << '\n'
            << prefix << "image_base=" << Hex(value.imageBase, 16) << '\n'
            << prefix << "entry_rva=" << Hex(value.entry) << '\n'
            << prefix << "initializer_slot_value=" << Hex(value.slotValue, 16) << '\n'
            << prefix << "x3_iat_rva=" << Hex(value.x3Iat) << '\n'
            << prefix << "relocations_complete=" << value.relocations.complete << '\n'
            << prefix << "slot_dir64_count=" << value.relocations.slotDir64 << '\n'
            << prefix << "critical_relocation_overlaps=" << value.relocations.criticalOverlaps << '\n';
    }
    return out.str();
}
}

void RunProfileEvidenceTests() {
    std::array<Bytes, 6> spans;
    Bytes function, constant;
    bool ready = ReadHex(L"pr3-recon-function.hex", 641, &function) && ReadHex(L"pr3-recon-constant.hex", 16, &constant);
    for (std::size_t index = 0; index < std::size(kRecordedSpans); ++index)
        ready = ReadHex(kRecordedSpans[index].file, kRecordedSpans[index].size, &spans[index]) && ready;
    RS2_CHECK(ready);
    if (!ready) return;
    RS2_CHECK(HashText(function) == kOriginalHash);
    RS2_CHECK(HashText(constant) == "9F8B5853D7A45A6EAD822F17501E0AA2A009C4F8212418C03CD9E50BC2A431D3");
    const auto& startup = kProductionStartupProfile;
    RS2_CHECK(startup.checksumCount == 2 && startup.spanCount == 6 && startup.spans != nullptr);
    if (startup.spanCount != 6 || !startup.spans) return;
    RS2_CHECK(startup.returnRva == 0xA69F0F && startup.stateRva == 0x17E64C8 && startup.stateValue == 1);
    RS2_CHECK(startup.initializerSlotRva == 0xE9E950 && startup.initializerRva == 0xE72D30);
    for (std::size_t index = 0; index < std::size(kRecordedSpans); ++index) {
        const auto& compiled = startup.spans[index];
        const auto& recorded = kRecordedSpans[index];
        RS2_CHECK(compiled.rva == recorded.rva && compiled.size == recorded.size && compiled.bytes != nullptr);
        if (compiled.size == recorded.size && compiled.bytes)
            RS2_CHECK(std::equal(spans[index].begin(), spans[index].end(), compiled.bytes));
        RS2_CHECK(HashText(spans[index]) == recorded.digest);
    }
    const auto& recon = kProductionReconProfile;
    RS2_CHECK(recon.functionRva == 0xB452D0 && recon.functionSize == 641);
    RS2_CHECK(recon.loadRva == 0xB45324 && recon.operandRva == 0xB45328 && recon.constantRva == 0x12891B0);
    RS2_CHECK(recon.oldDisplacement == 0x00360204 && recon.newDisplacement == 0x00743E84);
    RS2_CHECK(FormatSha256Upper(recon.hostDigest).data() == std::string(kFullDumpHash));
    RS2_CHECK(FormatSha256Upper(recon.originalDigest).data() == std::string(kOriginalHash));
    RS2_CHECK(FormatSha256Upper(recon.correctedDigest).data() == std::string(kCorrectedHash));
    RS2_CHECK(std::equal(recon.originalWindow.begin(), recon.originalWindow.end(), function.begin() + 0x54));
    RS2_CHECK(std::equal(recon.constantBytes.begin(), recon.constantBytes.end(), constant.begin()));
    constexpr std::uint8_t cvtt[]{0xF3, 0x0F, 0x2C, 0xF8};
    constexpr std::uint8_t multiply[]{0xF3, 0x0F, 0x59, 0xCE};
    RS2_CHECK(std::equal(std::begin(cvtt), std::end(cvtt), function.begin() + 0x82));
    RS2_CHECK(std::equal(std::begin(multiply), std::end(multiply), function.begin() + 0x6D));
    for (std::size_t index = 0; index < constant.size(); index += 4) {
        std::uint32_t bits = 0; RS2_CHECK(At(constant, index, &bits) && bits == 0x38000000);
    }
    RS2_CHECK((recon.operandRva & 3) == 0 && recon.operandRva + 4 <= recon.loadRva + 12);
    RS2_CHECK(static_cast<std::uint64_t>(recon.loadRva) + 8 + recon.oldDisplacement == 0xEA5530);
    RS2_CHECK(static_cast<std::uint64_t>(recon.loadRva) + 8 + recon.newDisplacement == recon.constantRva);
    Bytes corrected = function;
    const std::array<std::uint8_t, 4> displacement{0x84, 0x3E, 0x74, 0x00};
    std::copy(displacement.begin(), displacement.end(), corrected.begin() + 0x58);
    std::size_t different = 0;
    bool outsideUnchanged = true;
    for (std::size_t index = 0; index < function.size(); ++index) {
        if (function[index] == corrected[index]) continue;
        ++different;
        if (index < 0x58 || index >= 0x5C) outsideUnchanged = false;
    }
    RS2_CHECK(corrected.size() == 641 && different == 3 && outsideUnchanged);
    RS2_CHECK(HashText(corrected) == kCorrectedHash && Digest(corrected) == recon.correctedDigest);
    SourceEvidence full, stock;
    if (!CheckSource(RS2_CURRENT_FULLDUMP_PATH, true, function, constant, spans, &full) ||
        !CheckSource(RS2_CURRENT_STOCK_PATH, false, function, constant, spans, &stock)) return;
    std::string recordedMetadata;
    RS2_CHECK(ReadText(L"pr3-profile-audit.txt", &recordedMetadata));
    recordedMetadata.erase(std::remove(recordedMetadata.begin(), recordedMetadata.end(), '\r'), recordedMetadata.end());
    const auto actualMetadata = Metadata(full, stock);
    if (actualMetadata != recordedMetadata) std::cerr << "actual production profile metadata:\n" << actualMetadata;
    RS2_CHECK(actualMetadata == recordedMetadata);
}
}
