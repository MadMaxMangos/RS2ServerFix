#include "companion/steam_reporting_native_profile.h"
#include "shared/selected_profile.h"
#include "pe_reader.h"
#include "test_framework.h"
#include <cstring>

#if !defined(RS2_CURRENT_FULLDUMP_PATH) || !defined(RS2_CURRENT_STOCK_PATH)
#error Native logging/reporting evidence requires both authenticated current image paths.
#endif

namespace rs2fix::testcases {
namespace {
using namespace reporting;
// A data-only PE reader with synthetic loader-resolved imports. No SEC_IMAGE,
// LoadLibrary, EXE execution, native logger call or real SDK is involved.
struct FileImage {
    pe::Image image;
    bool badImport{};
    static constexpr std::uintptr_t kImportBase = 0x7FF200000000ULL;
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* result, DWORD*) noexcept {
        const auto& f = *static_cast<FileImage*>(context);
        const auto base = f.image.imageBase;
        if (address < base || address - base >= f.image.sizeOfImage) return false;
        const auto rva = static_cast<std::uint32_t>(address - base);
        if (rva < f.image.sizeOfHeaders) {
            *result = {base, base, f.image.sizeOfHeaders, MEM_COMMIT, MEM_IMAGE, PAGE_READONLY};
            return true;
        }
        const auto* section = pe::FindSection(f.image, rva, 1);
        if (!section || (section->characteristics & IMAGE_SCN_MEM_DISCARDABLE)) return false;
        const bool code = (section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool write = (section->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        const DWORD protection = code ? (write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
            : (write ? PAGE_READWRITE : PAGE_READONLY);
        *result = {base + section->virtualAddress, base, section->virtualSize,
            MEM_COMMIT, MEM_IMAGE, protection};
        return true;
    }
    static bool Read(void* context, std::uintptr_t address, void* result, std::size_t size, DWORD*) noexcept {
        const auto& f = *static_cast<FileImage*>(context);
        if (address < f.image.imageBase || address - f.image.imageBase > UINT32_MAX) return false;
        const auto rva = static_cast<std::uint32_t>(address - f.image.imageBase);
        const auto& profile = ProductionNativeLoggingProfile();
        for (std::size_t i = 0; i < profile.importCount; ++i) {
            if (rva == profile.imports[i].slotRva && size == 8) {
                const auto value = kImportBase + rva + (f.badImport ? 1 : 0);
                std::memcpy(result, &value, sizeof(value));
                return true;
            }
        }
        const auto& pump = ProductionReportingProfile().pump;
        if (rva == pump.slotRva && size == 8) {
            const auto value = kImportBase + rva;
            std::memcpy(result, &value, sizeof(value));
            return true;
        }
        std::size_t offset{};
        if (size > kProfileReadChunk || !pe::MapImageRva(f.image, rva, size, &offset)) return false;
        std::memcpy(result, f.image.rawBytes.data() + offset, size);
        return true;
    }
    static bool Resolve(void*, const char* module, const char* name, std::uintptr_t* value, DWORD*) noexcept {
        const auto& p = ProductionNativeLoggingProfile();
        for (std::size_t i = 0; i < p.importCount; ++i)
            if (!std::strcmp(module, p.imports[i].module) && !std::strcmp(name, p.imports[i].name)) {
                *value = kImportBase + p.imports[i].slotRva;
                return true;
            }
        return false;
    }
    ProfileResult Check() {
        const MemoryOps memory{this, Query, Read};
        const NativeImportOps imports{this, Resolve};
        DWORD error{};
        return ValidateNativeLoggingProfile(image.imageBase, kProductionStartupProfile,
            ProductionNativeLoggingProfile(), memory, imports, &error);
    }
    ProfileResult CheckReporting() {
        const MemoryOps memory{this, Query, Read};
        std::uintptr_t pump{};
        DWORD error{};
        const auto result = ValidateReportingProfile(image.imageBase, kProductionStartupProfile,
            ProductionReportingProfile(), memory, &pump, &error);
        if (result == ProfileResult::Ready)
            RS2_CHECK(pump == kImportBase + ProductionReportingProfile().pump.slotRva);
        return result;
    }
};
void PhysicalImport(const pe::Image& image, const PumpImportRecipe& recipe) {
    unsigned found{};
    for (const auto& module : image.normalImports) for (const auto& symbol : module.symbols)
        if (symbol.iatRva == recipe.slotRva && !_stricmp(module.name.c_str(), recipe.module) &&
            !symbol.byOrdinal && symbol.name == recipe.name) ++found;
    RS2_CHECK(found == 1);
}
void QualifiedFile(const wchar_t* path, const char* expectedHash) {
    FileImage fixture;
    std::string error;
    const bool read = pe::ReadPeImage(path, &fixture.image, &error);
    RS2_CHECK(read);
    if (!read) { std::cerr << error << '\n'; return; }
    Sha256Digest digest{};
    const bool hashed = HashBytesSha256(fixture.image.rawBytes.data(), fixture.image.rawBytes.size(), &digest);
    RS2_CHECK(hashed);
    if (!hashed) return;
    const bool qualified = !std::strcmp(FormatSha256Upper(digest).data(), expectedHash);
    RS2_CHECK(qualified);
    // Do not interpret any bytes from an unapproved physical executable.
    if (!qualified) return;

    const auto& profile = ProductionNativeLoggingProfile();
    for (std::size_t i = 0; i < profile.importCount; ++i) PhysicalImport(fixture.image, profile.imports[i]);
    PhysicalImport(fixture.image, ProductionReportingProfile().pump);
    // These validators read every compiled span, relocated pointer and unwind
    // membership from the physical PE, with only loader-resolved IAT cells
    // supplied synthetically. Named import identity was checked above.
    RS2_CHECK(fixture.CheckReporting() == ProfileResult::Ready);
    RS2_CHECK(fixture.Check() == ProfileResult::Ready);
    fixture.badImport = true;
    RS2_CHECK(fixture.Check() == ProfileResult::ImportMismatch);
    fixture.badImport = false;
    for (const std::size_t index : {std::size_t{0}, profile.body.spanCount - 1}) {
        const auto& span = profile.body.spans[index].span;
        std::size_t offset{};
        const bool mapped = pe::MapImageRva(fixture.image, span.rva, 1, &offset);
        RS2_CHECK(mapped);
        if (!mapped) return;
        fixture.image.rawBytes[offset] ^= 1;
        RS2_CHECK(fixture.Check() == ProfileResult::BytesMismatch);
        fixture.image.rawBytes[offset] ^= 1;
    }
    RS2_CHECK(fixture.Check() == ProfileResult::Ready);
}
}

void NativeLogFileProfileTests() {
    QualifiedFile(RS2_CURRENT_FULLDUMP_PATH,
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393");
    QualifiedFile(RS2_CURRENT_STOCK_PATH,
        "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3");
}
} // namespace rs2fix::testcases
