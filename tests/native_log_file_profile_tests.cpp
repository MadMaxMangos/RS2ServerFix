#include "companion/steam_reporting_native_profile.h"
#include "shared/selected_profile.h"
#include "pe_reader.h"
#include "test_framework.h"
#include <cstring>

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
};
}

void NativeLogFileProfileTests() {
    FileImage fixture;
    std::string error;
    const bool read = pe::ReadPeImage(RS2_CURRENT_FULLDUMP_PATH, &fixture.image, &error);
    RS2_CHECK(read);
    if (!read) { std::cerr << error << '\n'; return; }
    Sha256Digest digest{};
    RS2_CHECK(HashBytesSha256(fixture.image.rawBytes.data(), fixture.image.rawBytes.size(), &digest));
    RS2_CHECK(digest == ProductionReportingIdentities().hostDigest);
    RS2_CHECK(fixture.Check() == ProfileResult::Ready);
    fixture.badImport = true;
    RS2_CHECK(fixture.Check() == ProfileResult::ImportMismatch);
    fixture.badImport = false;
    const auto& profile = ProductionNativeLoggingProfile();
    for (const std::size_t index : {std::size_t{0}, profile.body.spanCount - 1}) {
        const auto& span = profile.body.spans[index].span;
        std::size_t offset{};
        RS2_CHECK(pe::MapImageRva(fixture.image, span.rva, 1, &offset));
        fixture.image.rawBytes[offset] ^= 1;
        RS2_CHECK(fixture.Check() == ProfileResult::BytesMismatch);
        fixture.image.rawBytes[offset] ^= 1;
    }
    RS2_CHECK(fixture.Check() == ProfileResult::Ready);
}
} // namespace rs2fix::testcases
