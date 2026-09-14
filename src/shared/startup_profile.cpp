#include "shared/startup_profile.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace rs2fix {
namespace {

bool Query(void*, std::uintptr_t address, MemoryRegion* result,
           DWORD* error) noexcept {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(reinterpret_cast<const void*>(address), &memory,
                     sizeof(memory)) != sizeof(memory)) {
        if (error) *error = GetLastError();
        return false;
    }
    *result = {reinterpret_cast<std::uintptr_t>(memory.BaseAddress),
        reinterpret_cast<std::uintptr_t>(memory.AllocationBase), memory.RegionSize,
        memory.State, memory.Type, memory.Protect};
    if (error) *error = ERROR_SUCCESS;
    return true;
}

bool Read(void*, std::uintptr_t address, void* output, std::size_t size,
          DWORD* error) noexcept {
    SIZE_T got{};
    const BOOL ok = ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<const void*>(address), output, size, &got);
    if (!ok || got != size) {
        if (error) *error = ok ? ERROR_PARTIAL_COPY : GetLastError();
        return false;
    }
    if (error) *error = ERROR_SUCCESS;
    return true;
}

bool Range(std::uintptr_t base, std::size_t imageSize, std::uint32_t rva,
           std::size_t size) noexcept {
    return base != 0 && size != 0 && imageSize != 0 &&
        imageSize <= (std::numeric_limits<std::uintptr_t>::max)() - base &&
        rva < imageSize && size <= imageSize - rva;
}

bool Readable(DWORD protection) noexcept {
    // No guard/no-access pages and no unknown modifiers.
    switch (protection) {
    case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: return true;
    default: return false;
    }
}

bool Regions(std::uintptr_t base, std::size_t imageSize, std::uint32_t rva,
             std::size_t size, DWORD exactProtection, const MemoryOps& ops,
             DWORD* error) noexcept {
    if (error) *error = ERROR_INVALID_ADDRESS;
    if (!Range(base, imageSize, rva, size) || !ops.query) return false;
    std::uintptr_t cursor = base + rva;
    const auto end = cursor + size;
    while (cursor < end) {
        MemoryRegion region{};
        if (!ops.query(ops.context, cursor, &region, error) ||
            region.allocationBase != base || region.state != MEM_COMMIT ||
            region.type != MEM_IMAGE || !Readable(region.protect) ||
            (exactProtection && region.protect != exactProtection) ||
            region.base > cursor || !region.size ||
            region.size > (std::numeric_limits<std::uintptr_t>::max)() - region.base ||
            region.base + region.size <= cursor) return false;
        cursor = (std::min)(end, region.base + region.size);
    }
    if (error) *error = ERROR_SUCCESS;
    return true;
}

bool Headers(std::uintptr_t base, std::size_t imageSize, IMAGE_NT_HEADERS64* nt,
             std::uint32_t* ntRva, const MemoryOps& ops) noexcept {
    IMAGE_DOS_HEADER dos{};
    DWORD error{};
    if (!ReadImageRange(base, imageSize, 0, &dos, sizeof(dos), ops, &error) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos) ||
        dos.e_lfanew > 0x100000) return false;
    *ntRva = static_cast<std::uint32_t>(dos.e_lfanew);
    return ReadImageRange(base, imageSize, *ntRva, nt, sizeof(*nt), ops, &error) &&
        nt->Signature == IMAGE_NT_SIGNATURE &&
        nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        (nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
        !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
        nt->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) &&
        nt->FileHeader.NumberOfSections > 0 && nt->FileHeader.NumberOfSections <= 96 &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt->OptionalHeader.SizeOfImage == imageSize &&
        nt->OptionalHeader.SizeOfHeaders < imageSize &&
        nt->OptionalHeader.SizeOfHeaders >= *ntRva + sizeof(*nt) &&
        nt->OptionalHeader.NumberOfRvaAndSizes == IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
}

} // namespace

const MemoryOps& ProductionMemoryOps() noexcept {
    static constexpr MemoryOps ops{nullptr, Query, Read};
    return ops;
}

bool ReadImageRange(std::uintptr_t base, std::size_t imageSize, std::uint32_t rva,
    void* output, std::size_t size, const MemoryOps& ops, DWORD* error) noexcept {
    if (!output || !ops.read || !Regions(base, imageSize, rva, size, 0, ops, error))
        return false;
    return ops.read(ops.context, base + rva, output, size, error);
}

bool ImageRangeProtection(std::uintptr_t base, std::size_t imageSize,
    std::uint32_t rva, std::size_t size, DWORD protection,
    const MemoryOps& ops, DWORD* error) noexcept {
    return protection != 0 && Regions(base, imageSize, rva, size, protection, ops, error);
}

bool ImageSectionMatches(std::uintptr_t base, std::size_t imageSize,
    std::uint32_t rva, std::size_t size, DWORD required, DWORD forbidden,
    const MemoryOps& ops) noexcept {
    if (!Range(base, imageSize, rva, size)) return false;
    IMAGE_NT_HEADERS64 nt{};
    std::uint32_t ntRva{};
    if (!Headers(base, imageSize, &nt, &ntRva, ops)) return false;
    const auto sectionRva = ntRva + static_cast<std::uint32_t>(sizeof(nt));
    std::array<IMAGE_SECTION_HEADER, 96> sections{};
    const std::size_t bytes = nt.FileHeader.NumberOfSections * sizeof(sections[0]);
    DWORD error{};
    if (sectionRva > nt.OptionalHeader.SizeOfHeaders ||
        bytes > nt.OptionalHeader.SizeOfHeaders - sectionRva ||
        !ReadImageRange(base, imageSize, sectionRva, sections.data(), bytes, ops, &error))
        return false;
    unsigned matching{};
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        const auto length = section.Misc.VirtualSize;
        if (section.VirtualAddress > imageSize || length > imageSize - section.VirtualAddress)
            return false;
        if (rva >= section.VirtualAddress && rva - section.VirtualAddress < length &&
            size <= length - (rva - section.VirtualAddress)) {
            if ((section.Characteristics & required) != required ||
                (section.Characteristics & forbidden) != 0) return false;
            ++matching;
        }
    }
    return matching == 1;
}

StartupGateResult CheckStartupOpportunity(const BootstrapContextV3& context,
    const StartupProfile& profile, const MemoryOps& ops) noexcept {
    if (context.size != sizeof(context) || context.abiVersion != kBootstrapAbiVersion ||
        context.reserved != 0 || context.triggerKind != kTriggerExeCrtInitialize ||
        !context.hostModule || !context.bootstrapModule || !context.genuineX3AudioModule ||
        context.genuineExportsMask != kRequiredGenuineExports ||
        context.hostModule == context.bootstrapModule ||
        context.hostModule == context.genuineX3AudioModule ||
        context.bootstrapModule == context.genuineX3AudioModule ||
        !profile.spans || !profile.spanCount || profile.spanCount > 16 ||
        !profile.checksumCount || profile.checksumCount > 2)
        return StartupGateResult::InvalidContext;
    if (context.staticLoad != 1) return StartupGateResult::DynamicLoad;
    if (!context.startupThreadId || context.startupThreadId != context.currentThreadId ||
        context.currentThreadId != GetCurrentThreadId()) return StartupGateResult::WrongThread;
    const auto base = reinterpret_cast<std::uintptr_t>(context.hostModule);
    if (!Range(base, profile.imageSize, profile.returnRva, 1) ||
        context.triggerReturnAddress != base + profile.returnRva)
        return StartupGateResult::WrongCaller;
    IMAGE_NT_HEADERS64 nt{};
    std::uint32_t ntRva{};
    if (!Headers(base, profile.imageSize, &nt, &ntRva, ops))
        return StartupGateResult::ImageUnavailable;
    bool checksum{};
    for (std::size_t i = 0; i < profile.checksumCount; ++i)
        checksum = checksum || nt.OptionalHeader.CheckSum == profile.checksums[i];
    if (!checksum || nt.FileHeader.TimeDateStamp != profile.timestamp ||
        nt.OptionalHeader.AddressOfEntryPoint != profile.entryRva ||
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0 ||
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0)
        return StartupGateResult::ImageMismatch;
    std::array<std::uint8_t, 1024> bytes{};
    DWORD error{};
    for (std::size_t i = 0; i < profile.spanCount; ++i) {
        const auto& span = profile.spans[i];
        if (!span.bytes || span.size > bytes.size() ||
            !ImageRangeProtection(base, profile.imageSize, span.rva, span.size,
                PAGE_EXECUTE_READ, ops, &error) ||
            !ImageSectionMatches(base, profile.imageSize, span.rva, span.size,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, ops) ||
            !ReadImageRange(base, profile.imageSize, span.rva, bytes.data(), span.size, ops, &error) ||
            std::memcmp(bytes.data(), span.bytes, span.size) != 0)
            return StartupGateResult::CodeMismatch;
    }
    std::uintptr_t initializer{};
    if (!Range(base, profile.imageSize, profile.initializerRva, 1) ||
        !ImageRangeProtection(base, profile.imageSize, profile.initializerSlotRva,
            sizeof(initializer), PAGE_READONLY, ops, &error) ||
        !ImageSectionMatches(base, profile.imageSize, profile.initializerSlotRva,
            sizeof(initializer), IMAGE_SCN_MEM_READ,
            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE, ops) ||
        !ReadImageRange(base, profile.imageSize, profile.initializerSlotRva,
            &initializer, sizeof(initializer), ops, &error) ||
        initializer != base + profile.initializerRva)
        return StartupGateResult::WrongInitializer;
    DWORD stage{};
    if (!ImageSectionMatches(base, profile.imageSize, profile.stateRva, sizeof(stage),
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE, ops) ||
        !ReadImageRange(base, profile.imageSize, profile.stateRva, &stage, sizeof(stage), ops, &error) ||
        stage != profile.stateValue) return StartupGateResult::WrongStage;
    return StartupGateResult::Ready;
}

const char* StartupGateResultName(StartupGateResult result) noexcept {
    switch (result) {
    case StartupGateResult::Ready: return "ready";
    case StartupGateResult::InvalidContext: return "invalid-context";
    case StartupGateResult::DynamicLoad: return "dynamic-load";
    case StartupGateResult::WrongThread: return "wrong-thread";
    case StartupGateResult::WrongCaller: return "wrong-caller";
    case StartupGateResult::ImageUnavailable: return "image-unavailable";
    case StartupGateResult::ImageMismatch: return "image-mismatch";
    case StartupGateResult::CodeMismatch: return "code-mismatch";
    case StartupGateResult::WrongInitializer: return "wrong-initializer";
    case StartupGateResult::WrongStage: return "wrong-stage";
    }
    return "invalid-context";
}

} // namespace rs2fix
