#include "companion/steam_reporting_capture.h"
#include <limits>

namespace rs2fix::reporting {
namespace {
bool NtHeaders(std::uintptr_t base, IMAGE_NT_HEADERS64* nt) noexcept {
    // The module handle is owned/resident. Still contain malformed own-image
    // metadata rather than dereferencing a computed header address unchecked.
    const auto& memory = ProductionMemoryOps();
    MemoryRegion region{};
    DWORD error{};
    IMAGE_DOS_HEADER dos{};
    if (!base || !memory.query(memory.context, base, &region, &error) ||
        region.state != MEM_COMMIT || region.type != MEM_IMAGE ||
        region.allocationBase != base || region.protect != PAGE_READONLY ||
        !memory.read(memory.context, base, &dos, sizeof(dos), &error) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
        dos.e_lfanew > 0x100000 ||
        static_cast<std::uintptr_t>(dos.e_lfanew) > (std::numeric_limits<std::uintptr_t>::max)() - base)
        return false;
    const auto address = base + static_cast<std::uint32_t>(dos.e_lfanew);
    if (!memory.query(memory.context, address, &region, &error) ||
        region.state != MEM_COMMIT || region.type != MEM_IMAGE ||
        region.allocationBase != base || region.protect != PAGE_READONLY ||
        !memory.read(memory.context, address, nt, sizeof(*nt), &error)) return false;
    return nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        (nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
        nt->FileHeader.NumberOfSections>0 && nt->FileHeader.NumberOfSections<=96 &&
        nt->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt->OptionalHeader.NumberOfRvaAndSizes == IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        nt->OptionalHeader.SizeOfImage != 0 &&
        nt->OptionalHeader.SizeOfImage <= (std::numeric_limits<std::uintptr_t>::max)() - base &&
        nt->OptionalHeader.SizeOfHeaders<nt->OptionalHeader.SizeOfImage &&
        static_cast<std::uint32_t>(dos.e_lfanew)<nt->OptionalHeader.SizeOfHeaders &&
        sizeof(*nt)<=nt->OptionalHeader.SizeOfHeaders-static_cast<std::uint32_t>(dos.e_lfanew);
}
bool ModuleSectionMatches(std::uintptr_t base, const IMAGE_NT_HEADERS64& nt,
    std::uint32_t rva, std::size_t bytes, DWORD required, DWORD forbidden) noexcept {
    // The shared startup helper intentionally accepts EXE hosts only. Do not
    // relax that contract merely to qualify this DLL's own unwind/code ranges.
    const auto size=nt.OptionalHeader.SizeOfImage;
    const auto& memory=ProductionMemoryOps();
    IMAGE_DOS_HEADER dos{}; DWORD error{};
    if (!bytes || rva>=size || bytes>size-rva ||
        !ReadImageRange(base,size,0,&dos,sizeof(dos),memory,&error) ||
        dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<static_cast<LONG>(sizeof(dos)) ||
        static_cast<std::uint32_t>(dos.e_lfanew)>=nt.OptionalHeader.SizeOfHeaders) return false;
    const auto table=static_cast<std::uint64_t>(dos.e_lfanew)+sizeof(nt);
    IMAGE_SECTION_HEADER sections[96]{};
    const auto tableBytes=nt.FileHeader.NumberOfSections*sizeof(sections[0]);
    if (!nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections>96 ||
        table>=nt.OptionalHeader.SizeOfHeaders || tableBytes>nt.OptionalHeader.SizeOfHeaders-table ||
        !ReadImageRange(base,size,static_cast<std::uint32_t>(table),sections,tableBytes,memory,&error)) return false;
    unsigned found{};
    for (unsigned i=0;i<nt.FileHeader.NumberOfSections;++i) {
        const auto& section=sections[i];
        const auto length=section.Misc.VirtualSize;
        if (section.VirtualAddress>size || length>size-section.VirtualAddress) return false;
        if (rva<section.VirtualAddress || rva-section.VirtualAddress>=length ||
            bytes>length-(rva-section.VirtualAddress)) continue;
        if ((section.Characteristics&required)!=required || (section.Characteristics&forbidden)) return false;
        ++found;
    }
    return found==1;
}
struct FunctionEntry { std::uint32_t begin; std::uint32_t end; std::uint32_t unwind; };
// Chained unwind semantics (including multiple shrink-wrapping):
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
bool SameEntry(const FunctionEntry& a, const FunctionEntry& b) noexcept {
    return a.begin==b.begin && a.end==b.end && a.unwind==b.unwind;
}
bool EntryAt(std::uintptr_t base, const IMAGE_NT_HEADERS64& nt, std::uint32_t index,
    FunctionEntry* result) noexcept {
    const auto& directory=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    DWORD error{};
    return index<directory.Size/sizeof(FunctionEntry) && ReadImageRange(base,nt.OptionalHeader.SizeOfImage,
        directory.VirtualAddress+index*sizeof(FunctionEntry),result,sizeof(*result),ProductionMemoryOps(),&error);
}
bool DirectoryEntry(std::uintptr_t base, const IMAGE_NT_HEADERS64& nt, const FunctionEntry& entry) noexcept {
    // The compiler/Windows exception directory is sorted by BeginAddress. Never
    // trust an embedded chain triple without matching its actual directory row.
    std::uint32_t low=0,high=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size/12;
    while (low<high) {
        const auto mid=low+(high-low)/2;
        FunctionEntry candidate{};
        if (!EntryAt(base,nt,mid,&candidate)) return false;
        if (candidate.begin<entry.begin) low=mid+1;
        else if (candidate.begin>entry.begin) high=mid;
        else return SameEntry(candidate,entry);
    }
    return false;
}
bool RootEntry(std::uintptr_t base, const IMAGE_NT_HEADERS64& nt,
    FunctionEntry entry, FunctionEntry* root) noexcept {
    const auto size=nt.OptionalHeader.SizeOfImage;
    const auto& memory=ProductionMemoryOps();
    FunctionEntry visited[kCaptureFragmentLimit]{};
    for (std::size_t depth=0;depth<kCaptureFragmentLimit;++depth) {
        if (entry.begin>=entry.end || entry.end>size || (entry.unwind&3) ||
            !DirectoryEntry(base,nt,entry)) return false;
        for (std::size_t i=0;i<depth;++i) if (SameEntry(visited[i],entry)) return false;
        visited[depth]=entry;
        std::uint8_t header[4]{}; DWORD error{};
        if (!ReadImageRange(base,size,entry.unwind,header,sizeof(header),memory,&error) || (header[0]&7)!=1)
            return false;
        const auto flags=header[0]>>3;
        if (flags>4 || (flags&4 && flags!=4)) return false;
        const auto codes=static_cast<std::uint32_t>(header[2]);
        const auto tail=4+2*((codes+1)&~1U);
        const auto bytes=tail+(flags==4 ? 12U : flags ? 4U : 0U);
        if (!ModuleSectionMatches(base,nt,entry.unwind,bytes,IMAGE_SCN_MEM_READ,
                IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE) ||
            !ImageRangeProtection(base,size,entry.unwind,bytes,PAGE_READONLY,memory,&error)) return false;
        if (flags!=4) { *root=entry; return true; }
        if (!ReadImageRange(base,size,entry.unwind+tail,&entry,sizeof(entry),memory,&error)) return false;
    }
    return false;
}
bool FindScope(std::uintptr_t base, const IMAGE_NT_HEADERS64& nt,
    const void* function, CaptureScope* output) noexcept {
    const auto address = reinterpret_cast<std::uintptr_t>(function);
    const auto size = nt.OptionalHeader.SizeOfImage;
    const auto& directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (address < base || address - base >= size || !directory.VirtualAddress ||
        directory.Size < 12 || directory.Size % 12 || directory.Size / 12 > 65536 ||
        directory.VirtualAddress >= size || directory.Size > size - directory.VirtualAddress) return false;
    const auto& memory = ProductionMemoryOps();
    const auto rva = static_cast<std::uint32_t>(address - base);
    DWORD error{};
    FunctionEntry primary{};
    unsigned matches=0;
    std::uint32_t previousEnd{};
    // Validate directory order once while resolving the named function. MSVC
    // can split even a single noinline function into chained unwind fragments.
    for (std::uint32_t offset = 0; offset < directory.Size; offset += 12) {
        FunctionEntry entry{};
        if (!EntryAt(base,nt,offset/12,&entry) || entry.begin<previousEnd || entry.begin>=entry.end || entry.end>size)
            return false;
        previousEnd=entry.end;
        if (rva<entry.begin || rva>=entry.end) continue;
        if (++matches!=1 || !RootEntry(base,nt,entry,&primary)) return false;
    }
    if (matches!=1) return false;
    CaptureScope scope{};
    for (std::uint32_t offset=0;offset<directory.Size;offset+=12) {
        FunctionEntry entry{},root{};
        if (!EntryAt(base,nt,offset/12,&entry)) return false;
        // Unrelated CRT routines can use other unwind formats (including v2).
        // Such a range is NEVER admitted. Only exact, fully resolved v1 chains
        // ending at this named function's qualified primary become its scope.
        if (!RootEntry(base,nt,entry,&root)) continue;
        if (!SameEntry(root,primary)) continue;
        if (scope.fragmentCount==kCaptureFragmentLimit ||
            !ModuleSectionMatches(base, nt, entry.begin, entry.end-entry.begin,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE) ||
            !ImageRangeProtection(base, size, entry.begin, entry.end-entry.begin, PAGE_EXECUTE_READ, memory, &error))
            return false;
        scope.fragments[scope.fragmentCount++]={entry.begin,entry.end};
    }
    *output=scope;
    return scope.fragmentCount!=0;
}
} // namespace
bool PrepareCaptureProfile(HMODULE companion, std::uintptr_t hostBase,
    std::uint32_t hostSize, const void* const* callers, std::size_t callerCount,
    CaptureProfile* output) noexcept {
    if (output) *output = {};
    if (!output || !companion || !hostBase || !hostSize || !callers || !callerCount ||
        callerCount >= kCapturePrefixLimit || hostSize > (std::numeric_limits<std::uintptr_t>::max)() - hostBase)
        return false;
    const auto base = reinterpret_cast<std::uintptr_t>(companion);
    IMAGE_NT_HEADERS64 nt{};
    if (!NtHeaders(base, &nt)) return false;
    CaptureProfile profile{};
    profile.companionBase = base; profile.companionSize = nt.OptionalHeader.SizeOfImage;
    profile.hostBase = hostBase; profile.hostSize = hostSize;
    if (!FindScope(base, nt, reinterpret_cast<const void*>(&CaptureHostCallers), &profile.prefix[0])) return false;
    for (std::size_t i = 0; i < callerCount; ++i)
        if (!FindScope(base, nt, callers[i], &profile.prefix[i + 1])) return false;
    profile.prefixCount = callerCount + 1;
    *output = profile;
    return true;
}
__declspec(noinline) bool CaptureHostCallers(const CaptureProfile& profile,
    std::uint32_t (&hostFrames)[kCaptureFrames], std::size_t* count, bool* truncated) noexcept {
    if (count) *count = 0;
    if (truncated) *truncated = false;
    for (auto& frame : hostFrames) frame = kUnqualifiedHostFrame;
    if (!count || !truncated || !profile.prefixCount || profile.prefixCount > kCapturePrefixLimit)
        return false;
    void* frames[kCaptureFrames]{};
    const auto captured = CaptureStackBackTrace(0, static_cast<DWORD>(kCaptureFrames), frames, nullptr);
    *truncated = captured == kCaptureFrames;
    if (captured <= profile.prefixCount) return false;
    for (std::size_t i = 0; i < profile.prefixCount; ++i) {
        const auto address = reinterpret_cast<std::uintptr_t>(frames[i]);
        const auto& scope = profile.prefix[i];
        if (address < profile.companionBase || address - profile.companionBase >= profile.companionSize ||
            !scope.fragmentCount || scope.fragmentCount>kCaptureFragmentLimit)
            return false;
        bool found=false;
        for (std::size_t n=0;n<scope.fragmentCount;++n)
            found|=address-profile.companionBase>=scope.fragments[n].begin &&
                address-profile.companionBase<scope.fragments[n].end;
        if (!found) return false;
    }
    const auto remaining = captured - profile.prefixCount;
    for (std::size_t i = 0; i < remaining; ++i) {
        const auto address = reinterpret_cast<std::uintptr_t>(frames[profile.prefixCount + i]);
        if (address >= profile.hostBase && address - profile.hostBase < profile.hostSize)
            hostFrames[i] = static_cast<std::uint32_t>(address - profile.hostBase);
    }
    *count = remaining;
    return true;
}
} // namespace rs2fix::reporting
