#include "companion/steam_reporting_profile.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace rs2fix::reporting {
namespace {
#include "companion/steam_reporting_profile_data.inc"

constexpr ReportingIdentities kIdentities{
    {0x0d,0x8f,0x32,0x22,0xad,0x79,0x6b,0x02,0x4f,0xb5,0x25,0x11,0x86,0x58,0xbb,0x1c,0xe9,0x46,0xe4,0x35,0x7e,0x35,0xba,0x6e,0x5e,0xcd,0x12,0x78,0x83,0x75,0x73,0x93},
    {0xa4,0x4e,0x55,0x37,0x93,0x9a,0xe4,0xee,0xbc,0x69,0x00,0x05,0x89,0xaa,0x9b,0x24,0x37,0xa6,0x67,0x81,0x3a,0x16,0x57,0xcc,0x77,0x91,0x98,0xba,0xe9,0xb8,0x15,0xa9},
    {0x81,0x65,0xd2,0xa8,0xe8,0x27,0x53,0xe5,0xcd,0x5a,0xd9,0x85,0xd6,0xd0,0x8c,0x23,0x79,0xe0,0xaa,0x8d,0x03,0x40,0x66,0x9b,0xcf,0x05,0x89,0x05,0x84,0xf5,0x1a,0xce},
    0x1766000,0x685F401F,0x17153E7
};

struct ImageContext {
    std::uintptr_t base;
    std::uint32_t size;
    std::uint32_t sectionTable;
    IMAGE_NT_HEADERS64 nt;
    const MemoryOps* memory;
    DWORD* error;
};
constexpr DWORD kImmutableForbidden = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

bool Range(std::uint32_t imageSize, std::uint32_t rva, std::size_t size) noexcept {
    return size && rva < imageSize && size <= imageSize - rva;
}
bool Overlaps(std::uint32_t a, std::size_t an, std::uint32_t b, std::size_t bn) noexcept {
    return static_cast<std::uint64_t>(a) < static_cast<std::uint64_t>(b) + bn &&
        static_cast<std::uint64_t>(b) < static_cast<std::uint64_t>(a) + an;
}
bool Read(const ImageContext& image, std::uint32_t rva, void* out,
    std::size_t size) noexcept {
    return size <= kProfileReadChunk && ReadImageRange(image.base,image.size,rva,
        out,size,*image.memory,image.error);
}
bool Protection(const ImageContext& image, std::uint32_t rva,
    std::size_t size, DWORD expected) noexcept {
    return ImageRangeProtection(image.base,image.size,rva,size,expected,
        *image.memory,image.error);
}
bool Section(const ImageContext& image, std::uint32_t rva, std::size_t size,
    DWORD required, DWORD forbidden) noexcept {
    if (!Range(image.size,rva,size)) return false;
    unsigned matches{};
    std::uint64_t previousEnd{};
    for (WORD i=0; i<image.nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        const auto slot=image.sectionTable+static_cast<std::uint32_t>(i)*sizeof(section);
        if (!Read(image,static_cast<std::uint32_t>(slot),&section,sizeof(section))) return false;
        const auto start=section.VirtualAddress;
        const auto length=section.Misc.VirtualSize;
        if (start > image.size || length > image.size-start || start < previousEnd) return false;
        previousEnd=static_cast<std::uint64_t>(start)+length;
        if (rva >= start && rva-start < length && size <= length-(rva-start)) {
            if ((section.Characteristics&required)!=required ||
                (section.Characteristics&forbidden)) return false;
            ++matches;
        }
    }
    return matches==1;
}
bool Immutable(const ImageContext& image, std::uint32_t rva, std::size_t size) noexcept {
    return Protection(image,rva,size,PAGE_READONLY) && Section(image,rva,size,
        IMAGE_SCN_MEM_READ,kImmutableForbidden|IMAGE_SCN_MEM_DISCARDABLE);
}
bool Headers(ImageContext& image, const StartupProfile& host) noexcept {
    IMAGE_DOS_HEADER dos{};
    if (!Protection(image,0,sizeof(dos),PAGE_READONLY) || !Read(image,0,&dos,sizeof(dos)) ||
        dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<static_cast<LONG>(sizeof(dos)) ||
        dos.e_lfanew>0x100000) return false;
    const auto ntRva=static_cast<std::uint32_t>(dos.e_lfanew);
    if (!Protection(image,ntRva,sizeof(image.nt),PAGE_READONLY) ||
        !Read(image,ntRva,&image.nt,sizeof(image.nt))) return false;
    const auto& nt=image.nt;
    if (nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 ||
        !(nt.FileHeader.Characteristics&IMAGE_FILE_EXECUTABLE_IMAGE) ||
        (nt.FileHeader.Characteristics&IMAGE_FILE_DLL) ||
        nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.FileHeader.NumberOfSections==0 || nt.FileHeader.NumberOfSections>96 ||
        nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage!=image.size ||
        nt.OptionalHeader.NumberOfRvaAndSizes!=IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
        nt.FileHeader.TimeDateStamp!=host.timestamp ||
        nt.OptionalHeader.AddressOfEntryPoint!=host.entryRva) return false;
    bool checksum{};
    for (std::size_t i=0; i<host.checksumCount; ++i)
        checksum=checksum || nt.OptionalHeader.CheckSum==host.checksums[i];
    if (!checksum) return false;
    const auto table=static_cast<std::uint64_t>(ntRva)+sizeof(nt);
    const auto tableBytes=static_cast<std::size_t>(nt.FileHeader.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER);
    if (nt.OptionalHeader.SizeOfHeaders>=image.size || table>nt.OptionalHeader.SizeOfHeaders ||
        tableBytes>nt.OptionalHeader.SizeOfHeaders-table) return false;
    image.sectionTable=static_cast<std::uint32_t>(table);
    return Protection(image,image.sectionTable,tableBytes,PAGE_READONLY);
}

bool Covered(const ReportingProfile& profile, std::uint32_t rva,
    std::size_t size, SpanKind kind) noexcept {
    for (std::size_t i=0; i<profile.spanCount; ++i) {
        const auto& item=profile.spans[i];
        if (item.kind==kind && rva>=item.span.rva &&
            rva-item.span.rva<item.span.size && size<=item.span.size-(rva-item.span.rva)) return true;
    }
    return false;
}
bool ProfileShape(const StartupProfile& host, const ReportingProfile& p) noexcept {
    if (!host.imageSize || !host.checksumCount || host.checksumCount>2 ||
        !p.spans || !p.spanCount || p.spanCount>kProfileSpanLimit ||
        !p.pointers || !p.pointerCount || p.pointerCount>kProfilePointerLimit ||
        !p.exceptions || !p.exceptionCount || p.exceptionCount>kProfileExceptionLimit ||
        !p.pump.module || !p.pump.name || (p.pump.slotRva&7) ||
        !Range(host.imageSize,p.pump.slotRva,sizeof(std::uintptr_t))) return false;
    std::size_t bytes=p.pointerCount*8+p.exceptionCount*12+8;
    for (std::size_t i=0; i<p.spanCount; ++i) {
        const auto& item=p.spans[i];
        const auto& span=item.span;
        if (!span.bytes || !span.size || span.size>kProfileSpanBytes ||
            !Range(host.imageSize,span.rva,span.size) ||
            (item.kind!=SpanKind::Code && item.kind!=SpanKind::ImmutableData) ||
            span.size>kProfileByteBudget-bytes) return false;
        bytes+=span.size;
        if (Overlaps(span.rva,span.size,p.pump.slotRva,8)) return false;
        for (std::size_t j=0; j<i; ++j)
            if (Overlaps(span.rva,span.size,p.spans[j].span.rva,p.spans[j].span.size)) return false;
    }
    for (std::size_t i=0; i<p.pointerCount; ++i) {
        const auto& pointer=p.pointers[i];
        if ((pointer.slotRva&7) || !Range(host.imageSize,pointer.slotRva,8) ||
            !Range(host.imageSize,pointer.targetRva,1) || Overlaps(pointer.slotRva,8,p.pump.slotRva,8)) return false;
        for (std::size_t j=0; j<i; ++j)
            if (Overlaps(pointer.slotRva,8,p.pointers[j].slotRva,8)) return false;
        for (std::size_t j=0; j<p.spanCount; ++j)
            if (Overlaps(pointer.slotRva,8,p.spans[j].span.rva,p.spans[j].span.size)) return false;
    }
    for (std::size_t i=0; i<p.exceptionCount; ++i) {
        const auto& e=p.exceptions[i];
        if ((e.entryRva&3) || (e.unwindRva&3) || e.beginRva>=e.endRva ||
            !Range(host.imageSize,e.entryRva,12) || !Range(host.imageSize,e.beginRva,e.endRva-e.beginRva) ||
            !Covered(p,e.beginRva,e.endRva-e.beginRva,SpanKind::Code) ||
            !Covered(p,e.unwindRva,4,SpanKind::ImmutableData) || Overlaps(e.entryRva,12,p.pump.slotRva,8)) return false;
        for (std::size_t j=0; j<i; ++j)
            if (Overlaps(e.entryRva,12,p.exceptions[j].entryRva,12)) return false;
        for (std::size_t j=0; j<p.pointerCount; ++j)
            if (Overlaps(e.entryRva,12,p.pointers[j].slotRva,8)) return false;
        for (std::size_t j=0; j<p.spanCount; ++j)
            if (Overlaps(e.entryRva,12,p.spans[j].span.rva,p.spans[j].span.size)) return false;
    }
    return true;
}

bool Exceptions(const ImageContext& image, const ReportingProfile& p) noexcept {
    const auto& directory=image.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!directory.VirtualAddress || !directory.Size || directory.Size%12 ||
        !Range(image.size,directory.VirtualAddress,directory.Size)) return false;
    for (std::size_t i=0; i<p.exceptionCount; ++i) {
        const auto& expected=p.exceptions[i];
        if (expected.entryRva<directory.VirtualAddress ||
            (expected.entryRva-directory.VirtualAddress)%12 ||
            expected.entryRva-directory.VirtualAddress>directory.Size-12 ||
            !Immutable(image,expected.entryRva,12)) return false;
        std::uint32_t record[3]{};
        if (!Read(image,expected.entryRva,record,sizeof(record)) ||
            record[0]!=expected.beginRva || record[1]!=expected.endRva || record[2]!=expected.unwindRva) return false;
        std::uint8_t header[4]{};
        if (!Read(image,expected.unwindRva,header,sizeof(header))) return false;
        const auto flags=header[0]>>3;
        if ((header[0]&7)!=1 || flags>7 || ((flags&4) && (flags&3))) return false;
        const std::size_t length=4+2*((static_cast<std::size_t>(header[2])+1)&~std::size_t{1})+
            ((flags&4) ? 12 : (flags&3) ? 4 : 0);
        if (!Covered(p,expected.unwindRva,length,SpanKind::ImmutableData)) return false;
    }
    return true;
}

bool NameEquals(const ImageContext& image, std::uint32_t rva, const char* expected,
    bool ignoreCase) noexcept {
    for (std::uint32_t i=0; i<128; ++i) {
        if (rva>UINT32_MAX-i) return false;
        char got{}, want=expected[i];
        if (!Read(image,rva+i,&got,1)) return false;
        if (ignoreCase) {
            if (got>='A' && got<='Z') got=static_cast<char>(got+('a'-'A'));
            if (want>='A' && want<='Z') want=static_cast<char>(want+('a'-'A'));
        }
        if (got!=want) return false;
        if (!want) return true;
    }
    return false;
}
bool PumpImport(const ImageContext& image, const PumpImportRecipe& p,
    std::uintptr_t* original) noexcept {
    const auto& directory=image.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || directory.Size<sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        directory.Size/sizeof(IMAGE_IMPORT_DESCRIPTOR)>256 ||
        !Range(image.size,directory.VirtualAddress,directory.Size) ||
        !Section(image,p.slotRva,8,IMAGE_SCN_MEM_READ,IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE) ||
        !(Protection(image,p.slotRva,8,PAGE_READONLY) || Protection(image,p.slotRva,8,PAGE_READWRITE))) return false;
    bool found{};
    const auto count=directory.Size/sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (std::uint32_t i=0; i<count; ++i) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        const auto rva=directory.VirtualAddress+i*static_cast<std::uint32_t>(sizeof(descriptor));
        if (!Read(image,rva,&descriptor,sizeof(descriptor))) return false;
        if (!descriptor.Name && !descriptor.FirstThunk && !descriptor.OriginalFirstThunk) {
            return found && Read(image,p.slotRva,original,sizeof(*original)) && *original!=0;
        }
        if (!NameEquals(image,descriptor.Name,p.module,true)) continue;
        if (!descriptor.OriginalFirstThunk || p.slotRva<descriptor.FirstThunk ||
            ((p.slotRva-descriptor.FirstThunk)&7)) return false;
        const auto offset=p.slotRva-descriptor.FirstThunk;
        if (offset/8>4096 || descriptor.OriginalFirstThunk>UINT32_MAX-offset) return false;
        std::uint64_t lookup{};
        if (found || !Read(image,descriptor.OriginalFirstThunk+offset,&lookup,sizeof(lookup)) ||
            !lookup || IMAGE_SNAP_BY_ORDINAL64(lookup) || lookup>UINT32_MAX-2 ||
            !NameEquals(image,static_cast<std::uint32_t>(lookup)+2,p.name,false)) return false;
        found=true;
    }
    return false;
}
} // namespace

const ReportingProfile& ProductionReportingProfile() noexcept { return kReportingProduction; }
const ReportingIdentities& ProductionReportingIdentities() noexcept { return kIdentities; }
const char* ReportingProfileInventorySha256() noexcept { return kInventorySha256; }

ProfileResult ValidateReportingProfile(std::uintptr_t base, const StartupProfile& host,
    const ReportingProfile& profile, const MemoryOps& memory,
    std::uintptr_t* pumpOriginal, DWORD* error) noexcept {
    if (error) *error=ERROR_INVALID_DATA;
    if (pumpOriginal) *pumpOriginal=0;
    if (!base || !memory.read || !memory.query || !pumpOriginal ||
        host.imageSize>(std::numeric_limits<std::uintptr_t>::max)()-base ||
        !ProfileShape(host,profile)) return ProfileResult::InvalidProfile;
    ImageContext image{base,host.imageSize,0,{},&memory,error};
    if (!Headers(image,host)) return ProfileResult::ImageMismatch;
    std::uint8_t scratch[kProfileReadChunk]{};
    for (std::size_t i=0; i<profile.spanCount; ++i) {
        const auto& item=profile.spans[i];
        const auto& span=item.span;
        const bool code=item.kind==SpanKind::Code;
        if (!(code ? Protection(image,span.rva,span.size,PAGE_EXECUTE_READ) &&
                Section(image,span.rva,span.size,IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE,
                    IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_DISCARDABLE) : Immutable(image,span.rva,span.size)))
            return ProfileResult::ProtectionMismatch;
        for (std::size_t offset=0; offset<span.size;) {
            const auto size=(std::min)(kProfileReadChunk,span.size-offset);
            if (!Read(image,span.rva+static_cast<std::uint32_t>(offset),scratch,size) ||
                std::memcmp(scratch,span.bytes+offset,size)) return ProfileResult::BytesMismatch;
            offset+=size;
        }
    }
    for (std::size_t i=0; i<profile.pointerCount; ++i) {
        const auto& pointer=profile.pointers[i];
        std::uintptr_t actual{};
        if (!Immutable(image,pointer.slotRva,8) ||
            !Protection(image,pointer.targetRva,1,PAGE_EXECUTE_READ) ||
            !Section(image,pointer.targetRva,1,IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE,IMAGE_SCN_MEM_WRITE) ||
            !Read(image,pointer.slotRva,&actual,sizeof(actual)) || actual!=base+pointer.targetRva)
            return ProfileResult::PointerMismatch;
    }
    if (!Exceptions(image,profile)) return ProfileResult::UnwindMismatch;
    // Relocation coverage is part of the approved, hash-bound generation input.
    // The loader may discard .reloc even before CRT startup. Exact final bytes
    // above and live-base pointer recipes detect unapproved relocation effects
    // without imposing residency of discardable loader metadata.
    std::uintptr_t original{};
    if (!PumpImport(image,profile.pump,&original)) return ProfileResult::ImportMismatch;
    *pumpOriginal=original;
    if (error) *error=ERROR_SUCCESS;
    return ProfileResult::Ready;
}
} // namespace rs2fix::reporting
