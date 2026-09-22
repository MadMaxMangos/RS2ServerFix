#include "companion/steam_observer_profile.h"
#include "shared/path_identity.h"
#include <cstring>
#include <limits>

namespace rs2fix::observer {
namespace {
// Qualified PR3 instructions; full evidence stays outside the source tree.
// Accessor and getter prove the cached 013 path; the constructor store is [this].
constexpr std::uint8_t kAccessor[]{0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9,0xff,0x15,0x59,0x0a,0x44,0x00,0x48,0x8d,0x15,0xb2,0xd3,0x76,0x00,0x8b,0xc8,0xff,0x15,0x1a,0x0a,0x44,0x00,0x48,0x89,0x03,0x48,0x83,0xc4,0x20,0x5b,0xc3};
constexpr std::uint8_t kGetter[]{0x40,0x53,0x48,0x83,0xec,0x30,0x48,0xc7,0x44,0x24,0x20,0xfe,0xff,0xff,0xff,0x48,0x8b,0x05,0x9a,0xf4,0xd4,0x00,0x48,0x85,0xc0,0x75,0x3a,0x8d,0x50,0x08,0xb9,0xb0,0x00,0x00,0x00,0xe8,0xc8,0x45,0x60,0xff,0x48,0x8b,0xd8,0x48,0x89,0x44,0x24,0x40,0x48,0x85,0xc0,0x74,0x19,0x48,0x8d,0x0d,0xa4,0xb8,0xa5,0x00,0xff,0x15,0xe6,0xc2,0x44,0x00,0x48,0x8b,0x10,0x48,0x8b,0xcb,0xe8,0x43,0xb9,0xff,0xff,0x90,0x48,0x89,0x05,0x5b,0xf4,0xd4,0x00,0x48,0x83,0xc4,0x30,0x5b,0xc3};
constexpr std::uint8_t kConstructorStore[]{0x48,0x89,0x11};
constexpr ByteSpan kSpans[]{
    {0xA54B10,sizeof(kAccessor),kAccessor},
    {0xA49230,sizeof(kGetter),kGetter},
    {0xA44BF4,sizeof(kConstructorStore),kConstructorStore}
};
constexpr Profile kProduction{
    {0x0d,0x8f,0x32,0x22,0xad,0x79,0x6b,0x02,0x4f,0xb5,0x25,0x11,0x86,0x58,0xbb,0x1c,0xe9,0x46,0xe4,0x35,0x7e,0x35,0xba,0x6e,0x5e,0xcd,0x12,0x78,0x83,0x75,0x73,0x93}, {0xa4,0x4e,0x55,0x37,0x93,0x9a,0xe4,0xee,0xbc,0x69,0x00,0x05,0x89,0xaa,0x9b,0x24,0x37,0xa6,0x67,0x81,0x3a,0x16,0x57,0xcc,0x77,0x91,0x98,0xba,0xe9,0xb8,0x15,0xa9},
    0x4D000,0x644C1ACD,0x4D627,
    0xE95548,0xE955A0,0xE955C0,0xA54B10,0xA54B2E,0x11C1ED8,
    0x14A4B10,0x17986E0,0x17981A0,0xA2CE07,0xA2AD5E,
    "steam_api64.dll",kSpans,sizeof(kSpans)/sizeof(kSpans[0])
};
constexpr const char* kExports[]{
    "SteamInternal_FindOrCreateGameServerInterface",
    "SteamGameServer_Shutdown", "SteamInternal_GameServer_Init"
};
bool Executable(DWORD p) noexcept {
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}
bool Readable(DWORD p) noexcept {
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
        p == PAGE_EXECUTE_WRITECOPY;
}
bool ReadableRange(std::uintptr_t address, std::size_t size, const MemoryOps& ops) noexcept {
    if (!address || !size || size>(std::numeric_limits<std::uintptr_t>::max)()-address)
        return false;
    const auto end=address+size;
    while (address<end) {
        MemoryRegion region{};
        DWORD error{};
        if (!ops.query(ops.context,address,&region,&error) || region.state!=MEM_COMMIT ||
            !Readable(region.protect) || region.base>address || !region.size ||
            region.size>(std::numeric_limits<std::uintptr_t>::max)()-region.base ||
            region.base+region.size<=address) return false;
        address=(region.base+region.size<end) ? region.base+region.size : end;
    }
    return true;
}
bool ImageNt(std::uintptr_t base, std::uint32_t size, const MemoryOps& ops,
    IMAGE_NT_HEADERS64* nt, DWORD* error) noexcept {
    IMAGE_DOS_HEADER dos{};
    if (!ReadImageRange(base,size,0,&dos,sizeof(dos),ops,error) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos) ||
        dos.e_lfanew > 0x100000 ||
        !ReadImageRange(base,size,static_cast<std::uint32_t>(dos.e_lfanew),
            nt,sizeof(*nt),ops,error)) return false;
    return nt->Signature == IMAGE_NT_SIGNATURE &&
        nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        nt->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt->OptionalHeader.SizeOfImage == size &&
        nt->OptionalHeader.NumberOfRvaAndSizes == IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        nt->FileHeader.NumberOfSections > 0 && nt->FileHeader.NumberOfSections <= 96;
}
bool EqualImageString(std::uintptr_t base, std::uint32_t size, std::uint32_t rva,
    const char* expected, bool ignoreCase, const MemoryOps& ops) noexcept {
    // Only PE metadata names are read. No SDK argument or arbitrary interface
    // string is inspected. This bounded comparison also requires the terminator.
    for (std::uint32_t i=0; i<260; ++i) {
        if (rva > UINT32_MAX-i) return false;
        char got{};
        DWORD error{};
        if (!ReadImageRange(base,size,rva+i,&got,1,ops,&error)) return false;
        char want=expected[i];
        if (ignoreCase) {
            if (got>='A' && got<='Z') got=static_cast<char>(got+('a'-'A'));
            if (want>='A' && want<='Z') want=static_cast<char>(want+('a'-'A'));
        }
        if (got!=want) return false;
        if (!want) return true;
    }
    return false;
}
bool NamedImport(std::uintptr_t base, std::uint32_t size, std::uint32_t iatRva,
    const char* module, const char* name, const MemoryOps& ops) noexcept {
    IMAGE_NT_HEADERS64 nt{};
    DWORD error{};
    if (!ImageNt(base,size,ops,&nt,&error)) return false;
    const auto& imports=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imports.VirtualAddress || imports.VirtualAddress >= size ||
        imports.Size > size-imports.VirtualAddress) return false;
    bool found=false;
    const std::uint32_t count=imports.Size/sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (count>256) return false;
    for (std::uint32_t i=0; i<count; ++i) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!ReadImageRange(base,size,imports.VirtualAddress+i*sizeof(desc),
            &desc,sizeof(desc),ops,&error)) return false;
        if (!desc.Name && !desc.FirstThunk && !desc.OriginalFirstThunk) return found;
        if (!EqualImageString(base,size,desc.Name,module,true,ops)) continue;
        if (!desc.OriginalFirstThunk || iatRva<desc.FirstThunk ||
            ((iatRva-desc.FirstThunk)%sizeof(std::uint64_t))) return false;
        const auto offset=iatRva-desc.FirstThunk;
        if (offset/sizeof(std::uint64_t)>4096 || desc.OriginalFirstThunk>UINT32_MAX-offset)
            return false;
        std::uint64_t lookup{};
        if (!ReadImageRange(base,size,desc.OriginalFirstThunk+offset,
            &lookup,sizeof(lookup),ops,&error) || !lookup ||
            IMAGE_SNAP_BY_ORDINAL64(lookup) || lookup>UINT32_MAX-2 ||
            !EqualImageString(base,size,static_cast<std::uint32_t>(lookup)+2,name,false,ops) ||
            found) return false;
        found=true;
    }
    return false; // A bounded descriptor table must include its null terminator.
}
bool CodeAddress(std::uintptr_t module, std::uint32_t imageSize,
    std::uintptr_t address, const MemoryOps& ops) noexcept {
    if (address<module || address-module>=imageSize) return false;
    MemoryRegion region{};
    DWORD error{};
    return ops.query && ops.query(ops.context,address,&region,&error) &&
        region.state==MEM_COMMIT && region.type==MEM_IMAGE &&
        region.allocationBase==module && Executable(region.protect);
}
bool ExportAddress(std::uintptr_t module, std::uint32_t size, const char* name,
    const MemoryOps& ops, std::uintptr_t* address) noexcept {
    IMAGE_NT_HEADERS64 nt{};
    DWORD error{};
    if (!ImageNt(module,size,ops,&nt,&error)) return false;
    const auto& dir=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || dir.VirtualAddress>=size ||
        dir.Size<sizeof(IMAGE_EXPORT_DIRECTORY) || dir.Size>size-dir.VirtualAddress) return false;
    IMAGE_EXPORT_DIRECTORY exports{};
    if (!ReadImageRange(module,size,dir.VirtualAddress,&exports,sizeof(exports),ops,&error) ||
        !exports.NumberOfNames || exports.NumberOfNames>65536 ||
        !exports.NumberOfFunctions || exports.NumberOfFunctions>65536) return false;
    bool found=false;
    for (DWORD i=0; i<exports.NumberOfNames; ++i) {
        if (exports.AddressOfNames>UINT32_MAX-i*4 ||
            exports.AddressOfNameOrdinals>UINT32_MAX-i*2) return false;
        std::uint32_t nameRva{};
        if (!ReadImageRange(module,size,exports.AddressOfNames+i*4,
            &nameRva,sizeof(nameRva),ops,&error)) return false;
        if (!EqualImageString(module,size,nameRva,name,false,ops)) continue;
        WORD ordinal{};
        std::uint32_t codeRva{};
        if (found || !ReadImageRange(module,size,exports.AddressOfNameOrdinals+i*2,
            &ordinal,sizeof(ordinal),ops,&error) || ordinal>=exports.NumberOfFunctions ||
            exports.AddressOfFunctions>UINT32_MAX-static_cast<std::uint32_t>(ordinal)*4 ||
            !ReadImageRange(module,size,exports.AddressOfFunctions+ordinal*4,
                &codeRva,sizeof(codeRva),ops,&error) ||
            (codeRva>=dir.VirtualAddress && codeRva-dir.VirtualAddress<dir.Size) ||
            codeRva>=size || !CodeAddress(module,size,module+codeRva,ops)) return false;
        *address=module+codeRva;
        found=true;
    }
    return found;
}
} // namespace

const Profile& ProductionObserverProfile() noexcept { return kProduction; }

Reason CheckColdProfile(const BootstrapContextV3& context, const StartupProfile& startup,
    const Profile& profile, const MemoryOps& ops, DWORD* error) noexcept {
    if (error) *error=ERROR_INVALID_DATA;
    if (CheckStartupOpportunity(context,startup,ops)!=StartupGateResult::Ready)
        return Reason::InvalidContext;
    const auto base=reinterpret_cast<std::uintptr_t>(context.hostModule);
    if (!profile.spans || !profile.spanCount || profile.spanCount>8 ||
        !profile.accessorRva || profile.accessorRva>=startup.imageSize ||
        profile.factoryReturnRva>=startup.imageSize) return Reason::ProfileMismatch;
    std::uint8_t scratch[1024]{};
    for (std::size_t i=0; i<profile.spanCount; ++i) {
        const auto& span=profile.spans[i];
        if (!span.bytes || !span.size || span.size>sizeof(scratch) ||
            !ImageSectionMatches(base,startup.imageSize,span.rva,span.size,
                IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_DISCARDABLE,ops) ||
            !ReadImageRange(base,startup.imageSize,span.rva,scratch,span.size,ops,error) ||
            std::memcmp(scratch,span.bytes,span.size)) return Reason::ProfileMismatch;
    }
    char literal[sizeof(kInterfaceVersion)]{};
    if (!ReadImageRange(base,startup.imageSize,profile.literalRva,
        literal,sizeof(literal),ops,error) ||
        std::memcmp(literal,kInterfaceVersion,sizeof(literal))) return Reason::ProfileMismatch;
    struct ContextCache { std::uintptr_t callback; std::uint64_t counter; void* object; } cache{};
    std::uintptr_t privateObject{}, publication{};
    if ((profile.contextRva|profile.privateRva|profile.publicationRva)&7)
        return Reason::ProfileMismatch;
    if (!ReadImageRange(base,startup.imageSize,profile.contextRva,&cache,sizeof(cache),ops,error) ||
        !ReadImageRange(base,startup.imageSize,profile.privateRva,&privateObject,sizeof(privateObject),ops,error) ||
        !ReadImageRange(base,startup.imageSize,profile.publicationRva,&publication,sizeof(publication),ops,error))
        return Reason::ProfileMismatch;
    if (cache.callback!=base+profile.accessorRva) return Reason::ProfileMismatch;
    if (cache.counter || cache.object || privateObject || publication)
        return Reason::AlreadyInitialized;
    if (error) *error=ERROR_SUCCESS;
    return Reason::None;
}

Reason QualifySdk(const BootstrapContextV3& context, const StartupProfile& startup,
    const Profile& profile, HostHashLease* sdkLease, DispatchConfig* config, DWORD* error) noexcept {
    if (error) *error=ERROR_INVALID_DATA;
    if (!sdkLease || !config || !profile.importModule || !profile.sdkImageSize)
        return Reason::SdkBindingMismatch;
    const auto base=reinterpret_cast<std::uintptr_t>(context.hostModule);
    const auto& ops=ProductionMemoryOps();
    const std::uint32_t iats[]{profile.factoryIatRva,profile.shutdownIatRva,profile.initIatRva};
    std::uintptr_t targets[3]{};
    HMODULE sdk{};
    for (unsigned i=0; i<3; ++i) {
        if ((iats[i]&7) || !ImageSectionMatches(base,startup.imageSize,iats[i],8,
            IMAGE_SCN_MEM_READ,IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE,ops) ||
            !NamedImport(base,startup.imageSize,iats[i],profile.importModule,kExports[i],ops) ||
            !ReadImageRange(base,startup.imageSize,iats[i],&targets[i],sizeof(targets[i]),ops,error) ||
            !targets[i]) return Reason::SdkBindingMismatch;
        HMODULE owner{};
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(targets[i]),&owner) || !owner ||
            (sdk && sdk!=owner)) return Reason::SdkBindingMismatch;
        sdk=owner;
    }
    const auto sdkBase=reinterpret_cast<std::uintptr_t>(sdk);
    IMAGE_NT_HEADERS64 nt{};
    if (!ImageNt(sdkBase,profile.sdkImageSize,ops,&nt,error) ||
        !(nt.FileHeader.Characteristics&IMAGE_FILE_DLL) ||
        nt.FileHeader.TimeDateStamp!=profile.sdkTimestamp ||
        nt.OptionalHeader.CheckSum!=profile.sdkChecksum) return Reason::SdkIdentityMismatch;
    // This storage is startup-only, not retained by a wrapper or writer.
    auto* path=static_cast<wchar_t*>(VirtualAlloc(nullptr,kPathCapacity*sizeof(wchar_t),
        MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!path) { if (error) *error=GetLastError(); return Reason::PreparationFailed; }
    Reason result=Reason::SdkIdentityMismatch;
    if (GetBoundedModulePath(sdk,path,kPathCapacity,error)) {
        const auto hash=AcquireHostHash(path,sdkLease);
        if (hash.reason==FixReason::None && hash.hash.digestValid &&
            hash.hash.digest==profile.sdkDigest && sdkLease->valid()) result=Reason::None;
        else if (error) *error=hash.hash.error;
    }
    VirtualFree(path,0,MEM_RELEASE);
    if (result!=Reason::None) return result;
    for (unsigned i=0; i<3; ++i) {
        std::uintptr_t exported{};
        if (!ExportAddress(sdkBase,profile.sdkImageSize,kExports[i],ops,&exported) ||
            exported!=targets[i]) return Reason::SdkBindingMismatch;
    }
    *config={base,startup.imageSize,profile.factoryReturnRva,
        reinterpret_cast<const char*>(base+profile.literalRva),
        profile.publisherReturnRva,profile.advertiseReturnRva,
        reinterpret_cast<FactoryFn>(targets[0]),reinterpret_cast<InitFn>(targets[2]),
        reinterpret_cast<ShutdownFn>(targets[1]),nullptr,ValidateInterfaceObject};
    if (error) *error=ERROR_SUCCESS;
    return Reason::None;
}

Reason QualifyServerPump(const BootstrapContextV3& context, const StartupProfile& startup,
    const Profile& profile, const DispatchConfig& dispatch, std::uint32_t iatRva,
    ShutdownFn* original, DWORD* error) noexcept {
    if (error) *error=ERROR_INVALID_DATA;
    if (original) *original=nullptr;
    if (!original || !dispatch.init || !profile.importModule || !profile.sdkImageSize)
        return Reason::SdkBindingMismatch;
    const auto base=reinterpret_cast<std::uintptr_t>(context.hostModule);
    const auto& ops=ProductionMemoryOps();
    constexpr char name[]="SteamGameServer_RunCallbacks";
    std::uintptr_t target{};
    if ((iatRva&7) || !ImageSectionMatches(base,startup.imageSize,iatRva,sizeof(target),
            IMAGE_SCN_MEM_READ,IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE,ops) ||
        !NamedImport(base,startup.imageSize,iatRva,profile.importModule,name,ops) ||
        !ReadImageRange(base,startup.imageSize,iatRva,&target,sizeof(target),ops,error) ||
        !target) return Reason::SdkBindingMismatch;
    HMODULE sdk{}, pumpOwner{};
    constexpr DWORD flags=GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if (!GetModuleHandleExW(flags,reinterpret_cast<LPCWSTR>(dispatch.init),&sdk) || !sdk ||
        !GetModuleHandleExW(flags,reinterpret_cast<LPCWSTR>(target),&pumpOwner) ||
        pumpOwner!=sdk) return Reason::SdkBindingMismatch;
    const auto sdkBase=reinterpret_cast<std::uintptr_t>(sdk);
    IMAGE_NT_HEADERS64 nt{};
    if (!ImageNt(sdkBase,profile.sdkImageSize,ops,&nt,error) ||
        !(nt.FileHeader.Characteristics&IMAGE_FILE_DLL) ||
        nt.FileHeader.TimeDateStamp!=profile.sdkTimestamp ||
        nt.OptionalHeader.CheckSum!=profile.sdkChecksum) return Reason::SdkIdentityMismatch;
    // A forwarded export or another module's identically named pump is not the
    // binding qualified for this already-leased Init implementation.
    std::uintptr_t exported{}, initExport{};
    if (!ExportAddress(sdkBase,profile.sdkImageSize,name,ops,&exported) || exported!=target ||
        !ExportAddress(sdkBase,profile.sdkImageSize,kExports[2],ops,&initExport) ||
        initExport!=reinterpret_cast<std::uintptr_t>(dispatch.init))
        return Reason::SdkBindingMismatch;
    *original=reinterpret_cast<ShutdownFn>(target);
    if (error) *error=ERROR_SUCCESS;
    return Reason::None;
}

bool ValidateInterfaceObject(void* memoryOps, void* object) noexcept {
    const MemoryOps& ops=memoryOps ? *static_cast<const MemoryOps*>(memoryOps) : ProductionMemoryOps();
    const auto address=reinterpret_cast<std::uintptr_t>(object);
    if (!address || (address&7) || !ops.query || !ops.read) return false;
    MemoryRegion region{};
    DWORD error{};
    std::uintptr_t table{};
    if (!ReadableRange(address,sizeof(table),ops) ||
        !ops.read(ops.context,address,&table,sizeof(table),&error) || !table || (table&7) ||
        table>(std::numeric_limits<std::uintptr_t>::max)()-kSlotCount*sizeof(void*)) return false;
    std::uintptr_t entries[kSlotCount]{};
    // Guarded copy, not VirtualQuery followed by an unguarded heap dereference.
    if (!ReadableRange(table,sizeof(entries),ops) ||
        !ops.read(ops.context,table,entries,sizeof(entries),&error)) return false;
    for (const auto entry: entries) {
        if (!entry || !ops.query(ops.context,entry,&region,&error) ||
            region.state!=MEM_COMMIT || !Executable(region.protect)) return false;
    }
    return true;
}
} // namespace rs2fix::observer
