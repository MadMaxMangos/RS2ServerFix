#pragma once
#include "shared/startup_profile.h"
#include <limits>

namespace rs2fix::reporting {
inline constexpr std::size_t kReadScopeRegions=24;

// Stack-owned metadata cache for ONE bounded, synchronous observation. Native
// bytes are never cached, and no region grants lifetime or write authority.
// Reset between independent observations. Final mutation checks use the root
// uncached MemoryOps, never these adapters. Cache saturation is only a miss.
class ReadScope {
public:
    explicit ReadScope(const MemoryOps& original) noexcept : original_(original),
        ops_{this,original.query ? Query : nullptr,original.read ? Read : nullptr} {}
    ReadScope(const ReadScope&)=delete;
    ReadScope& operator=(const ReadScope&)=delete;
    ReadScope(ReadScope&&)=delete;
    ReadScope& operator=(ReadScope&&)=delete;
    const MemoryOps& Ops() const noexcept { return ops_; }
    void Reset() noexcept { count_=0; } // Old entries are inaccessible, not authority for a later pass.

private:
    MemoryOps original_;
    MemoryOps ops_;
    MemoryRegion regions_[kReadScopeRegions]{};
    std::size_t count_{};

    static bool Cacheable(const MemoryRegion& region,std::uintptr_t address) noexcept {
        if (!region.size || region.base>address ||
            region.size>(std::numeric_limits<std::uintptr_t>::max)()-region.base ||
            address-region.base>=region.size || region.state!=MEM_COMMIT ||
            !region.allocationBase || region.allocationBase>region.base ||
            (region.type!=MEM_PRIVATE && region.type!=MEM_IMAGE && region.type!=MEM_MAPPED)) return false;
        // Unknown modifiers, guard/no-access and non-readable answers are never
        // cached. Return them unchanged so each reader keeps its exact policy.
        switch (region.protect) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY: return true;
        default: return false;
        }
    }
    static bool Query(void* context,std::uintptr_t address,MemoryRegion* output,DWORD* error) noexcept {
        if (!context || !output) { if (error) *error=ERROR_INVALID_PARAMETER; return false; }
        auto& scope=*static_cast<ReadScope*>(context);
        for (std::size_t i=0;i<scope.count_;++i) {
            const auto& region=scope.regions_[i];
            if (address>=region.base && address-region.base<region.size) {
                *output=region;
                if (error) *error=ERROR_SUCCESS;
                return true;
            }
        }
        // Even malformed successful answers are forwarded for the caller's
        // existing bounds/protection rejection; they cannot poison the cache.
        if (!scope.original_.query(scope.original_.context,address,output,error)) return false;
        if (scope.count_<kReadScopeRegions && Cacheable(*output,address)) scope.regions_[scope.count_++]=*output;
        return true;
    }
    static bool Read(void* context,std::uintptr_t address,void* output,std::size_t size,DWORD* error) noexcept {
        if (!context) { if (error) *error=ERROR_INVALID_PARAMETER; return false; }
        const auto& scope=*static_cast<const ReadScope*>(context);
        return scope.original_.read(scope.original_.context,address,output,size,error);
    }
};

// One-pass copy of READONLY image metadata, not native mutable fields. Validation
// and span containment mirror shared ImageSectionMatches; in particular only
// exactly one section containing the WHOLE requested span may qualify. An
// unrelated overlap is not rejected more broadly than that existing contract.
// Keep separate from ReadScope so task-only query users pay no section storage.
class ImageSections {
public:
    ImageSections(std::uintptr_t base,std::size_t imageSize,const MemoryOps& ops) noexcept :
        base_(base),imageSize_(imageSize),ops_(ops) {}
    ImageSections(const ImageSections&)=delete;
    ImageSections& operator=(const ImageSections&)=delete;
    void Reset() noexcept { ready_=false; count_=0; }
    bool Matches(std::uint32_t rva,std::size_t size,DWORD required,DWORD forbidden) noexcept {
        if (!Range(rva,size)) return false;
        if (!ready_) {
            const auto loaded=Load();
            if (loaded==LoadResult::Fallback)
                return ImageSectionMatches(base_,imageSize_,rva,size,required,forbidden,ops_);
            if (loaded!=LoadResult::Ready) return false;
        }
        unsigned matching{};
        for (unsigned i=0;i<count_;++i) {
            const auto& section=sections_[i];
            const auto length=section.Misc.VirtualSize;
            if (rva>=section.VirtualAddress && rva-section.VirtualAddress<length &&
                size<=length-(rva-section.VirtualAddress)) {
                if ((section.Characteristics&required)!=required || (section.Characteristics&forbidden)!=0) return false;
                ++matching;
            }
        }
        return matching==1;
    }

private:
    enum class LoadResult { Ready,Fallback,Invalid };
    std::uintptr_t base_;
    std::size_t imageSize_;
    MemoryOps ops_;
    IMAGE_SECTION_HEADER sections_[96]{};
    unsigned count_{};
    bool ready_{};
    bool Range(std::uint32_t rva,std::size_t size) const noexcept {
        return base_!=0 && size!=0 && imageSize_!=0 &&
            imageSize_<=(std::numeric_limits<std::uintptr_t>::max)()-base_ &&
            rva<imageSize_ && size<=imageSize_-rva;
    }
    bool Readonly(std::uint32_t rva,std::size_t size) const noexcept {
        DWORD error{};
        return ImageRangeProtection(base_,imageSize_,rva,size,PAGE_READONLY,ops_,&error);
    }
    LoadResult Load() noexcept {
        // Do not memorize writable/executable/unknown header mappings. The
        // shared helper remains their authority and still rereads every call.
        if (!Readonly(0,sizeof(IMAGE_DOS_HEADER))) return LoadResult::Fallback;
        IMAGE_DOS_HEADER dos{}; DWORD error{};
        if (!ReadImageRange(base_,imageSize_,0,&dos,sizeof(dos),ops_,&error) ||
            dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<sizeof(dos) || dos.e_lfanew>0x100000)
            return LoadResult::Invalid;
        const auto ntRva=static_cast<std::uint32_t>(dos.e_lfanew);
        if (!Readonly(ntRva,sizeof(IMAGE_NT_HEADERS64))) return LoadResult::Fallback;
        IMAGE_NT_HEADERS64 nt{};
        if (!ReadImageRange(base_,imageSize_,ntRva,&nt,sizeof(nt),ops_,&error) ||
            nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 ||
            !(nt.FileHeader.Characteristics&IMAGE_FILE_EXECUTABLE_IMAGE) ||
            (nt.FileHeader.Characteristics&IMAGE_FILE_DLL) ||
            nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER64) ||
            nt.FileHeader.NumberOfSections==0 || nt.FileHeader.NumberOfSections>96 ||
            nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt.OptionalHeader.SizeOfImage!=imageSize_ ||
            nt.OptionalHeader.SizeOfHeaders>=imageSize_ || nt.OptionalHeader.SizeOfHeaders<ntRva+sizeof(nt) ||
            nt.OptionalHeader.NumberOfRvaAndSizes!=IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return LoadResult::Invalid;
        const auto sectionRva=ntRva+static_cast<std::uint32_t>(sizeof(nt));
        const std::size_t bytes=nt.FileHeader.NumberOfSections*sizeof(sections_[0]);
        if (sectionRva>nt.OptionalHeader.SizeOfHeaders || bytes>nt.OptionalHeader.SizeOfHeaders-sectionRva)
            return LoadResult::Invalid;
        if (!Readonly(sectionRva,bytes)) return LoadResult::Fallback;
        if (!ReadImageRange(base_,imageSize_,sectionRva,sections_,bytes,ops_,&error)) return LoadResult::Invalid;
        for (unsigned i=0;i<nt.FileHeader.NumberOfSections;++i) {
            const auto& section=sections_[i];
            if (section.VirtualAddress>imageSize_ || section.Misc.VirtualSize>imageSize_-section.VirtualAddress)
                return LoadResult::Invalid;
        }
        count_=nt.FileHeader.NumberOfSections;
        ready_=true;
        return LoadResult::Ready;
    }
};
} // namespace rs2fix::reporting
