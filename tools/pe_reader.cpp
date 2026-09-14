#include "pe_reader.h"
#include "tool_paths.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace rs2fix::pe {
namespace {

bool SetError(std::string* error, const char* text) {
    if (error != nullptr) {
        *error = text;
    }
    return false;
}

bool AddSize(
    const std::size_t left,
    const std::size_t right,
    std::size_t* result) noexcept {
    if (result == nullptr ||
        right > (std::numeric_limits<std::size_t>::max)() - left) {
        return false;
    }
    *result = left + right;
    return true;
}

bool MultiplySize(
    const std::size_t left,
    const std::size_t right,
    std::size_t* result) noexcept {
    if (result == nullptr ||
        (left != 0 &&
         right > (std::numeric_limits<std::size_t>::max)() / left)) {
        return false;
    }
    *result = left * right;
    return true;
}

class FileBytes {
public:
    explicit FileBytes(const std::vector<std::uint8_t>& bytes) : bytes_(bytes) {}
    FileBytes() = default;
    const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
    bool Load(const wchar_t* path, std::string* error) {
        std::wstring normalized;
        if (!tooling::RequireAbsolutePlainFile(path, &normalized, error)) return false;

        const HANDLE file = CreateFileW(
            normalized.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return SetError(error, "open failed");
        }
        BY_HANDLE_FILE_INFORMATION identity{};
        if (!GetFileInformationByHandle(file, &identity) ||
            (identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            CloseHandle(file);
            return SetError(error, "not a plain file");
        }

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
            static_cast<unsigned long long>(size.QuadPart) >
                static_cast<unsigned long long>(
                    512ULL * 1024 * 1024)) {
            CloseHandle(file);
            return SetError(error, "invalid file size");
        }

        try {
            bytes_.resize(static_cast<std::size_t>(size.QuadPart));
        } catch (...) {
            CloseHandle(file);
            return SetError(error, "file allocation failed");
        }

        std::size_t cursor = 0;
        bool success = true;
        while (cursor < bytes_.size()) {
            const std::size_t remaining = bytes_.size() - cursor;
            const DWORD request = static_cast<DWORD>(std::min<std::size_t>(
                remaining,
                (std::numeric_limits<DWORD>::max)()));
            DWORD received = 0;
            if (!ReadFile(
                    file,
                    bytes_.data() + cursor,
                    request,
                    &received,
                    nullptr) ||
                received == 0) {
                success = false;
                break;
            }
            cursor += received;
        }
        if (!CloseHandle(file)) {
            success = false;
        }
        if (!success) {
            bytes_.clear();
            return SetError(error, "file read failed");
        }
        return true;
    }

    bool Contains(
        const std::size_t offset,
        const std::size_t size) const noexcept {
        return offset <= bytes_.size() &&
               size <= bytes_.size() - offset;
    }

    template <typename T>
    bool Read(const std::size_t offset, T* value) const noexcept {
        if (value == nullptr || !Contains(offset, sizeof(T))) {
            return false;
        }
        std::memcpy(value, bytes_.data() + offset, sizeof(T));
        return true;
    }

    const std::uint8_t* At(const std::size_t offset) const noexcept {
        return Contains(offset, 1) ? bytes_.data() + offset : nullptr;
    }

    std::size_t size() const noexcept { return bytes_.size(); }

private:
    std::vector<std::uint8_t> bytes_;
};

struct ParsedHeaders {
    bool pe32Plus{};
    std::uint32_t sizeOfHeaders{};
    std::uint32_t numberOfRvaAndSizes{};
    IMAGE_DATA_DIRECTORY exportDirectory{};
    IMAGE_DATA_DIRECTORY importDirectory{};
    IMAGE_DATA_DIRECTORY delayDirectory{};
    IMAGE_DATA_DIRECTORY tlsDirectory{};
    std::uint64_t imageBase{};
    std::vector<IMAGE_SECTION_HEADER> sections;
};

bool ReadHeaders(
    const FileBytes& file,
    ParsedHeaders* headers,
    Image* image,
    std::string* error) {
    IMAGE_DOS_HEADER dos{};
    if (!file.Read(0, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) {
        return SetError(error, "invalid DOS header");
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dos.e_lfanew);
    DWORD signature = 0;
    if (!file.Read(ntOffset, &signature) ||
        signature != IMAGE_NT_SIGNATURE) {
        return SetError(error, "invalid NT signature");
    }

    std::size_t fileHeaderOffset = 0;
    if (!AddSize(ntOffset, sizeof(DWORD), &fileHeaderOffset)) {
        return SetError(error, "NT header overflow");
    }
    IMAGE_FILE_HEADER fileHeader{};
    if (!file.Read(fileHeaderOffset, &fileHeader) ||
        fileHeader.NumberOfSections == 0 || fileHeader.NumberOfSections > 96) {
        return SetError(error, "invalid file header");
    }

    std::size_t optionalOffset = 0;
    if (!AddSize(
            fileHeaderOffset,
            sizeof(IMAGE_FILE_HEADER),
            &optionalOffset) ||
        !file.Contains(optionalOffset, fileHeader.SizeOfOptionalHeader)) {
        return SetError(error, "invalid optional-header range");
    }

    WORD magic = 0;
    if (!file.Read(optionalOffset, &magic)) {
        return SetError(error, "missing optional-header magic");
    }

    IMAGE_DATA_DIRECTORY exportDirectory{};
    IMAGE_DATA_DIRECTORY importDirectory{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fileHeader.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64)) {
            return SetError(error, "short PE32+ optional header");
        }
        IMAGE_OPTIONAL_HEADER64 optional{};
        if (!file.Read(optionalOffset, &optional)) {
            return SetError(error, "invalid PE32+ optional header");
        }
        headers->pe32Plus = true;
        headers->sizeOfHeaders = optional.SizeOfHeaders;
        headers->numberOfRvaAndSizes = optional.NumberOfRvaAndSizes;
        image->optionalMagic = optional.Magic;
        image->dllCharacteristics = optional.DllCharacteristics;
        image->sizeOfImage = optional.SizeOfImage;
        image->checksum = optional.CheckSum;
        image->imageBase = optional.ImageBase;
        image->entryPointRva = optional.AddressOfEntryPoint;
        headers->imageBase = optional.ImageBase;
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
            headers->delayDirectory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
            headers->tlsDirectory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        for (std::size_t i = 0; i < std::min<std::size_t>(optional.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); ++i)
            image->dataDirectories[i] = {optional.DataDirectory[i].VirtualAddress, optional.DataDirectory[i].Size};
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            exportDirectory =
                optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            importDirectory =
                optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fileHeader.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER32)) {
            return SetError(error, "short PE32 optional header");
        }
        IMAGE_OPTIONAL_HEADER32 optional{};
        if (!file.Read(optionalOffset, &optional)) {
            return SetError(error, "invalid PE32 optional header");
        }
        headers->pe32Plus = false;
        headers->sizeOfHeaders = optional.SizeOfHeaders;
        headers->numberOfRvaAndSizes = optional.NumberOfRvaAndSizes;
        image->optionalMagic = optional.Magic;
        image->dllCharacteristics = optional.DllCharacteristics;
        image->sizeOfImage = optional.SizeOfImage;
        image->checksum = optional.CheckSum;
        image->imageBase = optional.ImageBase;
        image->entryPointRva = optional.AddressOfEntryPoint;
        headers->imageBase = optional.ImageBase;
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
            headers->delayDirectory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
            headers->tlsDirectory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        for (std::size_t i = 0; i < std::min<std::size_t>(optional.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); ++i)
            image->dataDirectories[i] = {optional.DataDirectory[i].VirtualAddress, optional.DataDirectory[i].Size};
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            exportDirectory =
                optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            importDirectory =
                optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    } else {
        return SetError(error, "unsupported optional-header magic");
    }

    if (headers->numberOfRvaAndSizes >
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return SetError(error, "too many data directories");
    }
    for (std::size_t i = 0; i < image->dataDirectories.size(); ++i) {
        const auto& directory = image->dataDirectories[i];
        if ((directory.virtualAddress == 0) != (directory.size == 0))
            return SetError(error, "partial data-directory entry");
        if (!directory.virtualAddress) continue;
        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
            if (!file.Contains(directory.virtualAddress, directory.size)) return SetError(error, "invalid certificate file range");
        } else if (static_cast<std::uint64_t>(directory.virtualAddress) + directory.size > image->sizeOfImage)
            return SetError(error, "directory exceeds image");
    }
    headers->exportDirectory = exportDirectory;
    headers->importDirectory = importDirectory;
    image->machine = fileHeader.Machine;
    image->characteristics = fileHeader.Characteristics;
    image->coffTimestamp = fileHeader.TimeDateStamp;
    image->tlsDirectoryRva = headers->tlsDirectory.VirtualAddress;
    image->tlsDirectorySize = headers->tlsDirectory.Size;
    image->sizeOfHeaders = headers->sizeOfHeaders;
    if (image->sizeOfImage == 0 || image->sizeOfImage < image->sizeOfHeaders ||
        image->entryPointRva >= image->sizeOfImage)
        return SetError(error, "invalid image size or entry point");

    std::size_t sectionOffset = 0;
    std::size_t sectionBytes = 0;
    if (!AddSize(
            optionalOffset,
            fileHeader.SizeOfOptionalHeader,
            &sectionOffset) ||
        !MultiplySize(
            fileHeader.NumberOfSections,
            sizeof(IMAGE_SECTION_HEADER),
            &sectionBytes) ||
        !file.Contains(sectionOffset, sectionBytes)) {
        return SetError(error, "invalid section table");
    }
    std::size_t sectionEnd = 0;
    if (!AddSize(sectionOffset, sectionBytes, &sectionEnd) ||
        headers->sizeOfHeaders < sectionEnd ||
        headers->sizeOfHeaders > file.size()) {
        return SetError(error, "invalid header size");
    }

    headers->sections.reserve(fileHeader.NumberOfSections);
    for (std::size_t index = 0;
         index < fileHeader.NumberOfSections;
         ++index) {
        IMAGE_SECTION_HEADER section{};
        const std::size_t current =
            sectionOffset + index * sizeof(IMAGE_SECTION_HEADER);
        if (!file.Read(current, &section)) {
            return SetError(error, "invalid section header");
        }
        if (section.SizeOfRawData != 0 &&
            (section.PointerToRawData < headers->sizeOfHeaders || !file.Contains(
                section.PointerToRawData,
                section.SizeOfRawData))) {
            return SetError(error, "invalid section raw range");
        }
        const std::uint64_t virtualSpan = std::max<std::uint32_t>(
            section.Misc.VirtualSize,
            section.SizeOfRawData);
        if (static_cast<std::uint64_t>(section.VirtualAddress) +
                virtualSpan >
            image->sizeOfImage || (virtualSpan != 0 && section.VirtualAddress < headers->sizeOfHeaders)) {
            return SetError(error, "section RVA overflow");
        }
        for (const auto& previous : headers->sections) {
            const std::uint64_t previousSpan = std::max(previous.Misc.VirtualSize, previous.SizeOfRawData);
            if (virtualSpan != 0 && previousSpan != 0 &&
                section.VirtualAddress < static_cast<std::uint64_t>(previous.VirtualAddress) + previousSpan &&
                previous.VirtualAddress < static_cast<std::uint64_t>(section.VirtualAddress) + virtualSpan)
                return SetError(error, "overlapping virtual sections");
            if (section.SizeOfRawData != 0 && previous.SizeOfRawData != 0 &&
                section.PointerToRawData < static_cast<std::uint64_t>(previous.PointerToRawData) + previous.SizeOfRawData &&
                previous.PointerToRawData < static_cast<std::uint64_t>(section.PointerToRawData) + section.SizeOfRawData)
                return SetError(error, "overlapping raw sections");
        }
        headers->sections.push_back(section);
        Section exposed{};
        exposed.name.assign(reinterpret_cast<const char*>(section.Name),
            strnlen_s(reinterpret_cast<const char*>(section.Name), IMAGE_SIZEOF_SHORT_NAME));
        exposed.virtualAddress = section.VirtualAddress;
        exposed.virtualSize = section.Misc.VirtualSize;
        exposed.rawOffset = section.PointerToRawData;
        exposed.rawSize = section.SizeOfRawData;
        exposed.characteristics = section.Characteristics;
        image->sections.push_back(std::move(exposed));
    }
    return true;
}

class RvaReader {
public:
    RvaReader(const FileBytes& file, const ParsedHeaders& headers) noexcept
        : file_(file), headers_(headers) {}

    // Some legitimate PE data (exported globals and delay-load HMODULE slots)
    // lives in a section's loader-zeroed tail and has no physical file bytes.
    // Code, descriptors, lookup thunks and strings must still use raw Map/Read.
    bool Mapped(const std::uint32_t rva, const std::size_t needed) const noexcept {
        if (rva < headers_.sizeOfHeaders) return needed <= headers_.sizeOfHeaders - rva;
        for (const auto& section : headers_.sections) {
            const std::uint64_t span = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
            if (rva >= section.VirtualAddress && static_cast<std::uint64_t>(rva) - section.VirtualAddress < span &&
                needed <= span - (rva - section.VirtualAddress)) return true;
        }
        return false;
    }

    bool Map(
        const std::uint32_t rva,
        const std::size_t needed,
        std::size_t* offset,
        std::size_t* available = nullptr) const noexcept {
        if (offset == nullptr) {
            return false;
        }
        if (rva < headers_.sizeOfHeaders) {
            const std::size_t raw = rva;
            const std::size_t headerAvailable =
                headers_.sizeOfHeaders - raw;
            const std::size_t fileAvailable = file_.size() - raw;
            const std::size_t mapped =
                std::min(headerAvailable, fileAvailable);
            if (needed > mapped) {
                return false;
            }
            *offset = raw;
            if (available != nullptr) {
                *available = mapped;
            }
            return true;
        }

        for (const IMAGE_SECTION_HEADER& section : headers_.sections) {
            const std::uint64_t start = section.VirtualAddress;
            const std::uint64_t span = std::max<std::uint32_t>(
                section.Misc.VirtualSize,
                section.SizeOfRawData);
            const std::uint64_t value = rva;
            if (value < start || value - start >= span) {
                continue;
            }
            const std::uint64_t delta = value - start;
            if (delta >= section.SizeOfRawData) {
                return false;
            }
            const std::size_t raw =
                static_cast<std::size_t>(section.PointerToRawData) +
                static_cast<std::size_t>(delta);
            const std::size_t sectionAvailable =
                static_cast<std::size_t>(section.SizeOfRawData) -
                static_cast<std::size_t>(delta);
            if (needed > sectionAvailable ||
                !file_.Contains(raw, needed)) {
                return false;
            }
            *offset = raw;
            if (available != nullptr) {
                *available = std::min(
                    sectionAvailable, file_.size() - raw);
            }
            return true;
        }
        return false;
    }

    template <typename T>
    bool Read(const std::uint32_t rva, T* value) const noexcept {
        std::size_t offset = 0;
        return Map(rva, sizeof(T), &offset) && file_.Read(offset, value);
    }

    bool CString(
        const std::uint32_t rva,
        std::string* text) const {
        if (text == nullptr) {
            return false;
        }
        std::size_t offset = 0;
        std::size_t available = 0;
        if (!Map(rva, 1, &offset, &available)) {
            return false;
        }
        constexpr std::size_t kMaximumName = 4096;
        const std::size_t limit = std::min(available, kMaximumName);
        const std::uint8_t* begin = file_.At(offset);
        if (begin == nullptr) {
            return false;
        }
        const void* terminator = std::memchr(begin, 0, limit);
        if (terminator == nullptr) {
            return false;
        }
        const auto* end = static_cast<const std::uint8_t*>(terminator);
        text->assign(
            reinterpret_cast<const char*>(begin),
            reinterpret_cast<const char*>(end));
        return !text->empty();
    }

private:
    const FileBytes& file_;
    const ParsedHeaders& headers_;
};

bool DirectoryPresent(
    const IMAGE_DATA_DIRECTORY& directory,
    std::string* error) {
    if ((directory.VirtualAddress == 0) != (directory.Size == 0)) {
        return SetError(error, "partial data-directory entry");
    }
    return true;
}

bool ParseImportSymbols(
    const RvaReader& reader,
    const bool pe32Plus,
    const std::uint32_t thunkRva,
    const std::uint32_t iatRva,
    std::vector<ImportSymbol>* symbols,
    std::string* error) {
    if (symbols == nullptr || thunkRva == 0 || iatRva == 0) {
        return SetError(error, "missing import thunk");
    }
    const std::size_t entrySize = pe32Plus
        ? sizeof(ULONGLONG)
        : sizeof(DWORD);
    std::size_t firstOffset = 0;
    std::size_t available = 0;
    if (!reader.Map(thunkRva, entrySize, &firstOffset, &available)) {
        return SetError(error, "invalid import thunk range");
    }
    const std::size_t maximumEntries = available / entrySize;
    for (std::size_t index = 0; index < maximumEntries; ++index) {
        const std::uint64_t entryRva64 =
            static_cast<std::uint64_t>(thunkRva) + index * entrySize;
        if (entryRva64 >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return SetError(error, "import thunk RVA overflow");
        }

        std::uint64_t value = 0;
        const std::uint64_t currentIat = static_cast<std::uint64_t>(iatRva) + index * entrySize;
        std::size_t iatOffset = 0;
        if (currentIat > UINT32_MAX || !reader.Map(static_cast<DWORD>(currentIat), entrySize, &iatOffset))
            return SetError(error, "invalid import IAT range");
        if (pe32Plus) {
            ULONGLONG raw = 0;
            if (!reader.Read(static_cast<DWORD>(entryRva64), &raw)) {
                return SetError(error, "invalid PE32+ import thunk");
            }
            value = raw;
        } else {
            DWORD raw = 0;
            if (!reader.Read(static_cast<DWORD>(entryRva64), &raw)) {
                return SetError(error, "invalid PE32 import thunk");
            }
            value = raw;
        }
        if (value == 0) {
            return true;
        }

        const std::uint64_t ordinalFlag = pe32Plus
            ? IMAGE_ORDINAL_FLAG64
            : IMAGE_ORDINAL_FLAG32;
        ImportSymbol symbol{};
        symbol.iatRva = static_cast<DWORD>(currentIat);
        if ((value & ordinalFlag) != 0) {
            if ((value & ~(ordinalFlag | 0xffffULL)) != 0) {
                return SetError(error, "invalid ordinal import");
            }
            symbol.byOrdinal = true;
            symbol.ordinal = static_cast<std::uint16_t>(value & 0xffffULL);
        } else {
            if (value >
                (std::numeric_limits<std::uint32_t>::max)()) {
                return SetError(error, "import-name RVA overflow");
            }
            const std::uint32_t nameRva =
                static_cast<std::uint32_t>(value);
            WORD hint = 0;
            if (!reader.Read(nameRva, &hint) ||
                nameRva >
                    (std::numeric_limits<std::uint32_t>::max)() -
                        sizeof(WORD) ||
                !reader.CString(
                    nameRva + static_cast<DWORD>(sizeof(WORD)),
                    &symbol.name)) {
                return SetError(error, "invalid import-by-name entry");
            }
        }
        symbols->push_back(std::move(symbol));
    }
    return SetError(error, "unterminated import thunk");
}

bool ParseImports(
    const RvaReader& reader,
    const ParsedHeaders& headers,
    Image* image,
    std::string* error) {
    const IMAGE_DATA_DIRECTORY& directory = headers.importDirectory;
    if (!DirectoryPresent(directory, error)) {
        return false;
    }
    if (directory.VirtualAddress == 0) {
        return true;
    }
    if (directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        return SetError(error, "short import directory");
    }
    std::size_t directoryOffset = 0;
    if (!reader.Map(directory.VirtualAddress, directory.Size, &directoryOffset))
        return SetError(error, "invalid import directory range");

    const std::size_t maximumDescriptors =
        directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (std::size_t index = 0;
         index < maximumDescriptors;
         ++index) {
        const std::uint64_t descriptorRva64 =
            static_cast<std::uint64_t>(directory.VirtualAddress) +
            index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (descriptorRva64 >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return SetError(error, "import descriptor RVA overflow");
        }
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (!reader.Read(
                static_cast<DWORD>(descriptorRva64),
                &descriptor)) {
            return SetError(error, "invalid import descriptor");
        }
        const bool terminal =
            descriptor.OriginalFirstThunk == 0 &&
            descriptor.TimeDateStamp == 0 &&
            descriptor.ForwarderChain == 0 &&
            descriptor.Name == 0 &&
            descriptor.FirstThunk == 0;
        if (terminal) {
            return true;
        }
        if (descriptor.Name == 0) {
            return SetError(error, "missing import module name");
        }

        ImportModule module{};
        if (!reader.CString(descriptor.Name, &module.name)) {
            return SetError(error, "invalid import module name");
        }
        const DWORD thunk = descriptor.OriginalFirstThunk != 0
            ? descriptor.OriginalFirstThunk
            : descriptor.FirstThunk;
        if (!ParseImportSymbols(
                reader,
                headers.pe32Plus,
                thunk,
                descriptor.FirstThunk,
                &module.symbols,
                error)) {
            return false;
        }
        image->normalImports.push_back(std::move(module));
    }
    return SetError(error, "unterminated import directory");
}

struct DelayDescriptor {
    DWORD attributes, name, moduleHandle, iat, lookup, bound, unload, timestamp;
};
static_assert(sizeof(DelayDescriptor) == 32);
bool ParseDelayImports(const RvaReader& reader, const ParsedHeaders& headers,
                       Image* image, std::string* error) {
    const auto& directory = headers.delayDirectory;
    if (!DirectoryPresent(directory, error)) return false;
    if (!directory.VirtualAddress) return true;
    std::size_t offset = 0;
    if (directory.Size < sizeof(DelayDescriptor) ||
        !reader.Map(directory.VirtualAddress, directory.Size, &offset))
        return SetError(error, "invalid delay directory range");
    const auto count = directory.Size / sizeof(DelayDescriptor);
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint64_t rva = static_cast<std::uint64_t>(directory.VirtualAddress) + index * sizeof(DelayDescriptor);
        DelayDescriptor descriptor{};
        if (rva > UINT32_MAX || !reader.Read(static_cast<DWORD>(rva), &descriptor))
            return SetError(error, "invalid delay descriptor");
        const DelayDescriptor zero{};
        if (std::memcmp(&descriptor, &zero, sizeof(zero)) == 0) return true;
        if ((descriptor.attributes & ~1UL) != 0) return SetError(error, "unsupported delay attributes");
        DWORD* fields[]{&descriptor.name, &descriptor.moduleHandle, &descriptor.iat,
                       &descriptor.lookup, &descriptor.bound, &descriptor.unload};
        if ((descriptor.attributes & 1) == 0) {
            for (DWORD* field : fields) {
                if (*field == 0) continue;
                if (*field < headers.imageBase || static_cast<std::uint64_t>(*field) - headers.imageBase > UINT32_MAX)
                    return SetError(error, "invalid VA delay field");
                *field = static_cast<DWORD>(*field - headers.imageBase);
            }
        }
        const std::size_t pointerSize = headers.pe32Plus ? 8 : 4;
        if (!descriptor.name || !descriptor.moduleHandle || !descriptor.iat || !descriptor.lookup ||
            !reader.Mapped(descriptor.moduleHandle, pointerSize))
            return SetError(error, "missing or invalid delay required field");
        ImportModule module{};
        if (!reader.CString(descriptor.name, &module.name)) return SetError(error, "invalid delay module name");
        if (!ParseImportSymbols(reader, headers.pe32Plus, descriptor.lookup, descriptor.iat, &module.symbols, error)) return false;
        const std::size_t tableSize = (module.symbols.size() + 1) * pointerSize;
        if ((descriptor.bound && !reader.Map(descriptor.bound, tableSize, &offset)) ||
            (descriptor.unload && !reader.Map(descriptor.unload, tableSize, &offset)))
            return SetError(error, "invalid delay optional table");
        image->delayImports.push_back(std::move(module));
    }
    return SetError(error, "unterminated delay directory");
}

bool ParseTls(const RvaReader& reader, const ParsedHeaders& headers, std::string* error) {
    if (!DirectoryPresent(headers.tlsDirectory, error)) return false;
    if (!headers.tlsDirectory.VirtualAddress) return true;
    const std::size_t required = headers.pe32Plus ? sizeof(IMAGE_TLS_DIRECTORY64) : sizeof(IMAGE_TLS_DIRECTORY32);
    std::size_t offset = 0;
    return (headers.tlsDirectory.Size >= required && reader.Map(headers.tlsDirectory.VirtualAddress, headers.tlsDirectory.Size, &offset))
        || SetError(error, "invalid TLS directory range");
}

bool ParseExports(
    const FileBytes& file,
    const RvaReader& reader,
    const ParsedHeaders& headers,
    Image* image,
    std::string* error) {
    const IMAGE_DATA_DIRECTORY& directory = headers.exportDirectory;
    if (!DirectoryPresent(directory, error)) {
        return false;
    }
    if (directory.VirtualAddress == 0) {
        return true;
    }
    if (directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return SetError(error, "short export directory");
    }
    std::size_t directoryOffset = 0;
    if (!reader.Map(directory.VirtualAddress, directory.Size, &directoryOffset))
        return SetError(error, "invalid export directory range");

    IMAGE_EXPORT_DIRECTORY exports{};
    if (!reader.Read(directory.VirtualAddress, &exports)) {
        return SetError(error, "invalid export directory");
    }
    if (exports.NumberOfNames > exports.NumberOfFunctions) {
        return SetError(error, "export name count exceeds functions");
    }
    image->exportFunctionCount = exports.NumberOfFunctions;
    if (exports.NumberOfFunctions == 0) {
        return exports.NumberOfNames == 0
            ? true
            : SetError(error, "names without export functions");
    }

    std::size_t functionBytes = 0;
    if (!MultiplySize(
            exports.NumberOfFunctions,
            sizeof(DWORD),
            &functionBytes)) {
        return SetError(error, "export function count overflow");
    }
    std::size_t functionOffset = 0;
    if (exports.AddressOfFunctions == 0 ||
        !reader.Map(
            exports.AddressOfFunctions,
            functionBytes,
            &functionOffset) ||
        !file.Contains(functionOffset, functionBytes)) {
        return SetError(error, "invalid export function array");
    }

    if (exports.NumberOfNames == 0) {
        return true;
    }
    std::size_t nameBytes = 0;
    std::size_t ordinalBytes = 0;
    if (!MultiplySize(
            exports.NumberOfNames,
            sizeof(DWORD),
            &nameBytes) ||
        !MultiplySize(
            exports.NumberOfNames,
            sizeof(WORD),
            &ordinalBytes)) {
        return SetError(error, "export name count overflow");
    }
    std::size_t nameOffset = 0;
    std::size_t ordinalOffset = 0;
    if (exports.AddressOfNames == 0 ||
        exports.AddressOfNameOrdinals == 0 ||
        !reader.Map(exports.AddressOfNames, nameBytes, &nameOffset) ||
        !reader.Map(
            exports.AddressOfNameOrdinals,
            ordinalBytes,
            &ordinalOffset)) {
        return SetError(error, "invalid export name arrays");
    }

    image->exports.reserve(exports.NumberOfNames);
    for (std::size_t index = 0;
         index < exports.NumberOfNames;
         ++index) {
        DWORD nameRva = 0;
        WORD functionIndex = 0;
        if (!file.Read(nameOffset + index * sizeof(DWORD), &nameRva) ||
            !file.Read(
                ordinalOffset + index * sizeof(WORD),
                &functionIndex) ||
            functionIndex >= exports.NumberOfFunctions) {
            return SetError(error, "invalid named export index");
        }
        const std::uint64_t ordinal =
            static_cast<std::uint64_t>(exports.Base) + functionIndex;
        if (ordinal >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return SetError(error, "export ordinal overflow");
        }
        ExportSymbol symbol{};
        if (!reader.CString(nameRva, &symbol.name)) {
            return SetError(error, "invalid export name");
        }
        symbol.ordinal = static_cast<std::uint32_t>(ordinal);
        DWORD functionRva = 0;
        if (!file.Read(functionOffset + static_cast<std::size_t>(functionIndex) * sizeof(DWORD), &functionRva) || !functionRva)
            return SetError(error, "null named export address");
        symbol.rva = functionRva;
        if (functionRva >= directory.VirtualAddress &&
            static_cast<std::uint64_t>(functionRva) < static_cast<std::uint64_t>(directory.VirtualAddress) + directory.Size) {
            if (!reader.CString(functionRva, &symbol.forwarder) ||
                symbol.forwarder.size() + 1 > static_cast<std::uint64_t>(directory.VirtualAddress) + directory.Size - functionRva)
                return SetError(error, "invalid export forwarder");
        } else {
            if (!reader.Mapped(functionRva, 1)) return SetError(error, "invalid export address");
        }
        for (const auto& previous : image->exports)
            if (previous.name == symbol.name) return SetError(error, "duplicate export name");
        image->exports.push_back(std::move(symbol));
    }
    return true;
}

} // namespace

bool ReadPeImage(
    const wchar_t* path,
    Image* image,
    std::string* error) {
    if (image == nullptr) {
        return SetError(error, "null output image");
    }
    *image = {};
    if (error != nullptr) {
        error->clear();
    }

    try {
        FileBytes file;
        if (!file.Load(path, error)) {
            return false;
        }
        return ReadPeBytes(file.bytes(), image, error);
    } catch (...) {
        *image = {};
        return SetError(error, "PE parsing allocation failure");
    }
}

bool ReadPeBytes(const std::vector<std::uint8_t>& bytes, Image* image, std::string* error) {
    if (!image) return SetError(error, "null output image");
    *image = {};
    if (error) error->clear();
    if (bytes.empty() || bytes.size() > 512ULL * 1024 * 1024) return SetError(error, "invalid file size");
    try {
        FileBytes file(bytes);
        Image parsed{};
        ParsedHeaders headers{};
        if (!ReadHeaders(file, &headers, &parsed, error)) return false;
        const RvaReader reader(file, headers);
        if (!ParseImports(reader, headers, &parsed, error) ||
            !ParseDelayImports(reader, headers, &parsed, error) ||
            !ParseTls(reader, headers, error) ||
            !ParseExports(file, reader, headers, &parsed, error)) return false;
        parsed.rawBytes = bytes;
        *image = std::move(parsed);
        return true;
    } catch (...) {
        return SetError(error, "PE parsing allocation failure");
    }
}

const Section* FindSection(const Image& image, std::uint32_t rva, std::size_t size) noexcept {
    for (const auto& section : image.sections) {
        const std::uint64_t span = std::max(section.virtualSize, section.rawSize);
        if (rva >= section.virtualAddress && static_cast<std::uint64_t>(rva) - section.virtualAddress < span &&
            size <= span - (rva - section.virtualAddress)) return &section;
    }
    return nullptr;
}
bool MapImageRva(const Image& image, std::uint32_t rva, std::size_t size, std::size_t* rawOffset) noexcept {
    if (!rawOffset || rva >= image.sizeOfImage || size > static_cast<std::uint64_t>(image.sizeOfImage) - rva) return false;
    std::size_t raw = 0;
    if (rva < image.sizeOfHeaders) {
        if (size > image.sizeOfHeaders - rva) return false;
        raw = rva;
    } else {
        const auto* section = FindSection(image, rva, size);
        if (!section || rva - section->virtualAddress > section->rawSize ||
            size > section->rawSize - (rva - section->virtualAddress)) return false;
        raw = static_cast<std::size_t>(section->rawOffset) + rva - section->virtualAddress;
    }
    if (raw > image.rawBytes.size() || size > image.rawBytes.size() - raw) return false;
    *rawOffset = raw;
    return true;
}
bool ReadImageRva(const Image& image, std::uint32_t rva, std::size_t size,
                  std::vector<std::uint8_t>* bytes, std::string* error) {
    if (!bytes) return SetError(error, "null RVA output");
    bytes->clear();
    std::size_t raw = 0;
    if (!MapImageRva(image, rva, size, &raw)) return SetError(error, "invalid RVA raw range");
    bytes->assign(image.rawBytes.begin() + raw, image.rawBytes.begin() + raw + size);
    return true;
}

} // namespace rs2fix::pe
