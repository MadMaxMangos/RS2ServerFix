#include "pe_reader.h"

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
    bool Load(const wchar_t* path, std::string* error) {
        if (path == nullptr || path[0] == L'\0') {
            return SetError(error, "empty path");
        }

        const HANDLE file = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return SetError(error, "open failed");
        }

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
            static_cast<unsigned long long>(size.QuadPart) >
                static_cast<unsigned long long>(
                    (std::numeric_limits<std::size_t>::max)())) {
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
        fileHeader.NumberOfSections == 0) {
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
    headers->exportDirectory = exportDirectory;
    headers->importDirectory = importDirectory;
    image->machine = fileHeader.Machine;
    image->characteristics = fileHeader.Characteristics;

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
            !file.Contains(
                section.PointerToRawData,
                section.SizeOfRawData)) {
            return SetError(error, "invalid section raw range");
        }
        const std::uint64_t virtualSpan = std::max<std::uint32_t>(
            section.Misc.VirtualSize,
            section.SizeOfRawData);
        if (static_cast<std::uint64_t>(section.VirtualAddress) +
                virtualSpan >
            static_cast<std::uint64_t>(
                (std::numeric_limits<std::uint32_t>::max)()) + 1ULL) {
            return SetError(error, "section RVA overflow");
        }
        headers->sections.push_back(section);
    }
    return true;
}

class RvaReader {
public:
    RvaReader(const FileBytes& file, const ParsedHeaders& headers) noexcept
        : file_(file), headers_(headers) {}

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
    std::vector<ImportSymbol>* symbols,
    std::string* error) {
    if (symbols == nullptr || thunkRva == 0) {
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
                &module.symbols,
                error)) {
            return false;
        }
        image->imports.push_back(std::move(module));
    }
    return SetError(error, "unterminated import directory");
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
        ParsedHeaders headers{};
        if (!ReadHeaders(file, &headers, image, error)) {
            return false;
        }
        const RvaReader reader(file, headers);
        return ParseImports(reader, headers, image, error) &&
               ParseExports(file, reader, headers, image, error);
    } catch (...) {
        *image = {};
        return SetError(error, "PE parsing allocation failure");
    }
}

} // namespace rs2fix::pe
