#include "test_framework.h"
#include "pe_reader.h"
#include "file_evidence.h"
#include <Windows.h>
#include <Softpub.h>
#include <algorithm>
#include <cstring>
#include <functional>
namespace rs2fix::testcases {
namespace {
using Bytes = std::vector<std::uint8_t>;
template<class T> void Put(Bytes& bytes, std::size_t offset, const T& value) {
    RS2_CHECK(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset);
    if (offset <= bytes.size() && sizeof(T) <= bytes.size() - offset) std::memcpy(bytes.data() + offset, &value, sizeof(T));
}
void Text(Bytes& bytes, std::size_t offset, const char* value) {
    const auto count = std::strlen(value) + 1;
    RS2_CHECK(offset <= bytes.size() && count <= bytes.size() - offset);
    if (offset <= bytes.size() && count <= bytes.size() - offset) std::memcpy(bytes.data() + offset, value, count);
}
constexpr std::size_t kOptional = 0x98;
void Directory(Bytes& bytes, bool wide, std::size_t index, DWORD rva, DWORD size) {
    const auto start = kOptional + (wide ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    Put(bytes, start + index * sizeof(IMAGE_DATA_DIRECTORY), IMAGE_DATA_DIRECTORY{rva, size});
}
void Thunk(Bytes& bytes, bool wide, std::size_t offset, std::uint64_t value) {
    if (wide) Put(bytes, offset, value); else Put(bytes, offset, static_cast<DWORD>(value));
}
Bytes Fixture(bool wide, bool delay) {
    Bytes bytes(0x1200);
    IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80; Put(bytes, 0, dos);
    Put(bytes, 0x80, DWORD{IMAGE_NT_SIGNATURE});
    IMAGE_FILE_HEADER file{};
    file.Machine = wide ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    file.NumberOfSections = 1;
    file.TimeDateStamp = 0x12345678;
    file.SizeOfOptionalHeader = static_cast<WORD>(wide ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));
    file.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
    Put(bytes, 0x84, file);
    if (wide) {
        IMAGE_OPTIONAL_HEADER64 optional{};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; optional.ImageBase = 0x180000000ULL;
        optional.SizeOfImage = 0x3000; optional.SizeOfHeaders = 0x200;
        optional.AddressOfEntryPoint = 0x1700; optional.NumberOfRvaAndSizes = 16;
        optional.CheckSum = 0xABCDEF;
        Put(bytes, kOptional, optional);
    } else {
        IMAGE_OPTIONAL_HEADER32 optional{};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; optional.ImageBase = 0x400000;
        optional.SizeOfImage = 0x3000; optional.SizeOfHeaders = 0x200;
        optional.AddressOfEntryPoint = 0x1700; optional.NumberOfRvaAndSizes = 16;
        optional.CheckSum = 0xABCDEF;
        Put(bytes, kOptional, optional);
    }
    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".text", 5);
    section.Misc.VirtualSize = 0x1000; section.VirtualAddress = 0x1000;
    section.SizeOfRawData = 0x1000; section.PointerToRawData = 0x200;
    section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    Put(bytes, kOptional + file.SizeOfOptionalHeader, section);
    Text(bytes, 0x400, "X3DAudio1_7.dll");
    Thunk(bytes, wide, 0x500, 0x1400);
    Thunk(bytes, wide, 0x540, 0x1400);
    Text(bytes, 0x602, "X3DAudioInitialize");
    if (delay) {
        Directory(bytes, wide, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x1100, 64);
        const DWORD fields[]{1, 0x1200, 0x1380, 0x1340, 0x1300, 0, 0, 0};
        for (std::size_t i = 0; i < 8; ++i) Put(bytes, 0x300 + i * 4, fields[i]);
    } else {
        Directory(bytes, wide, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1100, 40);
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        descriptor.OriginalFirstThunk = 0x1300; descriptor.Name = 0x1200; descriptor.FirstThunk = 0x1340;
        Put(bytes, 0x300, descriptor);
    }
    Directory(bytes, wide, IMAGE_DIRECTORY_ENTRY_EXPORT, 0x1500, 0x100);
    IMAGE_EXPORT_DIRECTORY exports{};
    exports.Base = 1; exports.NumberOfFunctions = 1; exports.NumberOfNames = 1;
    exports.AddressOfFunctions = 0x1560; exports.AddressOfNames = 0x1570; exports.AddressOfNameOrdinals = 0x1580;
    Put(bytes, 0x700, exports); Put(bytes, 0x760, DWORD{0x1700}); Put(bytes, 0x770, DWORD{0x1590});
    Text(bytes, 0x790, "FixtureExport"); bytes[0x900] = 0xC3;
    return bytes;
}
void Reject(const Bytes& source, const std::function<void(Bytes&)>& change) {
    auto bytes = source; change(bytes);
    pe::Image image; std::string error;
    RS2_CHECK(!pe::ReadPeBytes(bytes, &image, &error));
    RS2_CHECK(!error.empty());
    RS2_CHECK(image.rawBytes.empty() && image.normalImports.empty() && image.delayImports.empty() && image.exports.empty());
}
struct TrustFixture { int calls{}; LONG verify{}, close{}; bool correct{true}; };
LONG Trust(void* raw, HWND window, GUID* action, WINTRUST_DATA* data) noexcept {
    auto& state = *static_cast<TrustFixture*>(raw);
    const GUID expected = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    state.correct = state.correct && window == reinterpret_cast<HWND>(INVALID_HANDLE_VALUE) &&
        std::memcmp(action, &expected, sizeof(expected)) == 0 && data->dwUIChoice == WTD_UI_NONE &&
        data->fdwRevocationChecks == WTD_REVOKE_NONE && data->dwUnionChoice == WTD_CHOICE_FILE &&
        data->dwProvFlags == WTD_CACHE_ONLY_URL_RETRIEVAL && data->pFile &&
        std::wcscmp(data->pFile->pcwszFilePath, L"C:\\fixture.dll") == 0 &&
        data->dwStateAction == static_cast<DWORD>(state.calls == 0 ? WTD_STATEACTION_VERIFY : WTD_STATEACTION_CLOSE);
    return state.calls++ == 0 ? state.verify : state.close;
}
#ifdef RS2_PE_CONTRACT_PATH
bool RunHelp(const wchar_t* tail, DWORD* exitCode, std::string* output) {
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE reader = nullptr, writer = nullptr;
    if (!CreatePipe(&reader, &writer, &attributes, 4096)) return false;
    if (!SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0)) { CloseHandle(reader); CloseHandle(writer); return false; }
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writer; startup.hStdError = writer; startup.hStdInput = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" RS2_PE_CONTRACT_PATH L"\" " + std::wstring(tail);
    const bool created = CreateProcessW(RS2_PE_CONTRACT_PATH, command.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
    CloseHandle(writer);
    if (!created) { CloseHandle(reader); return false; }
    const DWORD wait = WaitForSingleObject(process.hProcess, 20000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 20000);
        CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(reader); return false;
    }
    bool okay = GetExitCodeProcess(process.hProcess, exitCode) != FALSE;
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    char buffer[1024]{};
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(reader, buffer, sizeof(buffer), &count, nullptr)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) okay = false;
            break;
        }
        if (!count) break;
        if (output->size() + count > 65536) { okay = false; break; }
        output->append(buffer, count);
    }
    CloseHandle(reader);
    return okay;
}
#endif
}
void RunPeReaderTests() {
    for (bool wide : {false, true}) for (bool delay : {false, true}) {
        const auto source = Fixture(wide, delay);
        pe::Image image; std::string error;
        RS2_CHECK(pe::ReadPeBytes(source, &image, &error));
        RS2_CHECK(image.coffTimestamp == 0x12345678 && image.sizeOfImage == 0x3000 && image.checksum == 0xABCDEF);
        const auto& modules = delay ? image.delayImports : image.normalImports;
        RS2_CHECK(modules.size() == 1 && modules[0].symbols.size() == 1);
        if (!modules.empty() && !modules[0].symbols.empty()) {
            RS2_CHECK(!modules[0].symbols[0].byOrdinal && modules[0].symbols[0].name == "X3DAudioInitialize");
            RS2_CHECK(modules[0].symbols[0].iatRva == 0x1340);
        }
        RS2_CHECK((delay ? image.normalImports : image.delayImports).empty());
        RS2_CHECK(image.exports.size() == 1 && image.exports[0].rva == 0x1700);
        std::vector<std::uint8_t> code;
        RS2_CHECK(pe::ReadImageRva(image, 0x1700, 1, &code, &error) && code.size() == 1 && code[0] == 0xC3);
        RS2_CHECK(!pe::ReadImageRva(image, 0x1FFF, 2, &code, &error));
        RS2_CHECK(!pe::ReadImageRva(image, 0xFFFFFFFF, 4, &code, &error));
        auto zeroFill = source;
        const std::size_t sectionOffset = kOptional + (wide ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));
        Put(zeroFill, sectionOffset + offsetof(IMAGE_SECTION_HEADER, Misc), DWORD{0x1800});
        Put(zeroFill, 0x760, DWORD{0x2100});
        if (delay) Put(zeroFill, 0x308, DWORD{0x2200});
        RS2_CHECK(pe::ReadPeBytes(zeroFill, &image, &error));
        RS2_CHECK(image.exports.size() == 1 && image.exports[0].rva == 0x2100);
        RS2_CHECK(!pe::ReadImageRva(image, 0x2100, 1, &code, &error));
        const std::uint64_t flag = wide ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
        for (std::uint16_t ordinal : {std::uint16_t{1}, std::uint16_t{2}}) {
            auto bytes = source; Thunk(bytes, wide, 0x500, flag | ordinal);
            RS2_CHECK(pe::ReadPeBytes(bytes, &image, &error));
            const auto& imports = delay ? image.delayImports : image.normalImports;
            RS2_CHECK(imports.size() == 1 && imports[0].symbols[0].byOrdinal && imports[0].symbols[0].ordinal == ordinal);
        }
        const auto directory = delay ? IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT : IMAGE_DIRECTORY_ENTRY_IMPORT;
        Reject(source, [&](Bytes& b) { Directory(b, wide, directory, 0x1100, 0); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, directory, 0, 40); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, directory, 0x1100, delay ? 32 : 20); });
        Reject(source, [&](Bytes& b) { Put(b, delay ? 0x304 : 0x30C, DWORD{0xFFFFFFF0}); });
        Reject(source, [&](Bytes& b) { Thunk(b, wide, 0x500, 0xFFFFFF0); });
        Reject(source, [&](Bytes& b) { Thunk(b, wide, 0x500, flag | 0x10000); });
        Reject(source, [&](Bytes& b) {
            const DWORD last = wide ? 0x1FF8 : 0x1FFC;
            Put(b, delay ? 0x310 : 0x300, last);
            Put(b, delay ? 0x30C : 0x310, last);
            Thunk(b, wide, wide ? 0x11F8 : 0x11FC, flag | 1);
        });
        Reject(source, [&](Bytes& b) { Put(b, delay ? 0x30C : 0x310, DWORD{0}); });
        Reject(source, [&](Bytes& b) { Put(b, delay ? 0x30C : 0x310, DWORD{0xFFFFFFF0}); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, IMAGE_DIRECTORY_ENTRY_TLS, 0x1600, 0); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, IMAGE_DIRECTORY_ENTRY_TLS, 0, 40); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, IMAGE_DIRECTORY_ENTRY_TLS, 0x1600, 1); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x1600, 0); });
        Reject(source, [&](Bytes& b) { Directory(b, wide, IMAGE_DIRECTORY_ENTRY_SECURITY, 0x1200, 8); });
        Reject(source, [&](Bytes& b) { Put(b, 0x700 + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions), DWORD{UINT32_MAX}); });
        Reject(source, [&](Bytes& b) { Put(b, 0x760, DWORD{0}); });
        Reject(source, [&](Bytes& b) { Put(b, 0x760, DWORD{0xFFFFFFF0}); });
        Reject(source, [&](Bytes& b) { b.resize(0x200); });
        Reject(source, [&](Bytes& b) { Put(b, 0x84 + offsetof(IMAGE_FILE_HEADER, NumberOfSections), WORD{97}); });
        if (delay) {
            Reject(source, [&](Bytes& b) { Put(b, 0x300, DWORD{2}); });
            Reject(source, [&](Bytes& b) { Put(b, 0x300, DWORD{0}); });
            for (std::size_t offset : {0x308, 0x310}) {
                Reject(source, [&](Bytes& b) { Put(b, offset, DWORD{0}); });
                Reject(source, [&](Bytes& b) { Put(b, offset, DWORD{0xFFFFFFF0}); });
            }
            for (std::size_t offset : {0x314, 0x318})
                Reject(source, [&](Bytes& b) { Put(b, offset, DWORD{0xFFFFFFF0}); });
            if (!wide) {
                auto va = source; Put(va, 0x300, DWORD{0});
                for (std::size_t offset : {0x304, 0x308, 0x30C, 0x310}) {
                    DWORD value = 0; std::memcpy(&value, va.data() + offset, sizeof(value)); Put(va, offset, value + 0x400000);
                }
                RS2_CHECK(pe::ReadPeBytes(va, &image, &error));
            }
        }
    }
    TrustFixture state{};
    tooling::WinTrustOps ops{&state, Trust};
    auto result = tooling::VerifyEmbeddedSignatureCacheOnly(L"C:\\fixture.dll", ops);
    RS2_CHECK(state.correct && state.calls == 2 && result.closeAttempted && result.verifyStatus == 0 && result.closeStatus == 0);
    state = {}; state.verify = TRUST_E_BAD_DIGEST;
    result = tooling::VerifyEmbeddedSignatureCacheOnly(L"C:\\fixture.dll", ops);
    RS2_CHECK(state.correct && state.calls == 2 && result.verifyStatus == TRUST_E_BAD_DIGEST && result.closeAttempted);
    state = {}; state.close = TRUST_E_FAIL;
    result = tooling::VerifyEmbeddedSignatureCacheOnly(L"C:\\fixture.dll", ops);
    RS2_CHECK(state.correct && state.calls == 2 && result.closeStatus == TRUST_E_FAIL);
    state = {};
    result = tooling::VerifyEmbeddedSignatureCacheOnly(L"relative.dll", ops);
    RS2_CHECK(state.calls == 0 && !result.closeAttempted);
#ifdef RS2_PE_CONTRACT_PATH
    DWORD exitCode = 0; std::string output;
    RS2_CHECK(RunHelp(L"--help", &exitCode, &output));
    RS2_CHECK(exitCode == 0 && output.find("--kind") != std::string::npos && output.find("--file") != std::string::npos &&
        output.find("companion-active") != std::string::npos && output.find("fixture-bootstrap") != std::string::npos);
    wchar_t temporary[32768]{};
    const DWORD tempLength = GetTempPathW(static_cast<DWORD>(std::size(temporary)), temporary);
    RS2_CHECK(tempLength > 0 && tempLength < std::size(temporary));
    if (tempLength > 0 && tempLength < std::size(temporary)) {
        const auto sentinel = std::wstring(temporary) + L"rs2-pe-help-sentinel-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".dll";
        RS2_CHECK(GetFileAttributesW(sentinel.c_str()) == INVALID_FILE_ATTRIBUTES);
        const auto tail = L"--help --file \"" + sentinel + L"\"";
        output.clear();
        RS2_CHECK(RunHelp(tail.c_str(), &exitCode, &output) && exitCode == 2);
        RS2_CHECK(GetFileAttributesW(sentinel.c_str()) == INVALID_FILE_ATTRIBUTES);
    }
#endif
#ifdef RS2_NORMAL_IMPORT_FIXTURE_PATH
    pe::Image normal; std::string error;
    RS2_CHECK(pe::ReadPeImage(RS2_NORMAL_IMPORT_FIXTURE_PATH, &normal, &error));
    bool normalFound = false;
    for (const auto& module : normal.normalImports) for (const auto& symbol : module.symbols)
        if (symbol.name == "X3DAudioInitialize" && !symbol.byOrdinal) normalFound = true;
    RS2_CHECK(normalFound);
#endif
#ifdef RS2_DELAY_IMPORT_FIXTURE_PATH
    pe::Image delayed; std::string delayError;
    RS2_CHECK(pe::ReadPeImage(RS2_DELAY_IMPORT_FIXTURE_PATH, &delayed, &delayError));
    bool delayFound = false;
    for (const auto& module : delayed.delayImports) for (const auto& symbol : module.symbols)
        if (symbol.name == "X3DAudioInitialize" && !symbol.byOrdinal) delayFound = true;
    RS2_CHECK(delayFound);
#endif
}
}
