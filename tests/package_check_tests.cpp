#include "companion/package_check.h"
#include "companion/sha256.h"
#include "shared/version.h"
#include "test_framework.h"
#include <array>
#include <cstring>
#include <initializer_list>
#include <utility>
#include <string>

namespace rs2fix::testcases {
namespace {
constexpr std::size_t kPage = 0x1000;
constexpr std::uint32_t kImageSize = 0x5000;
constexpr std::uint32_t kNtRva = 0x80;
constexpr std::uint32_t kSectionRva = kNtRva + sizeof(IMAGE_NT_HEADERS64);
constexpr std::uint32_t kFunctionRva = 0x2080;
constexpr std::uint32_t kFunctionSize = 0x80;
constexpr std::uint32_t kPassedStoreRva = kFunctionRva + 0x40;
constexpr std::uint32_t kGreyStoreRva = kFunctionRva + 0x50;
constexpr std::uint32_t kClearRva = kFunctionRva + 0x60;
constexpr std::uint32_t kRemoveRva = 0x2800;
constexpr std::uint32_t kPassedRva = 0x4100;
constexpr std::uint32_t kGreyRva = 0x4104;
constexpr std::uint32_t kWaitingRva = 0x4110;
constexpr std::array<std::uint8_t, 8> kStartupBytes{0x48,0x83,0xEC,0x28,0x90,0x90,0x90,0x90};

struct Image {
    alignas(16) std::array<std::uint8_t, kImageSize> bytes{};
    std::array<DWORD, 5> protections{
        PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};
    ByteSpan span{0x1000, kStartupBytes.size(), kStartupBytes.data()};
    StartupProfile startup{};
    PackageCheckProfile profile{};
    BootstrapContextV3 context{};
    std::array<std::uint8_t, kFunctionSize> original{}, patched{};
    unsigned protects{}, writes{}, flushes{}, identities{}, functionReads{}, invalidAccesses{};
    std::uint32_t protectFailures{}, writeFailures{}, flushFailures{};
    unsigned failFunctionReadAt{}, failIdentityAt{};
    DWORD temporaryProtection{PAGE_EXECUTE_READWRITE};
    bool wrongOldProtection{}, advanceStageOnIdentity{}, advanceStageOnProtect{};
    bool partialWriteOnFailure{}, corruptReadAfterWrite{}, corruptionUsed{}, wrongHost{};
    std::array<DWORD, 8> requestedProtections{};

    Image() {
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = kNtRva;
        Put(0, dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 3;
        nt.FileHeader.TimeDateStamp = 0x12345678;
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = kImageSize;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
        nt.OptionalHeader.CheckSum = 0x10203040;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        Put(kNtRva, nt);
        IMAGE_SECTION_HEADER section{};
        section.VirtualAddress = 0x1000;
        section.Misc.VirtualSize = 0x2000;
        section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        Put(kSectionRva, section);
        section.VirtualAddress = 0x3000;
        section.Misc.VirtualSize = 0x1000;
        section.Characteristics = IMAGE_SCN_MEM_READ;
        Put(kSectionRva + sizeof(section), section);
        section.VirtualAddress = 0x4000;
        section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        Put(kSectionRva + 2 * sizeof(section), section);
        std::memcpy(bytes.data() + span.rva, span.bytes, span.size);
        startup = {kImageSize, nt.FileHeader.TimeDateStamp, {nt.OptionalHeader.CheckSum, 0},
            1, 0x1000, 0x1010, 0x4000, 1, 0x3100, 0x1040, &span, 1};
        Put(startup.stateRva, DWORD{1});
        Put(startup.initializerSlotRva, Base() + startup.initializerRva);
        context = {sizeof(BootstrapContextV3), kBootstrapAbiVersion,
            reinterpret_cast<HMODULE>(Base()), reinterpret_cast<HMODULE>(0x10000),
            reinterpret_cast<HMODULE>(0x20000), kRequiredGenuineExports, 0,
            Base() + startup.returnRva, GetCurrentThreadId(), GetCurrentThreadId(), 1,
            kTriggerExeCrtInitialize};
        profile = {kFunctionRva, kFunctionSize, kPassedStoreRva, kGreyStoreRva, kClearRva,
            kPassedRva, kGreyRva, kWaitingRva, kRemoveRva, {}, {}, {}};
        // Our own bounded byte arrays only; nothing here is executed.
        original.fill(0x90);
        original.back() = 0xC3;
        Encode(kPassedStoreRva, {0x44,0x89,0x35}, 7, kPassedRva);
        Encode(kGreyStoreRva, {0x44,0x89,0x35}, 7, kGreyRva);
        Encode(kClearRva, {0x44,0x8B,0x05}, 7, kWaitingRva + 8);
        original[kClearRva + 7 - kFunctionRva] = 0x33;
        original[kClearRva + 8 - kFunctionRva] = 0xD2;
        Encode(kClearRva + 9, {0x48,0x8D,0x0D}, 7, kWaitingRva);
        Encode(kClearRva + 16, {0xE8}, 5, kRemoveRva);
        PackageCheckStub stub{};
        RS2_CHECK(BuildPackageCheckStub(profile, &stub));
        patched = original;
        std::memcpy(patched.data(), stub.data(), stub.size());
        std::memcpy(bytes.data() + kFunctionRva, original.data(), original.size());
        Put(kPassedRva, DWORD{1});
        RS2_CHECK(HashBytesSha256("own-code-package-fixture", 24, &profile.hostDigest));
        RS2_CHECK(HashBytesSha256(original.data(), original.size(), &profile.originalDigest));
        RS2_CHECK(HashBytesSha256(patched.data(), patched.size(), &profile.patchedDigest));
    }
    Image(const Image&) = delete;
    Image& operator=(const Image&) = delete;
    void Encode(std::uint32_t rva, std::initializer_list<std::uint8_t> opcode,
                std::uint32_t length, std::uint32_t target) {
        const auto offset = rva - kFunctionRva;
        std::size_t cursor = offset;
        for (auto value : opcode) original[cursor++] = value;
        const auto displacement = static_cast<std::int32_t>(
            static_cast<std::int64_t>(target) - static_cast<std::int64_t>(rva + length));
        std::memcpy(original.data() + cursor, &displacement, sizeof(displacement));
    }
    std::uintptr_t Base() const { return reinterpret_cast<std::uintptr_t>(bytes.data()); }
    template<class T> void Put(std::uint32_t rva, const T& value) {
        RS2_CHECK(rva <= bytes.size() && sizeof(T) <= bytes.size() - rva);
        std::memcpy(bytes.data() + rva, &value, sizeof(T));
    }
    bool Bounds(std::uintptr_t address, std::size_t size) {
        const bool valid = address >= Base() && address - Base() <= bytes.size() &&
            size <= bytes.size() - (address - Base());
        if (!valid) ++invalidAccesses;
        return valid;
    }
    static bool Fails(std::uint32_t mask, unsigned call) {
        return call > 0 && call <= 32 && (mask & (1u << (call - 1))) != 0;
    }
    bool Original() const { return std::memcmp(bytes.data() + kFunctionRva, original.data(), original.size()) == 0; }
    bool Patched() const { return std::memcmp(bytes.data() + kFunctionRva, patched.data(), patched.size()) == 0; }
    ReconResult Run(ReconMode mode = ReconMode::Active) {
        Sha256Digest host = profile.hostDigest;
        if (wrongHost) host[0] ^= 1;
        return RunPackageCheckBypass(context, startup, profile, mode, host, Ops());
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* region, DWORD* error) noexcept {
        auto& state = *static_cast<Image*>(context);
        if (!state.Bounds(address, 1)) { *error = ERROR_INVALID_ADDRESS; return false; }
        const auto page = (address - state.Base()) / kPage;
        *region = {state.Base() + page * kPage, state.Base(), kPage, MEM_COMMIT, MEM_IMAGE,
            state.protections[page]};
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Read(void* context, std::uintptr_t address, void* output, std::size_t size, DWORD* error) noexcept {
        auto& state = *static_cast<Image*>(context);
        if (!state.Bounds(address, size)) { *error = ERROR_INVALID_ADDRESS; return false; }
        const auto rva = address - state.Base();
        const bool function = rva == kFunctionRva && size == kFunctionSize;
        if (function && ++state.functionReads == state.failFunctionReadAt) {
            *error = ERROR_PARTIAL_COPY;
            return false;
        }
        std::memcpy(output, state.bytes.data() + rva, size);
        if (function && state.writes == 1 && state.corruptReadAfterWrite && !state.corruptionUsed) {
            state.corruptionUsed = true;
            static_cast<std::uint8_t*>(output)[0] ^= 1;
        }
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Protect(void* context, std::uintptr_t address, std::size_t size,
                        DWORD requested, DWORD* previous, DWORD* error) noexcept {
        auto& state = *static_cast<Image*>(context);
        ++state.protects;
        if (state.protects <= state.requestedProtections.size())
            state.requestedProtections[state.protects - 1] = requested;
        if (address != state.Base() + kFunctionRva || size != kPackageCheckStubSize) {
            ++state.invalidAccesses;
            *error = ERROR_INVALID_ADDRESS;
            return false;
        }
        if (Fails(state.protectFailures, state.protects)) { *error = ERROR_ACCESS_DENIED; return false; }
        *previous = state.wrongOldProtection && state.protects == 1 ? PAGE_READWRITE : state.protections[2];
        state.protections[2] = requested == PAGE_EXECUTE_READWRITE ? state.temporaryProtection : requested;
        if (state.advanceStageOnProtect && state.protects == 1) state.Put(state.startup.stateRva, DWORD{2});
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Write(void* context, std::uintptr_t address, const void* source, std::size_t size,
                      DWORD* error) noexcept {
        auto& state = *static_cast<Image*>(context);
        ++state.writes;
        if (address != state.Base() + kFunctionRva || size != kPackageCheckStubSize ||
            (state.protections[2] != PAGE_EXECUTE_READWRITE && state.protections[2] != PAGE_EXECUTE_WRITECOPY)) {
            ++state.invalidAccesses;
            *error = ERROR_INVALID_ADDRESS;
            return false;
        }
        const bool fail = Fails(state.writeFailures, state.writes);
        // A reported failure may still have changed bytes: rollback must not assume otherwise.
        const std::size_t copied = !fail ? size : state.partialWriteOnFailure ? size / 2 : 0;
        std::memcpy(reinterpret_cast<void*>(address), source, copied);
        *error = fail ? ERROR_WRITE_FAULT : ERROR_SUCCESS;
        return !fail;
    }
    static bool Flush(void* context, std::uintptr_t address, std::size_t size, DWORD* error) noexcept {
        auto& state = *static_cast<Image*>(context);
        ++state.flushes;
        if (address != state.Base() + kFunctionRva || size != kFunctionSize) {
            ++state.invalidAccesses;
            *error = ERROR_INVALID_ADDRESS;
            return false;
        }
        *error = Fails(state.flushFailures, state.flushes) ? ERROR_WRITE_FAULT : ERROR_SUCCESS;
        return *error == ERROR_SUCCESS;
    }
    static FixReason Identity(void* context, DWORD* error) noexcept {
        auto& state = *static_cast<Image*>(context);
        ++state.identities;
        if (state.advanceStageOnIdentity) state.Put(state.startup.stateRva, DWORD{2});
        const bool fail = state.identities == state.failIdentityAt;
        *error = fail ? ERROR_FILE_INVALID : ERROR_SUCCESS;
        return fail ? FixReason::HostIdentityChanged : FixReason::None;
    }
    PackageCheckOps Ops() { return {{this, Query, Read}, this, Protect, Write, Flush, Identity}; }
};

// Runs the transaction and proves it touched nothing, relative to any state the
// scenario itself prepared (a changed byte, an unexpected page protection).
void CheckNoMutation(Image& image, ReconMode mode, FixReason reason) {
    const auto bytes = image.bytes;
    const auto protections = image.protections;
    const auto result = image.Run(mode);
    RS2_CHECK(result.outcome == ReconOutcome::Disabled && result.reason == reason && !result.qualified);
    RS2_CHECK(image.protects == 0 && image.writes == 0 && image.flushes == 0);
    // advanceStageOnIdentity's fake itself moves the startup stage word mid-run.
    auto expected = bytes;
    std::memcpy(expected.data() + image.startup.stateRva, image.bytes.data() + image.startup.stateRva, sizeof(DWORD));
    RS2_CHECK(image.bytes == expected && image.protections == protections && image.invalidAccesses == 0);
}

void TestProductionStub() {
    // Independently derived from the preserved production PEs (RVA arithmetic
    // by hand, cross-checked against the original instruction encodings).
    constexpr std::array<std::uint8_t, kPackageCheckStubSize> expected{
        0xC7,0x05,0x9A,0x40,0x9A,0x00,0x01,0x00,0x00,0x00,
        0xC7,0x05,0x24,0x4F,0xC2,0x00,0x00,0x00,0x00,0x00,
        0x44,0x8B,0x05,0xDD,0x50,0xCA,0x00,
        0x33,0xD2,
        0x48,0x8D,0x0D,0xCC,0x50,0xCA,0x00,
        0xE9,0x87,0xD5,0x54,0xFF};
    for (const auto* profile : {&kFullDumpPackageCheckProfile, &kStockPackageCheckProfile}) {
        PackageCheckStub stub{};
        RS2_CHECK(BuildPackageCheckStub(*profile, &stub) && stub == expected);
    }
    RS2_CHECK(SelectedPackageCheckProfile(kCurrentFullDumpDigest) == &kFullDumpPackageCheckProfile);
    RS2_CHECK(SelectedPackageCheckProfile(kCurrentStockDigest) == &kStockPackageCheckProfile);
    Sha256Digest other = kCurrentStockDigest;
    other[0] ^= 1;
    RS2_CHECK(SelectedPackageCheckProfile(other) == nullptr);
    // A target out of rel32 reach cannot be encoded.
    auto distant = kFullDumpPackageCheckProfile;
    distant.removeRva = 0xFFFFFFF0u;
    distant.functionRva = 0x10;
    PackageCheckStub stub{};
    RS2_CHECK(!BuildPackageCheckStub(distant, &stub));
}

void TestSuccess() {
    for (ReconMode mode : {ReconMode::Passive, ReconMode::Active}) {
        for (DWORD writable : {DWORD{PAGE_EXECUTE_READWRITE}, DWORD{PAGE_EXECUTE_WRITECOPY}}) {
            Image image;
            image.temporaryProtection = writable;
            const auto before = image.bytes;
            const auto result = image.Run(mode);
            RS2_CHECK(result.qualified && result.reason == FixReason::None && result.error == ERROR_SUCCESS);
            RS2_CHECK(image.protections[2] == PAGE_EXECUTE_READ && image.invalidAccesses == 0);
            RS2_CHECK(image.identities == (mode == ReconMode::Active ? 2u : 1u));
            if (mode == ReconMode::Passive) {
                RS2_CHECK(result.outcome == ReconOutcome::Passive && image.bytes == before);
                RS2_CHECK(image.protects == 0 && image.writes == 0 && image.flushes == 0);
                continue;
            }
            RS2_CHECK(result.outcome == ReconOutcome::Active && image.Patched());
            RS2_CHECK(image.protects == 2 && image.writes == 1 && image.flushes == 1);
            RS2_CHECK(image.requestedProtections[0] == PAGE_EXECUTE_READWRITE &&
                image.requestedProtections[1] == PAGE_EXECUTE_READ);
            bool outsideStubUnchanged = true;
            for (std::size_t offset = 0; offset < before.size(); ++offset)
                if (offset < kFunctionRva || offset >= kFunctionRva + kPackageCheckStubSize)
                    outsideStubUnchanged = outsideStubUnchanged && before[offset] == image.bytes[offset];
            RS2_CHECK(outsideStubUnchanged);
        }
    }
}

void TestPreWriteRejections() {
    for (ReconMode mode : {ReconMode::Passive, ReconMode::Active}) {
        for (unsigned scenario = 0; scenario < 15; ++scenario) {
            Image image;
            FixReason expected = FixReason::FunctionMismatch;
            switch (scenario) {
            case 0: image.Put(image.startup.stateRva, DWORD{2}); expected = FixReason::StartupRejected; break;
            case 1: image.context.size = 0; expected = FixReason::StartupRejected; break;
            case 2: image.bytes[kFunctionRva + kFunctionSize - 2] ^= 1; break;
            // The digest still matches; only the stub's targets disagree with the original's.
            case 3: image.profile.passedRva += 8; break;
            case 4: image.profile.greyRva += 4; break;
            case 5: image.profile.waitingRva += 0x10; break;
            case 6: image.profile.removeRva += 0x10; break;
            case 7: image.profile.patchedDigest[0] ^= 1; expected = FixReason::PreparedDigestMismatch; break;
            case 8: image.protections[2] = PAGE_EXECUTE_READWRITE; expected = FixReason::ProtectionMismatch; break;
            case 9: image.profile.greyRva = 0x3200; expected = FixReason::ProtectionMismatch; break;   // read-only data
            case 10: image.profile.removeRva = 0x4200; expected = FixReason::ProtectionMismatch; break; // not code
            case 11: image.failFunctionReadAt = 1; expected = FixReason::CodeUnreadable; break;
            case 12: image.failIdentityAt = 1; expected = FixReason::HostIdentityChanged; break;
            case 13: image.advanceStageOnIdentity = true; expected = FixReason::StartupRejected; break;
            case 14: image.profile.originalDigest[0] ^= 1; break;
            }
            CheckNoMutation(image, mode, expected);
        }
        Image wrongHost;
        wrongHost.wrongHost = true;
        CheckNoMutation(wrongHost, mode, FixReason::UnsupportedHost);
        Image alreadyPatched;
        std::memcpy(alreadyPatched.bytes.data() + kFunctionRva, alreadyPatched.patched.data(), kFunctionSize);
        CheckNoMutation(alreadyPatched, mode, FixReason::FunctionMismatch);
    }
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        Image image;
        switch (scenario) {
        case 0: image.profile.functionSize = static_cast<std::uint32_t>(kPackageCheckFunctionCapacity + 1); break;
        case 1: image.profile.clearRva = kFunctionRva + kFunctionSize - 4; break;
        case 2: image.profile.removeRva = kFunctionRva + 4; break;
        case 3: image.profile.functionSize = kPackageCheckStubSize - 1; break;
        }
        CheckNoMutation(image, ReconMode::Active, FixReason::InvalidContext);
    }
}

void TestTransactionFailures() {
    for (unsigned scenario = 0; scenario < 10; ++scenario) {
        Image image;
        FixReason expected = FixReason::ReadbackFailed;
        bool noWrite = false;
        switch (scenario) {
        case 0: image.protectFailures = 1u; expected = FixReason::ProtectFailed; noWrite = true; break;
        case 1: image.wrongOldProtection = true; expected = FixReason::ProtectionMismatch; noWrite = true; break;
        case 2: image.advanceStageOnProtect = true; expected = FixReason::StartupRejected; noWrite = true; break;
        case 3: image.writeFailures = 1u; expected = FixReason::WriteFailed; break;
        case 4: image.writeFailures = 1u; image.partialWriteOnFailure = true; expected = FixReason::WriteFailed; break;
        case 5: image.corruptReadAfterWrite = true; break;
        case 6: image.protectFailures = 2u; expected = FixReason::RestoreFailed; break;
        case 7: image.flushFailures = 1u; expected = FixReason::FlushFailed; break;
        case 8: image.failIdentityAt = 2; expected = FixReason::HostIdentityChanged; break;
        case 9: image.temporaryProtection = PAGE_EXECUTE_READ; expected = FixReason::ProtectionMismatch; noWrite = true; break;
        }
        const auto result = image.Run();
        RS2_CHECK(result.outcome == (noWrite ? ReconOutcome::Disabled : ReconOutcome::RolledBack));
        RS2_CHECK(result.reason == expected && result.qualified);
        RS2_CHECK(image.Original() && image.protections[2] == PAGE_EXECUTE_READ && image.invalidAccesses == 0);
        if (noWrite) RS2_CHECK(image.writes == 0 && image.flushes == 0);
        else RS2_CHECK(image.writes == 2 && image.protects <= 4 && image.flushes <= 2);
    }
}

void TestFatal() {
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        Image image;
        switch (scenario) {
        case 0: image.flushFailures = 1u; image.protectFailures = 4u; break; // rollback cannot make writable
        case 1: image.flushFailures = 1u; image.writeFailures = 2u; break;   // rollback write fails
        case 2: image.flushFailures = 3u; break;                             // rollback flush also fails
        case 3: image.advanceStageOnProtect = true; image.protectFailures = 2u; break; // no-write restore fails
        }
        const auto result = image.Run();
        RS2_CHECK(result.outcome == ReconOutcome::Fatal && result.reason == FixReason::RollbackFailed);
        RS2_CHECK(image.invalidAccesses == 0 && image.writes <= 2 && image.protects <= 4);
        if (scenario == 0 || scenario == 1) RS2_CHECK(image.Patched());
        if (scenario == 2) RS2_CHECK(image.Original());
        if (scenario == 3) RS2_CHECK(image.Original() && image.writes == 0);
    }
}

void TestConfig() {
    const auto parse = [](const char* text) { return ParsePackageCheckConfig(text, std::strlen(text)); };
    for (const char* on : {"AllowAnyMutator=true", "allowanymutator=TRUE", "AllowAnyMutator = True \t",
             "AllowAnyMutator=1", "[RS2ServerFix]\r\n; ranked with any mutator\r\nAllowAnyMutator=True\r\n",
             "\xEF\xBB\xBF" "AllowAnyMutator=true\r\n", "# note\nAllowAnyMutator=true\n\n"})
        RS2_CHECK(parse(on) == PackageCheckConfig::Enabled);
    for (const char* off : {"AllowAnyMutator=false", "AllowAnyMutator=FALSE", "AllowAnyMutator=0",
             "[RS2ServerFix]\r\nAllowAnyMutator=False\r\n"})
        RS2_CHECK(parse(off) == PackageCheckConfig::Disabled);
    for (const char* absent : {"", "\r\n", "[RS2ServerFix]\r\n", "; AllowAnyMutator=true\r\n", "\xEF\xBB\xBF"})
        RS2_CHECK(parse(absent) == PackageCheckConfig::Absent);
    for (const char* bad : {"AllowAnyMutator=", "AllowAnyMutator=yes", "AllowAnyMutator=true;x",
             "AllowAnyMutators=true", "bAllowAnyMutator=true", "AllowAnyMutator", "mode=bypass",
             "AllowAnyMutator=true\r\nAllowAnyMutator=true", "AllowAnyMutator=true\r\nOther=1",
             "[RS2ServerFix\r\nAllowAnyMutator=true", "AllowAnyMutator=true\x01",
             "AllowAnyMutator=tr\xC3\xBC" "e", "\xFF\xFE" "A\0"})
        RS2_CHECK(parse(bad) == PackageCheckConfig::Invalid);
    RS2_CHECK(ParsePackageCheckConfig("\xFF\xFE" "A\0l\0", 6) == PackageCheckConfig::Invalid); // UTF-16
    RS2_CHECK(ParsePackageCheckConfig(nullptr, 4) == PackageCheckConfig::Invalid);
    std::string large(257, ' ');
    large.replace(0, 20, "AllowAnyMutator=true");
    RS2_CHECK(ParsePackageCheckConfig(large.data(), large.size()) == PackageCheckConfig::Invalid);

    wchar_t temp[MAX_PATH]{};
    RS2_CHECK(GetTempPathW(MAX_PATH, temp) > 0);
    const std::wstring directory = std::wstring(temp) + L"rs2_package_check_" +
        std::to_wstring(GetCurrentProcessId());
    const std::wstring file = directory + L"\\RS2PackageCheck.ini";
    RS2_CHECK(CreateDirectoryW(directory.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    DeleteFileW(file.c_str());
    DWORD error = 1;
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Absent && error == 0);
    const auto write = [&](const char* text) {
        const HANDLE handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        DWORD written{};
        RS2_CHECK(handle != INVALID_HANDLE_VALUE &&
            WriteFile(handle, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr) &&
            CloseHandle(handle));
    };
    write("[RS2ServerFix]\r\nAllowAnyMutator=False\r\n");
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Disabled && error == 0);
    write("[RS2ServerFix]\r\nAllowAnyMutator=True\r\n");
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Enabled && error == 0);
    write("AllowAnyMutator=maybe\r\n");
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Invalid && error != 0);
    write("");
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Absent && error == 0);
    std::string oversized(300, ';');
    write(oversized.c_str());
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Invalid && error != 0);
    RS2_CHECK(DeleteFileW(file.c_str()));
    RS2_CHECK(CreateDirectoryW(file.c_str(), nullptr)); // a directory is never a configuration
    RS2_CHECK(ReadPackageCheckConfig(directory.c_str(), &error) == PackageCheckConfig::Invalid);
    RS2_CHECK(RemoveDirectoryW(file.c_str()) && RemoveDirectoryW(directory.c_str()));
    RS2_CHECK(ReadPackageCheckConfig(nullptr, &error) == PackageCheckConfig::Invalid);
}

void TestLine() {
    PackageCheckReport report{};
    report.stage = PackageCheckStage::Ran;
    report.config = PackageCheckConfig::Enabled;
    report.mode = ReconMode::Active;
    report.result = {ReconOutcome::Active, FixReason::None, ERROR_SUCCESS, true};
    report.host = BuildIdentity::CurrentFullDump;
    report.processId = 4242;
    ConsoleReportContext line{};
    RS2_CHECK(FormatPackageCheckLine(report, &line) && ValidConsoleReport(line));
    RS2_CHECK(std::string(line.line, line.bytes) == std::string("[RS2PackageCheck] v") + RS2FIX_VERSION_ASCII +
        " package_check=active reason=none mode=active allow_any_mutator=true host=current-full-dump pid=4242 error=0\r\n");
    report.stage = PackageCheckStage::ConfigOff;
    report.result = {ReconOutcome::Disabled, FixReason::None, ERROR_SUCCESS, false};
    const std::pair<PackageCheckConfig, const char*> off[]{
        {PackageCheckConfig::Disabled, " package_check=off reason=allow_any_mutator_false mode=active allow_any_mutator=false "},
        {PackageCheckConfig::Absent, " package_check=off reason=allow_any_mutator_absent mode=active allow_any_mutator=absent "},
        {PackageCheckConfig::Invalid, " package_check=off reason=config_invalid mode=active allow_any_mutator=invalid "}};
    for (const auto& [config, expected] : off) {
        report.config = config;
        RS2_CHECK(FormatPackageCheckLine(report, &line) && std::string(line.line).find(expected) != std::string::npos);
    }
    report = {};
    RS2_CHECK(FormatPackageCheckLine(report, &line) &&
        std::string(line.line).find(" package_check=skipped reason=recon_not_accepted mode=passive allow_any_mutator=unread ") != std::string::npos);
    report.result.reason = static_cast<FixReason>(999);
    RS2_CHECK(!FormatPackageCheckLine(report, &line) && line.bytes == 0);
}
}
void RunPackageCheckTests() {
    TestProductionStub();
    TestSuccess();
    TestPreWriteRejections();
    TestTransactionFailures();
    TestFatal();
    TestConfig();
    TestLine();
}
}
