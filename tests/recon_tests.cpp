#include "companion/recon_fix.h"
#include "companion/sha256.h"
#include "test_framework.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace rs2fix::testcases {
namespace {
constexpr std::size_t kPage = 0x1000;
constexpr std::uint32_t kImageSize = 0x5000;
constexpr std::uint32_t kNtRva = 0x80;
constexpr std::uint32_t kSectionRva = kNtRva + sizeof(IMAGE_NT_HEADERS64);
constexpr std::uint32_t kFunctionRva = 0x2080;
constexpr std::uint32_t kFunctionSize = 64;
constexpr std::uint32_t kLoadRva = 0x2094;
constexpr std::uint32_t kConstantRva = 0x3080;
constexpr std::array<std::uint8_t, 8> kStartupBytes{0x48,0x83,0xEC,0x28,0x90,0x90,0x90,0x90};

struct SyntheticImage {
    alignas(16) std::array<std::uint8_t, kImageSize> bytes{};
    std::array<DWORD, 5> protections{
        PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};
    ByteSpan span{0x1000, kStartupBytes.size(), kStartupBytes.data()};
    StartupProfile startup{};
    ReconProfile profile{};
    BootstrapContextV3 context{};
    std::array<std::uint8_t, kFunctionSize> original{};
    std::array<std::uint8_t, kFunctionSize> corrected{};
    unsigned protects{}, writes{}, flushes{}, identities{}, functionReads{}, constantReads{};
    unsigned invalidAccesses{};
    std::uint32_t protectFailures{}, writeFailures{}, flushFailures{};
    unsigned failFunctionReadAt{}, corruptFunctionReadAt{}, failIdentityAt{};
    unsigned failFunctionReadsRemainingAfterProtect{};
    DWORD temporaryProtection{PAGE_EXECUTE_READWRITE};
    bool wrongOldProtection{}, wrongRestoredProtection{}, wrongAllocation{}, wrongRegionType{}, uncommitted{};
    bool advanceStageOnIdentity{}, advanceStageOnProtect{}, mutateConstantOnWrite{};
    bool mutateBeforeWriteFailure{}, mutateNeighborOnWrite{}, failQuery{}, failConstantRead{};
    bool failReadAfterWrite{}, corruptReadAfterWrite{}, readAfterWriteFaultUsed{};
    bool badRegionExtent{}, protectNoOp{};
    std::array<DWORD, 8> requestedProtections{};
    std::array<std::uint32_t, 8> writtenValues{};

    SyntheticImage() {
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
        profile.functionRva = kFunctionRva;
        profile.functionSize = kFunctionSize;
        profile.loadRva = kLoadRva;
        profile.operandRva = kLoadRva + 4;
        profile.constantRva = kConstantRva;
        profile.oldDisplacement = 0x0E44;
        profile.newDisplacement = kConstantRva - (kLoadRva + 8);
        profile.originalWindow = {0xF3,0x0F,0x10,0x35,0x44,0x0E,0,0,0x0F,0x1F,0x40,0};
        profile.constantBytes = {0,0,0,0x38,0,0,0,0x38,0,0,0,0x38,0,0,0,0x38};
        // These are only our own bounded byte arrays. No mapped bytes are executed.
        original.fill(0x90);
        original.back() = 0xC3;
        std::memcpy(original.data() + profile.loadRva - kFunctionRva,
            profile.originalWindow.data(), profile.originalWindow.size());
        corrected = original;
        std::memcpy(corrected.data() + profile.operandRva - kFunctionRva,
            &profile.newDisplacement, sizeof(profile.newDisplacement));
        std::memcpy(bytes.data() + kFunctionRva, original.data(), original.size());
        std::memcpy(bytes.data() + kConstantRva, profile.constantBytes.data(), profile.constantBytes.size());
        RS2_CHECK(HashBytesSha256("own-code-recon-fixture", 21, &profile.hostDigest));
        RS2_CHECK(HashBytesSha256(original.data(), original.size(), &profile.originalDigest));
        RS2_CHECK(HashBytesSha256(corrected.data(), corrected.size(), &profile.correctedDigest));
    }
    SyntheticImage(const SyntheticImage&) = delete;
    SyntheticImage& operator=(const SyntheticImage&) = delete;
    std::uintptr_t Base() const { return reinterpret_cast<std::uintptr_t>(bytes.data()); }
    template<class T> void Put(std::uint32_t rva, const T& value) {
        RS2_CHECK(rva <= bytes.size() && sizeof(T) <= bytes.size() - rva);
        std::memcpy(bytes.data() + rva, &value, sizeof(T));
    }
    template<class T> T Get(std::uint32_t rva) const {
        T value{};
        std::memcpy(&value, bytes.data() + rva, sizeof(T));
        return value;
    }
    bool Bounds(std::uintptr_t address, std::size_t size) {
        const bool valid = address >= Base() && address - Base() <= bytes.size() &&
            size <= bytes.size() - (address - Base());
        if (!valid) ++invalidAccesses;
        return valid;
    }
    static bool Fails(std::uint32_t mask, unsigned call) {
        // Bit zero selects the first call, including calls made during rollback.
        return call > 0 && call <= 32 && (mask & (1u << (call - 1))) != 0;
    }
    bool Original() const {
        return std::memcmp(bytes.data() + kFunctionRva, original.data(), original.size()) == 0;
    }
    bool Corrected() const {
        return std::memcmp(bytes.data() + kFunctionRva, corrected.data(), corrected.size()) == 0;
    }
    ReconResult Run(ReconMode mode = ReconMode::Active) {
        return RunReconFix(context, startup, profile, mode, profile.hostDigest, Ops());
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* region, DWORD* error) noexcept {
        auto& state = *static_cast<SyntheticImage*>(context);
        if (state.failQuery || !state.Bounds(address, 1)) { *error = ERROR_INVALID_ADDRESS; return false; }
        const auto page = (address - state.Base()) / kPage;
        *region = {state.Base() + page * kPage,
            state.wrongAllocation ? state.Base() + 16 : state.Base(),
            state.badRegionExtent ? 0 : kPage,
            static_cast<DWORD>(state.uncommitted ? MEM_RESERVE : MEM_COMMIT),
            static_cast<DWORD>(state.wrongRegionType ? MEM_PRIVATE : MEM_IMAGE), state.protections[page]};
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Read(void* context, std::uintptr_t address, void* output, std::size_t size, DWORD* error) noexcept {
        auto& state = *static_cast<SyntheticImage*>(context);
        if (!state.Bounds(address, size)) { *error = ERROR_INVALID_ADDRESS; return false; }
        const auto rva = address - state.Base();
        if (rva == kFunctionRva && size == kFunctionSize) {
            ++state.functionReads;
            if (state.protects && state.failFunctionReadsRemainingAfterProtect) {
                --state.failFunctionReadsRemainingAfterProtect;
                *error = ERROR_PARTIAL_COPY;
                return false;
            }
            if (state.functionReads == state.failFunctionReadAt) { *error = ERROR_PARTIAL_COPY; return false; }
            if (state.writes == 1 && state.failReadAfterWrite && !state.readAfterWriteFaultUsed) {
                state.readAfterWriteFaultUsed = true;
                *error = ERROR_PARTIAL_COPY;
                return false;
            }
        }
        if (rva == kConstantRva) {
            ++state.constantReads;
            if (state.failConstantRead) { *error = ERROR_PARTIAL_COPY; return false; }
        }
        std::memcpy(output, state.bytes.data() + rva, size);
        if (rva == kFunctionRva && size == kFunctionSize &&
            state.functionReads == state.corruptFunctionReadAt)
            static_cast<std::uint8_t*>(output)[0] ^= 1;
        if (rva == kFunctionRva && size == kFunctionSize && state.writes == 1 &&
            state.corruptReadAfterWrite && !state.readAfterWriteFaultUsed) {
            state.readAfterWriteFaultUsed = true;
            static_cast<std::uint8_t*>(output)[0] ^= 1;
        }
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Protect(void* context, std::uintptr_t address, std::size_t size,
                        DWORD requested, DWORD* previous, DWORD* error) noexcept {
        auto& state = *static_cast<SyntheticImage*>(context);
        ++state.protects;
        if (state.protects <= state.requestedProtections.size())
            state.requestedProtections[state.protects - 1] = requested;
        if (!state.Bounds(address, size) || address != state.Base() + state.profile.operandRva || size != 4) {
            ++state.invalidAccesses;
            *error = ERROR_INVALID_ADDRESS;
            return false;
        }
        if (Fails(state.protectFailures, state.protects)) { *error = ERROR_ACCESS_DENIED; return false; }
        *previous = state.protections[2];
        if (state.wrongOldProtection && state.protects == 1) *previous = PAGE_READWRITE;
        if (!state.protectNoOp)
            state.protections[2] = requested == PAGE_EXECUTE_READWRITE ? state.temporaryProtection : requested;
        if (state.wrongRestoredProtection && state.protects == 2) state.protections[2] = PAGE_EXECUTE_READWRITE;
        if (state.advanceStageOnProtect && state.protects == 1) state.Put(state.startup.stateRva, DWORD{2});
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Write(void* context, std::uintptr_t address, std::uint32_t value, DWORD* error) noexcept {
        auto& state = *static_cast<SyntheticImage*>(context);
        ++state.writes;
        if (state.writes <= state.writtenValues.size()) state.writtenValues[state.writes - 1] = value;
        if (!state.Bounds(address, 4) || address != state.Base() + state.profile.operandRva || (address & 3) != 0 ||
            (state.protections[2] != PAGE_EXECUTE_READWRITE && state.protections[2] != PAGE_EXECUTE_WRITECOPY)) {
            ++state.invalidAccesses;
            *error = ERROR_INVALID_ADDRESS;
            return false;
        }
        const bool fail = Fails(state.writeFailures, state.writes);
        // Exercise the conservative transaction rule: a reported write failure
        // can still require rollback because bytes may already have changed.
        if (!fail || state.mutateBeforeWriteFailure) std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
        if (state.mutateConstantOnWrite && state.writes == 1) state.bytes[kConstantRva] ^= 1;
        if (state.mutateNeighborOnWrite && state.writes == 1) state.bytes[kFunctionRva] ^= 1;
        *error = fail ? ERROR_WRITE_FAULT : ERROR_SUCCESS;
        return !fail;
    }
    static bool Flush(void* context, std::uintptr_t address, std::size_t size, DWORD* error) noexcept {
        auto& state = *static_cast<SyntheticImage*>(context);
        ++state.flushes;
        if (!state.Bounds(address, size) || address != state.Base() + kFunctionRva || size != kFunctionSize) {
            ++state.invalidAccesses;
            *error = ERROR_INVALID_ADDRESS;
            return false;
        }
        *error = Fails(state.flushFailures, state.flushes) ? ERROR_WRITE_FAULT : ERROR_SUCCESS;
        return *error == ERROR_SUCCESS;
    }
    static FixReason Identity(void* context, DWORD* error) noexcept {
        auto& state = *static_cast<SyntheticImage*>(context);
        ++state.identities;
        if (state.advanceStageOnIdentity) state.Put(state.startup.stateRva, DWORD{2});
        const bool fail = state.identities == state.failIdentityAt;
        *error = fail ? ERROR_FILE_INVALID : ERROR_SUCCESS;
        return fail ? FixReason::HostIdentityChanged : FixReason::None;
    }
    ReconOps Ops() { return {{this, Query, Read}, this, Protect, Write, Flush, Identity}; }
};

void CheckNoMutation(const SyntheticImage& image, const ReconResult& result, FixReason reason) {
    RS2_CHECK(result.outcome == ReconOutcome::Disabled && result.reason == reason);
    RS2_CHECK(image.protects == 0 && image.writes == 0 && image.flushes == 0);
    RS2_CHECK(image.Original() && image.protections[2] == PAGE_EXECUTE_READ);
    RS2_CHECK(image.invalidAccesses == 0);
}
void TestSuccess() {
    for (ReconMode mode : {ReconMode::Passive, ReconMode::Active}) {
        for (DWORD writable : {DWORD{PAGE_EXECUTE_READWRITE}, DWORD{PAGE_EXECUTE_WRITECOPY}}) {
            SyntheticImage image;
            image.temporaryProtection = writable;
            const auto before = image.bytes;
            RS2_CHECK(CheckStartupOpportunity(image.context, image.startup, image.Ops().memory) == StartupGateResult::Ready);
            const ReconResult result = image.Run(mode);
            RS2_CHECK(result.qualified && result.reason == FixReason::None && result.error == ERROR_SUCCESS);
            RS2_CHECK(image.protections[2] == PAGE_EXECUTE_READ && image.invalidAccesses == 0);
            RS2_CHECK(image.identities != 0 && image.constantReads != 0 && image.functionReads != 0);
            if (mode == ReconMode::Passive) {
                RS2_CHECK(result.outcome == ReconOutcome::Passive && image.bytes == before);
                RS2_CHECK(image.protects == 0 && image.writes == 0 && image.flushes == 0);
            } else {
                RS2_CHECK(result.outcome == ReconOutcome::Active && image.Corrected());
                RS2_CHECK(image.protects == 2 && image.writes == 1 && image.flushes == 1);
                RS2_CHECK(image.writtenValues[0] == image.profile.newDisplacement);
                RS2_CHECK(image.requestedProtections[0] == PAGE_EXECUTE_READWRITE &&
                    image.requestedProtections[1] == PAGE_EXECUTE_READ);
                bool outsideOperandUnchanged = true;
                for (std::size_t offset = 0; offset < before.size(); ++offset)
                    if (offset < image.profile.operandRva || offset >= image.profile.operandRva + 4)
                        outsideOperandUnchanged = outsideOperandUnchanged && before[offset] == image.bytes[offset];
                RS2_CHECK(outsideOperandUnchanged);
            }
        }
    }
}
void TestPreWriteRejections() {
    for (ReconMode mode : {ReconMode::Passive, ReconMode::Active}) {
        for (unsigned scenario = 0; scenario < 17; ++scenario) {
            SyntheticImage image;
            FixReason expected = FixReason::StartupRejected;
            switch (scenario) {
            case 0: image.context.size = 0; break;
            case 1: image.context.staticLoad = 0; break;
            case 2: ++image.context.currentThreadId; break;
            case 3: ++image.context.triggerReturnAddress; break;
            case 4: image.Put(image.startup.stateRva, DWORD{2}); break;
            case 5: image.bytes[image.span.rva] ^= 1; break;
            case 6: image.Put(image.startup.initializerSlotRva, image.Base() + image.startup.initializerRva + 1); break;
            case 7: image.profile.correctedDigest[0] ^= 1; expected = FixReason::PreparedDigestMismatch; break;
            case 8: image.profile.originalDigest[0] ^= 1; expected = FixReason::FunctionMismatch; break;
            case 9: image.bytes[kConstantRva] ^= 1; expected = FixReason::ConstantMismatch; break;
            case 10: image.failFunctionReadAt = 1; expected = FixReason::CodeUnreadable; break;
            case 11: image.failConstantRead = true; expected = FixReason::ConstantMismatch; break;
            case 12: image.failIdentityAt = 1; expected = FixReason::HostIdentityChanged; break;
            case 13: image.advanceStageOnIdentity = true; break;
            case 14: image.context.reserved = 1; break;
            case 15: image.context.genuineExportsMask = kGenuineInitializePresent; break;
            case 16: image.context.bootstrapModule = image.context.hostModule; break;
            }
            CheckNoMutation(image, image.Run(mode), expected);
        }
        SyntheticImage wrongHost;
        Sha256Digest digest = wrongHost.profile.hostDigest;
        digest[0] ^= 1;
        CheckNoMutation(wrongHost, RunReconFix(wrongHost.context, wrongHost.startup,
            wrongHost.profile, mode, digest, wrongHost.Ops()), FixReason::UnsupportedHost);
        SyntheticImage alreadyPatched;
        std::memcpy(alreadyPatched.bytes.data() + kFunctionRva, alreadyPatched.corrected.data(), kFunctionSize);
        const auto before = alreadyPatched.bytes;
        const auto result = alreadyPatched.Run(mode);
        RS2_CHECK(result.outcome == ReconOutcome::Disabled && result.reason == FixReason::FunctionMismatch);
        RS2_CHECK(alreadyPatched.bytes == before && alreadyPatched.protects == 0 && alreadyPatched.writes == 0);
        SyntheticImage otherByte;
        otherByte.bytes[kFunctionRva + kFunctionSize - 2] ^= 1;
        const auto changed = otherByte.bytes;
        const auto mismatch = otherByte.Run(mode);
        RS2_CHECK(mismatch.reason == FixReason::FunctionMismatch && mismatch.outcome == ReconOutcome::Disabled);
        RS2_CHECK(otherByte.bytes == changed && otherByte.protects == 0 && otherByte.writes == 0);
    }
}
void TestHeadersSectionsAndRegions() {
    for (unsigned scenario = 0; scenario < 15; ++scenario) {
        SyntheticImage image;
        bool startupRejected = true;
        auto nt = image.Get<IMAGE_NT_HEADERS64>(kNtRva);
        auto ro = image.Get<IMAGE_SECTION_HEADER>(kSectionRva + sizeof(IMAGE_SECTION_HEADER));
        switch (scenario) {
        case 0: nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386; image.Put(kNtRva, nt); break;
        case 1: nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {0x3000, 40}; image.Put(kNtRva, nt); break;
        case 2: ++nt.OptionalHeader.CheckSum; image.Put(kNtRva, nt); break;
        case 3: nt.OptionalHeader.SizeOfImage += 0x1000; image.Put(kNtRva, nt); break;
        case 4: image.wrongAllocation = true; break;
        case 5: image.wrongRegionType = true; break;
        case 6: image.uncommitted = true; break;
        case 7: image.badRegionExtent = true; break;
        case 8: image.failQuery = true; break;
        case 9: ro.Characteristics |= IMAGE_SCN_MEM_WRITE; image.Put(kSectionRva + sizeof(ro), ro); break;
        case 10: image.protections[2] = PAGE_EXECUTE_READWRITE; startupRejected = false; break;
        case 11: image.protections[3] = PAGE_READWRITE; break;
        case 12: {
            auto code = image.Get<IMAGE_SECTION_HEADER>(kSectionRva);
            code.Misc.VirtualSize = 0x1000; // startup is valid; recon lies outside the code section.
            image.Put(kSectionRva, code);
            startupRejected = false;
            break;
        }
        case 13: image.protections[2] = PAGE_EXECUTE_READ | PAGE_GUARD; startupRejected = false; break;
        case 14:
            ro.Characteristics |= IMAGE_SCN_MEM_DISCARDABLE;
            image.Put(kSectionRva + sizeof(ro), ro);
            startupRejected = false;
            break;
        }
        const auto before = image.bytes;
        for (ReconMode mode : {ReconMode::Passive, ReconMode::Active}) {
            const auto result = image.Run(mode);
            RS2_CHECK(result.outcome == ReconOutcome::Disabled);
            RS2_CHECK(result.reason == (startupRejected ? FixReason::StartupRejected : FixReason::ProtectionMismatch));
            RS2_CHECK(image.bytes == before && image.protects == 0 && image.writes == 0 && image.flushes == 0);
            RS2_CHECK(image.invalidAccesses == 0);
        }
    }
    SyntheticImage badProfile;
    badProfile.profile.functionSize = static_cast<std::uint32_t>(kReconFunctionCapacity + 1);
    CheckNoMutation(badProfile, badProfile.Run(), FixReason::InvalidContext);
    SyntheticImage wrongDisplacement;
    ++wrongDisplacement.profile.newDisplacement;
    CheckNoMutation(wrongDisplacement, wrongDisplacement.Run(), FixReason::InvalidContext);
}
void TestTransactionFailures() {
    for (unsigned scenario = 0; scenario < 9; ++scenario) {
        SyntheticImage image;
        FixReason expected = FixReason::ReadbackFailed;
        switch (scenario) {
        case 0: image.protectFailures = 1u; expected = FixReason::ProtectFailed; break;
        case 1: image.writeFailures = 1u; expected = FixReason::WriteFailed; break;
        case 2: image.writeFailures = 1u; image.mutateBeforeWriteFailure = true; expected = FixReason::WriteFailed; break;
        case 3: image.failReadAfterWrite = true; break;
        case 4: image.corruptReadAfterWrite = true; break;
        case 5: image.protectFailures = 2u; expected = FixReason::RestoreFailed; break;
        case 6: image.wrongRestoredProtection = true; expected = FixReason::RestoreFailed; break;
        case 7: image.flushFailures = 1u; expected = FixReason::FlushFailed; break;
        case 8: image.advanceStageOnProtect = true; expected = FixReason::StartupRejected; break;
        }
        const auto result = image.Run();
        const bool noWrite = scenario == 0 || scenario == 8;
        RS2_CHECK(result.outcome == (noWrite ? ReconOutcome::Disabled : ReconOutcome::RolledBack));
        RS2_CHECK(result.reason == expected);
        if (scenario == 0 || scenario == 5) RS2_CHECK(result.error == ERROR_ACCESS_DENIED);
        if (scenario == 1 || scenario == 2 || scenario == 7) RS2_CHECK(result.error == ERROR_WRITE_FAULT);
        if (scenario == 3) RS2_CHECK(result.error == ERROR_PARTIAL_COPY);
        RS2_CHECK(image.Original() && image.protections[2] == PAGE_EXECUTE_READ);
        RS2_CHECK(image.invalidAccesses == 0 && image.protects <= 4 && image.writes <= 2 && image.flushes <= 2);
        if (!noWrite) RS2_CHECK(image.writtenValues[image.writes - 1] == image.profile.oldDisplacement);
        else RS2_CHECK(image.writes == 0 && image.flushes == 0);
    }
    SyntheticImage changedOld;
    changedOld.wrongOldProtection = true;
    const auto result = changedOld.Run();
    RS2_CHECK(result.reason == FixReason::ProtectionMismatch && result.outcome == ReconOutcome::Disabled);
    RS2_CHECK(changedOld.Original() && changedOld.protections[2] == PAGE_EXECUTE_READ);
    RS2_CHECK(changedOld.writes == 0 && changedOld.flushes == 0);
}
void TestNoWriteRecovery() {
    SyntheticImage noOp;
    noOp.protectNoOp = true;
    const auto noOpResult = noOp.Run();
    RS2_CHECK(noOpResult.outcome == ReconOutcome::Disabled);
    RS2_CHECK(noOpResult.reason == FixReason::ProtectionMismatch);
    RS2_CHECK(noOp.Original() && noOp.protections[2] == PAGE_EXECUTE_READ);
    RS2_CHECK(noOp.protects == 1 && noOp.writes == 0 && noOp.flushes == 0);

    for (unsigned transientReads = 1; transientReads <= 2; ++transientReads) {
        SyntheticImage refused;
        refused.protectFailures = 1u;
        refused.failFunctionReadsRemainingAfterProtect = transientReads;
        const auto result = refused.Run();
        RS2_CHECK(result.outcome == ReconOutcome::Disabled && result.reason == FixReason::ProtectFailed);
        RS2_CHECK(refused.Original() && refused.protections[2] == PAGE_EXECUTE_READ);
        RS2_CHECK(refused.protects == 1 && refused.writes == 0 && refused.flushes == 0);
    }
    SyntheticImage cannotRestore;
    cannotRestore.advanceStageOnProtect = true;
    cannotRestore.protectFailures = 2u;
    const auto unsafe = cannotRestore.Run();
    RS2_CHECK(unsafe.outcome == ReconOutcome::Fatal && unsafe.reason == FixReason::RollbackFailed);
    RS2_CHECK(cannotRestore.Original() && cannotRestore.protections[2] == PAGE_EXECUTE_READWRITE);
    RS2_CHECK(cannotRestore.writes == 0 && cannotRestore.flushes == 0);
}
void TestFatalRollback() {
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        SyntheticImage image;
        image.flushFailures = 1u;
        switch (scenario) {
        case 0: image.protectFailures = 4u; break; // rollback cannot make page writable
        case 1: image.writeFailures = 2u; break; // rollback cannot restore operand
        case 2: image.protectFailures = 8u; break; // rollback cannot restore RX
        case 3: image.flushFailures = 3u; break; // rollback cache flush also fails
        case 4: image.mutateNeighborOnWrite = true; image.flushFailures = 0; break;
        }
        const auto result = image.Run();
        RS2_CHECK(result.outcome == ReconOutcome::Fatal && result.reason == FixReason::RollbackFailed);
        RS2_CHECK(image.protects <= 4 && image.writes <= 2 && image.flushes <= 2);
        RS2_CHECK(image.invalidAccesses == 0);
        if (scenario == 0 || scenario == 1) RS2_CHECK(image.Corrected());
        if (scenario == 2 || scenario == 3) RS2_CHECK(image.Original());
        if (scenario == 2) RS2_CHECK(image.protections[2] != PAGE_EXECUTE_READ);
        if (scenario == 3) RS2_CHECK(image.protections[2] == PAGE_EXECUTE_READ);
        if (scenario == 4) RS2_CHECK(!image.Original() && !image.Corrected());
    }
}
void TestFinalCustodyAndConstantValidation() {
    SyntheticImage lateIdentity;
    lateIdentity.failIdentityAt = 2;
    const auto identityResult = lateIdentity.Run();
    RS2_CHECK(lateIdentity.identities >= 2);
    RS2_CHECK(identityResult.outcome != ReconOutcome::Active);
    RS2_CHECK(identityResult.outcome == ReconOutcome::Fatal || lateIdentity.Original());
    SyntheticImage changedConstant;
    changedConstant.mutateConstantOnWrite = true;
    const auto constantResult = changedConstant.Run();
    RS2_CHECK(changedConstant.constantReads >= 2);
    RS2_CHECK(constantResult.outcome != ReconOutcome::Active);
    RS2_CHECK(constantResult.outcome == ReconOutcome::Fatal || changedConstant.Original());
}
}
void RunReconTests() {
    TestSuccess();
    TestPreWriteRejections();
    TestHeadersSectionsAndRegions();
    TestTransactionFailures();
    TestNoWriteRecovery();
    TestFatalRollback();
    TestFinalCustodyAndConstantValidation();
}
}
