// Disposable SEC_IMAGE mapping of the separately hashed OWN-CODE test EXE.
// This tool never executes mapped bytes or opens a game process.
#include "fixture_profile.h"
#include "companion/host_hash.h"
#include "tool_paths.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <cwchar>

namespace {
bool Observe(const void* address, const void* expectedBase, const char* phase,
             DWORD* protection) noexcept {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory)) return false;
    *protection = memory.Protect;
    std::printf("phase=%s protect=%08lX state=%08lX type=%08lX allocation_base=%p "
        "expected_base=%p allocation_protect=%08lX\n", phase, memory.Protect,
        memory.State, memory.Type, memory.AllocationBase, expectedBase, memory.AllocationProtect);
    return memory.AllocationBase == expectedBase && memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE;
}
bool Equal(const void* address, const std::uint8_t* expected, std::size_t size) noexcept {
    std::array<std::uint8_t, rs2fix::kReconFunctionCapacity> actual{};
    SIZE_T count{};
    return size <= actual.size() && ReadProcessMemory(GetCurrentProcess(), address,
        actual.data(), size, &count) && count == size && !std::memcmp(actual.data(), expected, size);
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"--help") == 0) {
        std::puts("rs2_image_protection_probe --image <absolute own-code probe input>\n"
            "Maps only the exact build-qualified own-code EXE; never executes it or starts VNGame.");
        return 0;
    }
    if (argc != 3 || std::wcscmp(argv[1], L"--image") != 0) return 2;
    std::wstring path;
    std::string error;
    if (!rs2fix::tooling::RequireAbsolutePlainFile(argv[2], &path, &error)) return 3;
    rs2fix::HostHashLease lease;
    const auto host = rs2fix::AcquireHostHash(path.c_str(), &lease);
    if (host.reason != rs2fix::FixReason::None || !host.hash.digestValid ||
        host.hash.digest != rs2fix::kFixtureReconProfile.hostDigest) {
        std::puts("FAIL input is not the exact own-code fixture for this probe");
        return 4;
    }
    std::printf("input_sha256=%s\n", rs2fix::FormatSha256Upper(host.hash.digest).data());
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 5;
    // Bind mapping to this exact validated handle as well, not a path re-open
    // assumption. Neither handle permits external writes or deletion.
    const auto mappedFileHash = rs2fix::HashHandleSha256(file, GetTickCount64() + 10000);
    if (!mappedFileHash.digestValid || mappedFileHash.digest != host.hash.digest) {
        CloseHandle(file);
        return 5;
    }
    const HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!mapping) { CloseHandle(file); return 6; }
    auto* base = static_cast<std::uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!base) { CloseHandle(mapping); CloseHandle(file); return 7; }
    const auto& profile = rs2fix::kFixtureReconProfile;
    auto* function = base + profile.functionRva;
    auto* operand = reinterpret_cast<volatile LONG*>(base + profile.operandRva);
    std::array<std::uint8_t, rs2fix::kReconFunctionCapacity> original{}, corrected{};
    SIZE_T count{};
    DWORD protection{}, previous{}, ignored{};
    bool ok = profile.functionSize <= original.size() && (profile.operandRva & 3) == 0 &&
        Observe(function, base, "initial", &protection) && protection == PAGE_EXECUTE_READ &&
        ReadProcessMemory(GetCurrentProcess(), function, original.data(), profile.functionSize, &count) &&
        count == profile.functionSize;
    rs2fix::Sha256Digest digest{};
    if (ok) ok = rs2fix::HashBytesSha256(original.data(), profile.functionSize, &digest) &&
        digest == profile.originalDigest;
    corrected = original;
    std::memcpy(corrected.data() + profile.operandRva - profile.functionRva,
        &profile.newDisplacement, sizeof(profile.newDisplacement));
    if (ok) ok = rs2fix::HashBytesSha256(corrected.data(), profile.functionSize, &digest) &&
        digest == profile.correctedDigest;
    if (ok) ok = VirtualProtect(const_cast<LONG*>(operand), 4, PAGE_EXECUTE_READWRITE, &previous) != FALSE;
    if (ok) ok = previous == PAGE_EXECUTE_READ && Observe(const_cast<LONG*>(operand), base,
        "after_protect", &protection) &&
        (protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);
    if (ok) {
        InterlockedExchange(operand, static_cast<LONG>(profile.newDisplacement));
        ok = Observe(const_cast<LONG*>(operand), base, "after_write", &protection) &&
            (protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY) &&
            Equal(function, corrected.data(), profile.functionSize);
        InterlockedExchange(operand, static_cast<LONG>(profile.oldDisplacement));
        ok = Equal(function, original.data(), profile.functionSize) && ok;
    }
    if (previous) {
        const bool restored = VirtualProtect(const_cast<LONG*>(operand), 4, previous, &ignored) != FALSE;
        const bool observed = Observe(function, base, "restored", &protection);
        const bool flushed = FlushInstructionCache(GetCurrentProcess(), function, profile.functionSize) != FALSE;
        ok = ok && restored && observed && flushed && protection == PAGE_EXECUTE_READ &&
            Equal(function, original.data(), profile.functionSize);
    }
    DWORD stableError{};
    ok = lease.ValidateStable(&stableError) == rs2fix::FixReason::None && ok;
    const bool unmapped = UnmapViewOfFile(base) != FALSE;
    const bool closedMapping = CloseHandle(mapping) != FALSE;
    const bool closedFile = CloseHandle(file) != FALSE;
    ok = ok && unmapped && closedMapping && closedFile;
    std::puts(ok ? "PASS own SEC_IMAGE mapping only; never executed; original bytes restored" :
        "FAIL own SEC_IMAGE probe; do not proceed to active server test");
    return ok ? 0 : 8;
}
