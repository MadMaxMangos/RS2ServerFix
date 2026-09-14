#include "companion/host_hash.h"
#include "companion/build_identity.h"
#include "test_framework.h"
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace rs2fix::testcases {
namespace {
struct TemporaryFile {
    wchar_t path[MAX_PATH]{};
    TemporaryFile() {
        wchar_t directory[MAX_PATH]{};
        const DWORD length = GetTempPathW(MAX_PATH, directory);
        RS2_CHECK(length > 0 && length < MAX_PATH);
        RS2_CHECK(GetTempFileNameW(directory, L"R2H", 0, path) != 0);
    }
    ~TemporaryFile() { if (path[0]) RS2_CHECK(DeleteFileW(path) != FALSE); }
    void Write(const void* bytes, const DWORD size) {
        const HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        RS2_CHECK(file != INVALID_HANDLE_VALUE);
        if (file == INVALID_HANDLE_VALUE) return;
        DWORD written = 0;
        RS2_CHECK(WriteFile(file, bytes, size, &written, nullptr) != FALSE);
        RS2_CHECK(written == size);
        RS2_CHECK(CloseHandle(file) != FALSE);
    }
};
Sha256Digest Digest(const char* text) {
    Sha256Digest value{};
    RS2_CHECK(ParseSha256Upper(text, &value));
    return value;
}
struct HashFaults {
    unsigned metadataCalls{};
    unsigned reads{};
    unsigned clocks{};
    unsigned closes{};
    unsigned opens{};
    unsigned changeAt{};
    unsigned failMetadataAt{};
    bool sizeChange{};
    bool expireBeforeRead{};
    bool expireAfterRead{};
    bool failRead{};
    bool zeroRead{};
};
ULONGLONG FaultTicks(void* context) noexcept {
    auto& state = *static_cast<HashFaults*>(context);
    ++state.clocks;
    if ((state.expireBeforeRead && state.clocks > 1) ||
        (state.expireAfterRead && state.reads > 0)) return 10100;
    return 100;
}
HANDLE FaultOpen(void* context, const wchar_t* path, DWORD* error) noexcept {
    ++static_cast<HashFaults*>(context)->opens;
    return ProductionHostHashOps().open(nullptr, path, error);
}
bool FaultMetadata(void* context, HANDLE file, BY_HANDLE_FILE_INFORMATION* info, DWORD* error) noexcept {
    auto& state = *static_cast<HashFaults*>(context);
    ++state.metadataCalls;
    if (state.metadataCalls == state.failMetadataAt) { *error = ERROR_ACCESS_DENIED; return false; }
    if (!ProductionHostHashOps().metadata(nullptr, file, info, error)) return false;
    if (state.metadataCalls == state.changeAt) {
        if (state.sizeChange) ++info->nFileSizeLow;
        else ++info->nFileIndexLow;
    }
    return true;
}
bool FaultRead(void* context, HANDLE file, void* bytes, DWORD size, DWORD* read, DWORD* error) noexcept {
    auto& state = *static_cast<HashFaults*>(context);
    ++state.reads;
    if (state.failRead) { *error = ERROR_READ_FAULT; return false; }
    if (state.zeroRead) { *read = 0; *error = ERROR_SUCCESS; return true; }
    return ProductionHostHashOps().read(nullptr, file, bytes, size, read, error);
}
void FaultClose(void* context, HANDLE file) noexcept {
    ++static_cast<HashFaults*>(context)->closes;
    ProductionHostHashOps().close(nullptr, file);
}
HostHashOps FaultOps(HashFaults& state) {
    return {&state, FaultTicks, FaultOpen, FaultMetadata, FaultRead, FaultClose};
}
void TestHashesAndCustody() {
    Sha256Digest digest{};
    RS2_CHECK(HashBytesSha256("abc", 3, &digest));
    RS2_CHECK(digest == Digest("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
    RS2_CHECK(HashBytesSha256(nullptr, 0, &digest));
    RS2_CHECK(digest == Digest("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"));
    RS2_CHECK(!HashBytesSha256(nullptr, 3, &digest));
    RS2_CHECK(digest == Sha256Digest{});
    RS2_CHECK(!HashBytesSha256("abc", 3, nullptr));
    TemporaryFile file;
    std::vector<unsigned char> bytes(150123);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<unsigned char>(i % 251);
    file.Write(bytes.data(), static_cast<DWORD>(bytes.size()));
    RS2_CHECK(HashBytesSha256(bytes.data(), bytes.size(), &digest));
    const FileHashResult offline = HashFileSha256(file.path, GetTickCount64() + 10000);
    RS2_CHECK(offline.digestValid && offline.digest == digest && offline.fileSize == bytes.size());
    RS2_CHECK(HashFileSha256(file.path, 0).timedOut);
    HashFaults state{};
    {
        HostHashLease lease;
        const HostHashResult result = AcquireHostHash(file.path, &lease, FaultOps(state));
        RS2_CHECK(result.reason == FixReason::None && result.hash.digestValid);
        RS2_CHECK(result.hash.digest == digest && result.hash.fileSize == bytes.size());
        RS2_CHECK(lease.valid() && state.metadataCalls == 2 && state.opens == 1);
        const HANDLE writer = CreateFileW(file.path, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        RS2_CHECK(writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION);
        if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
        RS2_CHECK(!DeleteFileW(file.path) && GetLastError() == ERROR_SHARING_VIOLATION);
        HostHashLease moved(std::move(lease));
        RS2_CHECK(!lease.valid() && moved.valid() && state.closes == 0);
        RS2_CHECK(moved.ValidateStable() == FixReason::None);
        HostHashLease assigned;
        assigned = std::move(moved);
        RS2_CHECK(assigned.valid() && !moved.valid() && state.closes == 0);
    }
    RS2_CHECK(state.opens == 1 && state.closes == 1);
    const FileHashResult after = HashFileSha256(file.path, GetTickCount64() + 10000);
    RS2_CHECK(after.digestValid && after.digest == digest);
}
void TestSharingConflicts() {
    TemporaryFile file;
    file.Write("abc", 3);
    for (const DWORD access : {DWORD{DELETE}, DWORD{GENERIC_WRITE}, DWORD{DELETE | GENERIC_WRITE}}) {
        const HANDLE held = CreateFileW(file.path, access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        RS2_CHECK(held != INVALID_HANDLE_VALUE);
        if (held == INVALID_HANDLE_VALUE) continue;
        HostHashLease lease;
        const HostHashResult result = AcquireHostHash(file.path, &lease);
        RS2_CHECK(result.reason == FixReason::HostOpenSharingViolation);
        RS2_CHECK(!result.hash.digestValid && !lease.valid());
        RS2_CHECK(result.hash.error == ERROR_SHARING_VIOLATION);
        RS2_CHECK(CloseHandle(held) != FALSE);
    }
    HostHashLease missing;
    const std::wstring nonexistent = std::wstring(file.path) + L".missing";
    const HostHashResult result = AcquireHostHash(nonexistent.c_str(), &missing);
    RS2_CHECK(result.reason == FixReason::HostOpenFailed && !result.hash.digestValid);
}
void TestHashFailures() {
    TemporaryFile file;
    file.Write("abc", 3);
    for (unsigned scenario = 0; scenario < 8; ++scenario) {
        HashFaults state{};
        FixReason expected = FixReason::HostIdentityChanged;
        switch (scenario) {
        case 0: state.expireBeforeRead = true; expected = FixReason::HostHashBudgetExceeded; break;
        case 1: state.expireAfterRead = true; expected = FixReason::HostHashBudgetExceeded; break;
        case 2: state.changeAt = 2; break;
        case 3: state.changeAt = 2; state.sizeChange = true; break;
        case 4: state.failMetadataAt = 1; break;
        case 5: state.failMetadataAt = 2; break;
        case 6: state.failRead = true; expected = FixReason::HostHashFailed; break;
        case 7: state.zeroRead = true; break;
        }
        {
            HostHashLease lease;
            const HostHashResult result = AcquireHostHash(file.path, &lease, FaultOps(state));
            RS2_CHECK(result.reason == expected && !result.hash.digestValid);
            RS2_CHECK(result.hash.digest == Sha256Digest{});
            RS2_CHECK(lease.valid() && state.closes == 0 && state.opens == 1);
            if (scenario == 0) RS2_CHECK(state.reads == 0);
            if (scenario == 1) RS2_CHECK(state.reads == 1);
        }
        RS2_CHECK(state.closes == 1);
    }
    for (bool metadataFailure : {false, true}) {
        HashFaults state{};
        HostHashLease lease;
        RS2_CHECK(AcquireHostHash(file.path, &lease, FaultOps(state)).reason == FixReason::None);
        if (metadataFailure) state.failMetadataAt = 3;
        else state.changeAt = 3;
        DWORD error = 0;
        RS2_CHECK(lease.ValidateStable(&error) == FixReason::HostIdentityChanged);
        RS2_CHECK(error == static_cast<DWORD>(metadataFailure ? ERROR_ACCESS_DENIED : ERROR_FILE_INVALID));
        RS2_CHECK(state.opens == 1 && state.closes == 0);
    }
}
void TestRunningOwnExecutable() {
    wchar_t ownPath[32768]{};
    const DWORD size = GetModuleFileNameW(nullptr, ownPath, static_cast<DWORD>(std::size(ownPath)));
    RS2_CHECK(size > 0 && size < std::size(ownPath));
    HostHashLease lease;
    const HostHashResult result = AcquireHostHash(ownPath, &lease);
    RS2_CHECK(result.reason == FixReason::None && result.hash.digestValid);
    RS2_CHECK(lease.ValidateStable() == FixReason::None);
}
#if defined(RS2_PR1_BASELINE_PATH) && defined(RS2_CURRENT_STOCK_PATH)
void TestImmutableStockInputs() {
    struct Input { const wchar_t* path; const char* digest; BuildIdentity identity; };
    const Input inputs[]{
        {RS2_PR1_BASELINE_PATH, "5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF", BuildIdentity::Pr1StockBaseline},
        {RS2_CURRENT_STOCK_PATH, "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3", BuildIdentity::CurrentStock}};
    for (const auto& input : inputs) {
        const auto before = HashFileSha256(input.path, GetTickCount64() + 60000);
        RS2_CHECK(before.digestValid && before.digest == Digest(input.digest));
        {
            HostHashLease lease;
            const auto held = AcquireHostHash(input.path, &lease);
            RS2_CHECK(held.reason == FixReason::None && held.hash.digest == before.digest);
            RS2_CHECK(ClassifyBuild(held.hash.digest, held.hash.digestValid) == input.identity);
            RS2_CHECK(lease.ValidateStable() == FixReason::None);
        }
        const auto after = HashFileSha256(input.path, GetTickCount64() + 60000);
        RS2_CHECK(after.digestValid && after.digest == before.digest && after.fileSize == before.fileSize);
    }
}
#endif
}
void RunHostHashTests() {
    TestHashesAndCustody();
    TestSharingConflicts();
    TestHashFailures();
    TestRunningOwnExecutable();
#if defined(RS2_PR1_BASELINE_PATH) && defined(RS2_CURRENT_STOCK_PATH)
    TestImmutableStockInputs();
#endif
}
}
