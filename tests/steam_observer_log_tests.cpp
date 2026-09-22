#include "companion/steam_observer_log.h"
#include "test_framework.h"
#include <aclapi.h>
#include <winioctl.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <thread>
#include <vector>

namespace {
using namespace rs2fix::observer;
volatile LONG g_directoryNumber{};
struct Fixture {
    DispatchState dispatch{};
    Writer* writer{};
    wchar_t root[kWriterPathCapacity]{};
    Reason reason{};
    DWORD error{};
    explicit Fixture(const WriterTestOptions& options = {}) {
        wchar_t temporary[kWriterPathCapacity]{};
        RS2_CHECK(GetTempPathW(_countof(temporary), temporary) != 0);
        const LONG number = InterlockedIncrement(&g_directoryNumber);
        const int count = _snwprintf_s(root, _countof(root), _TRUNCATE,
            L"%sRS2SteamObserve-Writer-Test-%lu-%llu-%ld", temporary,
            GetCurrentProcessId(), GetTickCount64(), number);
        RS2_CHECK(count > 0 && CreateDirectoryW(root, nullptr));
        writer = PrepareWriterForTest(root, &dispatch, options, &reason, &error);
        RS2_CHECK(writer != nullptr && reason == Reason::None && error == ERROR_SUCCESS);
        if (writer) InitializeDispatch(dispatch, {}, GetWriterSink(writer));
    }
    void Arm() {
        InterlockedExchange(&dispatch.gate, static_cast<LONG>(Gate::Armed));
        ArmWriter(writer);
    }
    void Send(const Event& event) { dispatch.sink.publish(dispatch.sink.context, event); }
    std::wstring Events() const { return std::wstring(GetWriterDirectory(writer)) + L"\\events.jsonl"; }
    std::wstring RunId() const {
        const std::wstring path(GetWriterDirectory(writer));
        return path.substr(path.size() - 32);
    }
    std::wstring Key() const { return std::wstring(root) + L"\\RS2SteamObserveKeys\\" + RunId() + L".key"; }
    ~Fixture() { FinishWriterForTest(writer); }
};

std::string ReadFileText(const std::wstring& path) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    RS2_CHECK(GetFileSizeEx(file, &size) && size.QuadPart >= 0 && size.QuadPart <= 32 * 1024 * 1024);
    std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD written = 0;
    RS2_CHECK(result.empty() || (ReadFile(file, result.data(), static_cast<DWORD>(result.size()),
        &written, nullptr) && written == result.size()));
    CloseHandle(file);
    return result;
}
bool HasProtectedPrivateAcl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL acl = nullptr;
    PSID owner = nullptr;
    const DWORD error = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) return false;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision{};
    bool ok = owner && acl && acl->AceCount == 3 &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) && (control & SE_DACL_PROTECTED);
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void* raw = nullptr;
        ok = GetAce(acl, i, &raw) != FALSE;
        if (!ok) break;
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        ok = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Mask == FILE_ALL_ACCESS &&
            !(ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE));
        if (!ok) break;
        const PSID sid = const_cast<DWORD*>(&ace->SidStart);
        ok = EqualSid(sid, owner) || IsWellKnownSid(sid, WinLocalSystemSid) ||
            IsWellKnownSid(sid, WinBuiltinAdministratorsSid);
    }
    LocalFree(descriptor);
    return ok;
}
Event Sample() {
    Event event{};
    event.method = Method::BUpdateUserData;
    event.phase = Phase::Complete;
    event.flags = HasSteamId;
    event.steamId = 76561197960265729ULL;
    event.callId = 11;
    event.argument = 123;
    event.result = 1;
    return event;
}
void StartupPrivacyAndSharing() {
    Fixture fixture;
    if (!fixture.writer) return;
    RS2_CHECK(ReadFileText(fixture.Events()).empty());
    // A not-yet-Armed worker must not touch or report partially initialized
    // DispatchState; this manual pump models the inactive production worker.
    PumpWriterForTest(fixture.writer);
    RS2_CHECK(ReadFileText(fixture.Events()).empty());
    RS2_CHECK(HasProtectedPrivateAcl(fixture.Key()));
    RS2_CHECK(HasProtectedPrivateAcl(std::wstring(fixture.root) + L"\\RS2SteamObserveKeys"));
    const std::string key = ReadFileText(fixture.Key());
    RS2_CHECK(key.size() == 32);
    fixture.Arm();
    fixture.Send(Sample());
    PumpWriterForTest(fixture.writer);
    const auto snapshot = SnapshotWriter(fixture.writer);
    RS2_CHECK(snapshot.status == WriterStatus::Recording && snapshot.eventsWritten == 1);
    const std::string log = ReadFileText(fixture.Events());
    RS2_CHECK(log.find("\"type\":\"startup\"") != std::string::npos);
    RS2_CHECK(log.find("\"armed\":true") != std::string::npos);
    RS2_CHECK(log.find("\"process_start_filetime\":") != std::string::npos);
    RS2_CHECK(log.find("\"method\":27") != std::string::npos);
    RS2_CHECK(log.find("76561197960265729") == std::string::npos);
    RS2_CHECK(log.find("RS2SteamObserveKeys") == std::string::npos);
    RS2_CHECK(log.find(".key") == std::string::npos && log.find("steamId") == std::string::npos);
    RS2_CHECK(log.find(key) == std::string::npos);
    char expectedToken[33]{};
    RS2_CHECK(key.size() == 32 && HmacSteamIdForTest(
        reinterpret_cast<const unsigned char*>(key.data()), Sample().steamId, expectedToken));
    RS2_CHECK(log.find(std::string("\"steam_token\":\"") + expectedToken + "\"") != std::string::npos);
    const HANDLE writable = CreateFileW(fixture.Events().c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    RS2_CHECK(writable == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION);
    if (writable != INVALID_HANDLE_VALUE) CloseHandle(writable);
}
void KnownHmac() {
    unsigned char key[32]{};
    for (unsigned i = 0; i < 32; ++i) key[i] = static_cast<unsigned char>(i);
    char token[33]{};
    RS2_CHECK(HmacSteamIdForTest(key, 0x0102030405060708ULL, token));
    // Independent HMAC-SHA256 over bytes08 07 06 05 04 03 02 01, key00..1f.
    RS2_CHECK(std::strcmp(token, "2c5da9bdc91003712d1b67b06f18e790") == 0);
}
void QueueBoundsAndLoss() {
    Fixture fixture;
    if (!fixture.writer) return;
    fixture.Arm();
    LockWriterQueueForTest(fixture.writer);
    std::thread contender([&fixture] { fixture.Send(Sample()); });
    contender.join();
    UnlockWriterQueueForTest(fixture.writer);
    RS2_CHECK(SnapshotWriter(fixture.writer).droppedContention == 1);
    for (std::size_t i = 0; i < kQueueCapacity + 3; ++i) fixture.Send(Sample());
    auto snapshot = SnapshotWriter(fixture.writer);
    RS2_CHECK(snapshot.queueDepth == kQueueCapacity && snapshot.droppedFull == 3);
    PumpWriterForTest(fixture.writer);
    snapshot = SnapshotWriter(fixture.writer);
    RS2_CHECK(snapshot.eventsWritten == 4 * 256 && snapshot.queueDepth == kQueueCapacity - 4 * 256);
    for (unsigned i = 0; i < 3; ++i) PumpWriterForTest(fixture.writer);
    snapshot = SnapshotWriter(fixture.writer);
    RS2_CHECK(snapshot.queueDepth == 0 && snapshot.eventsWritten == kQueueCapacity);
}
struct Fault {
    enum class Kind { None, Partial, Disk, BadCount } kind{};
    unsigned calls{};
    unsigned failCall{2};
    unsigned flushes{};
};
bool FaultWrite(void* context, HANDLE file, const void* bytes, DWORD size,
    DWORD* written, DWORD* error) noexcept {
    auto& fault = *static_cast<Fault*>(context);
    ++fault.calls;
    if (fault.calls == fault.failCall && fault.kind != Fault::Kind::None) {
        if (fault.kind == Fault::Kind::Disk) { *written = 0; *error = ERROR_DISK_FULL; return false; }
        if (fault.kind == Fault::Kind::BadCount) { *written = size + 1; *error = 0; return true; }
        const DWORD partial = size > 8 ? 8 : 1;
        const bool ok = WriteFile(file, bytes, partial, written, nullptr) != FALSE;
        *error = ok ? ERROR_SUCCESS : GetLastError();
        return ok;
    }
    const bool ok = WriteFile(file, bytes, size, written, nullptr) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
bool CountFlush(void* context, HANDLE file, DWORD* error) noexcept {
    auto& fault = *static_cast<Fault*>(context);
    ++fault.flushes;
    const bool ok = FlushFileBuffers(file) != FALSE;
    *error = ok ? 0 : GetLastError();
    return ok;
}
void FailureAndCap() {
    for (const auto kind : {Fault::Kind::Partial, Fault::Kind::Disk, Fault::Kind::BadCount}) {
        Fault fault{}; fault.kind = kind;
        Fixture fixture({0, &fault, FaultWrite, CountFlush});
        if (!fixture.writer) continue;
        fixture.Arm(); fixture.Send(Sample()); fixture.Send(Sample());
        PumpWriterForTest(fixture.writer);
        const auto failed = SnapshotWriter(fixture.writer);
        RS2_CHECK(failed.status == WriterStatus::Failed && failed.eventsWritten == 0 && failed.abandoned == 2);
        const auto before = ReadFileText(fixture.Events());
        const auto writes = fault.calls;
        fixture.Send(Sample()); PumpWriterForTest(fixture.writer);
        RS2_CHECK(fault.calls == writes && SnapshotWriter(fixture.writer).abandoned == 3);
        RS2_CHECK(ReadFileText(fixture.Events()) == before);
        if (kind == Fault::Kind::Partial) {
            RS2_CHECK(!before.empty() && before.back() != '\n');
            RS2_CHECK(before.find("\"type\":\"footer\"") == std::string::npos);
        }
        if (kind == Fault::Kind::Disk) {
            RS2_CHECK(failed.error == ERROR_DISK_FULL);
            RS2_CHECK(before.find("\"status\":\"failed\"") != std::string::npos);
        }
    }
    Fixture limited({16 * 1024, nullptr, nullptr, nullptr});
    if (!limited.writer) return;
    limited.Arm();
    for (unsigned i = 0; i < 128; ++i) limited.Send(Sample());
    PumpWriterForTest(limited.writer);
    const auto capped = SnapshotWriter(limited.writer);
    RS2_CHECK(capped.status == WriterStatus::Truncated && capped.bytesWritten <= 16 * 1024);
    const auto text = ReadFileText(limited.Events());
    RS2_CHECK(text.size() == capped.bytesWritten && text.back() == '\n');
    RS2_CHECK(text.find("\"type\":\"footer\"") != std::string::npos);
    RS2_CHECK(text.find("\"status\":\"truncated\"") != std::string::npos);
    RS2_CHECK(capped.abandoned + capped.eventsWritten == 128);
}
void ExtremeSerializationAndFlushCadence() {
    Fault fault{};
    Fixture fixture({0, &fault, FaultWrite, CountFlush});
    if (!fixture.writer) return;
    fixture.Arm();
    Event extreme = Sample();
    extreme.callId = UINT64_MAX; extreme.entryQpc = INT64_MIN; extreme.qpc = INT64_MAX;
    extreme.entryLifecycle = extreme.lifecycle = UINT64_MAX;
    extreme.argument = INT64_MIN; extreme.result = INT64_MAX;
    extreme.threadId = extreme.callerRva = extreme.bindingId = extreme.bindingSequence = UINT32_MAX;
    extreme.flags = UINT32_MAX;
    fixture.Send(extreme); PumpWriterForTest(fixture.writer);
    for (unsigned i = 0; i < 16; ++i) PumpWriterForTest(fixture.writer);
    RS2_CHECK(fault.flushes == 0);
    const auto text = ReadFileText(fixture.Events());
    const auto begin = text.find("{\"type\":\"event\"");
    const auto end = text.find('\n', begin);
    RS2_CHECK(begin != std::string::npos && end != std::string::npos && end - begin + 1 < 1024);
    // The test waits only for the actual one-second rate limit, not for a game.
    Sleep(1020); PumpWriterForTest(fixture.writer);
    RS2_CHECK(fault.flushes == 1 && SnapshotWriter(fixture.writer).status == WriterStatus::Recording);
    for (unsigned i = 0; i < 16; ++i) PumpWriterForTest(fixture.writer);
    RS2_CHECK(fault.flushes == 1);
    RS2_CHECK(ReadFileText(fixture.Events()).find("\"snapshots_atomic\":false") != std::string::npos);
}
void RejectUnsafeKeyDirectory() {
    Fixture fixture;
    if (!fixture.writer) return;
    const auto keyDirectory = std::wstring(fixture.root) + L"\\RS2SteamObserveKeys";
    FinishWriterForTest(fixture.writer);
    // Deliberately turn only this owned fixture directory into an inherited,
    // unprotected ACL. The next preparation must fail before any key is written.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL originalAcl = nullptr;
    RS2_CHECK(GetNamedSecurityInfoW(const_cast<wchar_t*>(keyDirectory.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &originalAcl, nullptr, &descriptor) == ERROR_SUCCESS);
    const DWORD changed = SetNamedSecurityInfoW(const_cast<wchar_t*>(keyDirectory.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, originalAcl, nullptr);
    if (descriptor) LocalFree(descriptor);
    RS2_CHECK(changed == ERROR_SUCCESS);
    DispatchState state{};
    Reason reason{}; DWORD error{};
    const auto rejected = PrepareWriterForTest(fixture.root, &state, {}, &reason, &error);
    RS2_CHECK(rejected == nullptr && reason == Reason::KeyStoreFailed && error != ERROR_SUCCESS);
    FinishWriterForTest(rejected);
    const std::wstring traversal = std::wstring(fixture.root) + L"\\..";
    const auto ambiguous = PrepareWriterForTest(traversal.c_str(), &state, {}, &reason, &error);
    RS2_CHECK(ambiguous == nullptr && reason == Reason::OutputPathFailed && error == ERROR_BAD_PATHNAME);
    FinishWriterForTest(ambiguous);
}
bool MakeOwnedJunction(const std::wstring& path, const std::wstring& target) {
    struct MountPointBuffer {
        DWORD tag;
        WORD dataLength;
        WORD reserved;
        WORD substituteOffset;
        WORD substituteLength;
        WORD printOffset;
        WORD printLength;
        wchar_t paths[2 * kWriterPathCapacity + 8];
    } buffer{};
    const std::wstring substitute = L"\\??\\" + target;
    buffer.tag = IO_REPARSE_TAG_MOUNT_POINT;
    buffer.substituteLength = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    buffer.printOffset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
    buffer.printLength = static_cast<WORD>(target.size() * sizeof(wchar_t));
    std::memcpy(buffer.paths, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
    std::memcpy(reinterpret_cast<unsigned char*>(buffer.paths) + buffer.printOffset,
        target.c_str(), (target.size() + 1) * sizeof(wchar_t));
    buffer.dataLength = static_cast<WORD>(8 + buffer.printOffset + buffer.printLength + sizeof(wchar_t));
    if (!CreateDirectoryW(path.c_str(), nullptr)) return false;
    const HANDLE directory = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (directory == INVALID_HANDLE_VALUE) return false;
    DWORD returned = 0;
    const bool ok = DeviceIoControl(directory, FSCTL_SET_REPARSE_POINT, &buffer,
        static_cast<DWORD>(8 + buffer.dataLength), nullptr, 0, &returned, nullptr) != FALSE;
    CloseHandle(directory);
    return ok;
}
void ReparseAndCollision() {
    Fixture fixture;
    if (!fixture.writer) return;
    // All targets are new owned test directories. No existing project/server
    // junction is created, modified, followed for deletion, or removed.
    const auto target = std::wstring(fixture.root) + L"\\junction-target";
    const auto redirected = std::wstring(fixture.root) + L"\\junction-input";
    RS2_CHECK(CreateDirectoryW(target.c_str(), nullptr));
    RS2_CHECK(MakeOwnedJunction(redirected, target));
    DispatchState state{};
    Reason reason{}; DWORD error{};
    const auto reparse = PrepareWriterForTest(redirected.c_str(), &state, {}, &reason, &error);
    RS2_CHECK(reparse == nullptr && reason == Reason::OutputPathFailed && error == ERROR_REPARSE_TAG_INVALID);
    FinishWriterForTest(reparse);
    RS2_CHECK(GetFileAttributesW((target + L"\\RS2SteamObserveKeys").c_str()) == INVALID_FILE_ATTRIBUTES);

    // The same cheap obstruction distinguishes the results path from the key
    // store. Both fail closed and preserve the pre-existing owned file bytes.
    for (bool keyStore : {false, true}) {
        const auto collisionRoot = std::wstring(fixture.root) +
            (keyStore ? L"\\key-collision-input" : L"\\results-collision-input");
        RS2_CHECK(CreateDirectoryW(collisionRoot.c_str(), nullptr));
        const auto collisionFile = collisionRoot +
            (keyStore ? L"\\RS2SteamObserveKeys" : L"\\RS2SteamObserve");
        const HANDLE file = CreateFileW(collisionFile.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        RS2_CHECK(file != INVALID_HANDLE_VALUE);
        const char original[] = "owned collision must not be overwritten";
        DWORD written = 0;
        RS2_CHECK(file != INVALID_HANDLE_VALUE && WriteFile(file, original, sizeof(original), &written, nullptr));
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        const auto collision = PrepareWriterForTest(collisionRoot.c_str(), &state, {}, &reason, &error);
        RS2_CHECK(collision == nullptr && error != ERROR_SUCCESS &&
            reason == (keyStore ? Reason::KeyStoreFailed : Reason::OutputPathFailed));
        FinishWriterForTest(collision);
        RS2_CHECK(ReadFileText(collisionFile) == std::string(original, sizeof(original)));
    }
}
} // namespace

void RunSteamObserverLogTests() {
    KnownHmac(); StartupPrivacyAndSharing(); QueueBoundsAndLoss(); FailureAndCap();
    ExtremeSerializationAndFlushCadence(); RejectUnsafeKeyDirectory(); ReparseAndCollision();
}
#if defined(RS2_OBSERVER_LOG_STANDALONE_TEST_MAIN)
int main() {
    RunSteamObserverLogTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}
#endif
