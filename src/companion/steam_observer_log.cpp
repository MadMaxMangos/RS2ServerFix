#include "companion/steam_observer_log.h"
#include "companion/console_status.h"
#if defined(RS2_STEAM_REPORTING)
#include "companion/steam_reporting_log.h"
#include "companion/steam_reporting_profile.h"
#include "shared/selected_reporting_profile.h"
#endif
#include "shared/version.h"
#include <bcrypt.h>
#include <aclapi.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>

namespace rs2fix::observer {
namespace {
constexpr std::size_t kEventBytes = 1024;
constexpr std::size_t kAnchorBytes = 8192;
constexpr std::size_t kMetadataBytes = 128 * 1024;
constexpr std::size_t kBatchCount = 256;
constexpr std::size_t kDirectoryHandles = 256;
constexpr std::uint64_t kFooterReserve = kAnchorBytes;
constexpr Method kObservedMethods[] = {Method::LogOnAnonymous, Method::BLoggedOn,
    Method::SetMaxPlayerCount, Method::SetKeyValue, Method::BUpdateUserData,
    Method::BeginAuthSession, Method::EndAuthSession, Method::EnableHeartbeats,
    Method::SetHeartbeatInterval, Method::Factory, Method::Init, Method::Shutdown};
struct QueuedEvent { Event event; std::uint64_t sequence; };
struct FileOps {
    void* context;
    bool (*write)(void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept;
    bool (*flush)(void*, HANDLE, DWORD*) noexcept;
};
struct PrivateSecurity {
    SECURITY_DESCRIPTOR descriptor;
    alignas(DWORD) unsigned char acl[1024];
    alignas(DWORD) unsigned char user[SECURITY_MAX_SID_SIZE];
    alignas(DWORD) unsigned char system[SECURITY_MAX_SID_SIZE];
    alignas(DWORD) unsigned char administrators[SECURITY_MAX_SID_SIZE];
    SECURITY_ATTRIBUTES attributes;
};
ReporterStorage g_disabledReporter{};
#if defined(RS2_STEAM_REPORTING)
// Reporting must not contend for the legacy observer's already-used slots.
ReporterStorage g_reportReadyReporter{};
ReporterStorage g_reportDisabledReporter{};
#endif

std::uint64_t Read64(volatile LONG64* value) noexcept {
    return static_cast<std::uint64_t>(InterlockedCompareExchange64(value, 0, 0));
}
void Add64(volatile LONG64* value, std::uint64_t delta) noexcept {
    // Resource limits make normal counters far smaller than INT64_MAX. Saturate
    // diagnostic losses rather than letting a pathological run wrap to zero.
    LONG64 before = InterlockedCompareExchange64(value, 0, 0);
    for (;;) {
        const auto room = static_cast<std::uint64_t>(INT64_MAX - before);
        const LONG64 after = delta > room ? INT64_MAX : before + static_cast<LONG64>(delta);
        const LONG64 seen = InterlockedCompareExchange64(value, after, before);
        if (seen == before) return;
        before = seen;
    }
}
bool WriteNative(void*, HANDLE file, const void* data, DWORD length,
    DWORD* written, DWORD* error) noexcept {
    const bool ok = WriteFile(file, data, length, written, nullptr) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
bool FlushNative(void*, HANDLE file, DWORD* error) noexcept {
    const bool ok = FlushFileBuffers(file) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
std::uint64_t FiletimeValue(FILETIME time) noexcept {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
std::uint64_t UtcNow() noexcept {
    FILETIME value{};
    GetSystemTimeAsFileTime(&value);
    return FiletimeValue(value);
}
std::int64_t QpcNow() noexcept {
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}
bool MakePrivateSecurity(PrivateSecurity& security, DWORD& error) noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = GetLastError(); return false;
    }
    // TOKEN_USER plus the largest SID is a fixed bounded query, not an inherited
    // access assumption. The creating account is named explicitly in every ACL.
    alignas(void*) unsigned char tokenBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]{};
    DWORD returned = 0;
    const bool tokenOk = GetTokenInformation(token, TokenUser, tokenBuffer,
        sizeof(tokenBuffer), &returned) != FALSE;
    error = tokenOk ? ERROR_SUCCESS : GetLastError();
    CloseHandle(token);
    if (!tokenOk) return false;
    const auto user = reinterpret_cast<TOKEN_USER*>(tokenBuffer);
    if (!IsValidSid(user->User.Sid) || !CopySid(sizeof(security.user),
        security.user, user->User.Sid)) { error = ERROR_INVALID_SID; return false; }
    DWORD size = sizeof(security.system);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, security.system, &size)) {
        error = GetLastError(); return false;
    }
    size = sizeof(security.administrators);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, security.administrators, &size) ||
        !InitializeAcl(reinterpret_cast<ACL*>(security.acl), sizeof(security.acl), ACL_REVISION)) {
        error = GetLastError(); return false;
    }
    auto acl = reinterpret_cast<ACL*>(security.acl);
    for (PSID sid : {static_cast<PSID>(security.user), static_cast<PSID>(security.system),
                    static_cast<PSID>(security.administrators)}) {
        if (!AddAccessAllowedAceEx(acl, ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, sid)) {
            error = GetLastError(); return false;
        }
    }
    if (!InitializeSecurityDescriptor(&security.descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&security.descriptor, security.user, FALSE) ||
        !SetSecurityDescriptorDacl(&security.descriptor, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(&security.descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
        error = GetLastError(); return false;
    }
    security.attributes = {sizeof(SECURITY_ATTRIBUTES), &security.descriptor, FALSE};
    return true;
}
bool CheckPrivateSecurity(HANDLE file, const PrivateSecurity& expected, DWORD& error) noexcept {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL acl = nullptr;
    error = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &acl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) return false;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool ok = owner && EqualSid(owner, const_cast<unsigned char*>(expected.user)) && acl &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) && acl->AceCount == 3;
    bool found[3]{};
    PSID expectedSids[]{const_cast<unsigned char*>(expected.user),
        const_cast<unsigned char*>(expected.system), const_cast<unsigned char*>(expected.administrators)};
    for (DWORD index = 0; ok && index < acl->AceCount; ++index) {
        void* rawAce = nullptr;
        ok = GetAce(acl, index, &rawAce) != FALSE;
        if (!ok) break;
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
        ok = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Mask == FILE_ALL_ACCESS &&
            !(ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE));
        if (!ok) break;
        bool matched = false;
        // A SYSTEM-run process can deliberately have duplicate SID entries;
        // require a bijection to the three explicit entries, not unique names.
        for (std::size_t candidate = 0; candidate < 3; ++candidate) {
            if (!found[candidate] && EqualSid(const_cast<DWORD*>(&ace->SidStart), expectedSids[candidate])) {
                found[candidate] = true; matched = true; break;
            }
        }
        ok = matched;
    }
    LocalFree(descriptor);
    if (!ok) error = ERROR_INVALID_SECURITY_DESCR;
    return ok;
}
bool Identity(HANDLE file, bool directory, BY_HANDLE_FILE_INFORMATION& identity,
    DWORD& error) noexcept {
    if (!GetFileInformationByHandle(file, &identity)) { error = GetLastError(); return false; }
    if ((identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        static_cast<bool>(identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory ||
        (!directory && identity.nNumberOfLinks != 1)) {
        error = ERROR_REPARSE_TAG_INVALID; return false;
    }
    return true;
}
bool SameIdentity(const BY_HANDLE_FILE_INFORMATION& left,
    const BY_HANDLE_FILE_INFORMATION& right) noexcept {
    return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
        left.nFileIndexHigh == right.nFileIndexHigh && left.nFileIndexLow == right.nFileIndexLow;
}
bool JoinPath(wchar_t* output, const wchar_t* parent, const wchar_t* leaf) noexcept {
    const int count = _snwprintf_s(output, kWriterPathCapacity, _TRUNCATE, L"%s\\%s", parent, leaf);
    return count > 0;
}
void Hex(const unsigned char* bytes, std::size_t length, char* result) noexcept {
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < length; ++i) {
        result[2 * i] = digits[bytes[i] >> 4];
        result[2 * i + 1] = digits[bytes[i] & 15];
    }
    result[2 * length] = '\0';
}
class JsonBuffer {
public:
    JsonBuffer(char* buffer, std::size_t capacity) noexcept : buffer_(buffer), capacity_(capacity) {
        buffer_[0] = '\0';
    }
    bool Append(const char* format, ...) noexcept {
        if (!ok_) return false;
        va_list args;
        va_start(args, format);
        const int written = std::vsnprintf(buffer_ + length_, capacity_ - length_, format, args);
        va_end(args);
        if (written < 0 || static_cast<std::size_t>(written) >= capacity_ - length_) return ok_ = false;
        length_ += static_cast<std::size_t>(written);
        return true;
    }
    bool WideString(const wchar_t* value) noexcept {
        // Each path code point is converted on the worker; argument pointers
        // from Steam never reach this formatter. Reject invalid surrogate pairs.
        if (!Append("\"")) return false;
        for (std::size_t i = 0; value[i] != 0; ++i) {
            const wchar_t first = value[i];
            int units = 1;
            if (first >= 0xd800 && first <= 0xdbff) {
                if (value[i + 1] < 0xdc00 || value[i + 1] > 0xdfff) return ok_ = false;
                units = 2;
            }
            char utf8[5]{};
            const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                value + i, units, utf8, 4, nullptr, nullptr);
            if (!count) return ok_ = false;
            if (units == 2) ++i;
            for (int j = 0; j < count; ++j) {
                const auto byte = static_cast<unsigned char>(utf8[j]);
                if (byte == '"' || byte == '\\') { if (!Append("\\%c", byte)) return false; }
                else if (byte < 32) { if (!Append("\\u%04x", byte)) return false; }
                else if (!Append("%c", byte)) return false;
            }
        }
        return Append("\"");
    }
    bool Good() const noexcept { return ok_; }
    DWORD Size() const noexcept { return static_cast<DWORD>(length_); }
private:
    char* buffer_;
    std::size_t capacity_;
    std::size_t length_{};
    bool ok_{true};
};
} // namespace

struct Writer {
    DispatchState* dispatch;
    SRWLOCK queueLock;
    QueuedEvent queue[kQueueCapacity];
    QueuedEvent batch[kBatchCount];
    std::size_t head;
    std::size_t count;
    std::uint64_t nextQueueSequence;
    volatile LONG queueDepth;
    volatile LONG status;
    volatile LONG error;
    volatile LONG armed;
    volatile LONG stop;
    volatile LONG64 bytesWritten;
    volatile LONG64 eventsWritten;
    volatile LONG64 droppedContention;
    volatile LONG64 droppedFull;
    volatile LONG64 abandoned;
    HANDLE wakeEvent;
    HANDLE thread;
    HANDLE file;
    HANDLE directories[kDirectoryHandles];
    std::size_t directoryCount;
    BCRYPT_ALG_HANDLE algorithm;
    unsigned char key[32];
    wchar_t directory[kWriterPathCapacity];
    char runId[33];
    char formatBuffer[kMetadataBytes];
    ReporterStorage reporters[4];
    FileOps ops;
    std::uint64_t limit;
    std::uint64_t processStart;
    std::int64_t frequency;
    ULONGLONG lastAnchor;
    ULONGLONG lastFlush;
    DWORD pid;
    bool started;
    bool footerWritten;
    bool partialTail;
    bool closed;
    bool manual;
    bool noticedBound;
    bool noticedCalls;
#if defined(RS2_STEAM_REPORTING)
    reporting::StatusWire* reportStatus;
    reporting::ReportRing* reportRing;
    reporting::StatusHeader reportHeader;
    reporting::ReportRecord reportBatch[reporting::kReportBatchLimit];
    std::uint64_t lastReportSequence;
    volatile LONG reportReadyNotice;
    volatile LONG reportDisabledNotice;
    volatile LONG reportNoticeReason;
#endif
};
static_assert(std::is_trivial_v<Writer> && std::is_standard_layout_v<Writer>);

namespace {
bool HoldDirectory(Writer& writer, const wchar_t* path, bool make,
    bool requireNew, PrivateSecurity* security, DWORD& error) noexcept {
    if (writer.directoryCount == kDirectoryHandles) { error = ERROR_TOO_MANY_OPEN_FILES; return false; }
    if (make && !CreateDirectoryW(path, security ? &security->attributes : nullptr)) {
        error = GetLastError();
        if (requireNew || error != ERROR_ALREADY_EXISTS) return false;
    }
    // Omitting share-delete pins every path component against rename/removal.
    // OPEN_REPARSE_POINT checks the component itself rather than following it.
    const HANDLE directory = CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (directory == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
    BY_HANDLE_FILE_INFORMATION initial{};
    bool ok = Identity(directory, true, initial, error);
    if (ok && security) ok = CheckPrivateSecurity(directory, *security, error);
    // Compare a second path-based open while all ancestors and the new handle
    // are pinned. This rejects path/object ambiguity without trusting attributes.
    if (ok) {
        const HANDLE check = CreateFileW(path, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (check == INVALID_HANDLE_VALUE) { error = GetLastError(); ok = false; }
        else {
            BY_HANDLE_FILE_INFORMATION current{};
            ok = Identity(check, true, current, error) && SameIdentity(initial, current);
            CloseHandle(check);
            if (!ok && error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
        }
    }
    if (!ok) { CloseHandle(directory); return false; }
    writer.directories[writer.directoryCount++] = directory;
    return true;
}
bool HoldAncestors(Writer& writer, const wchar_t* path, wchar_t* canonical,
    DWORD& error) noexcept {
    const std::size_t length = wcsnlen_s(path, kWriterPathCapacity);
    if (length < 3 || length >= kWriterPathCapacity - 128 || path[1] != L':' || path[2] != L'\\' ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) {
        error = ERROR_BAD_PATHNAME; return false;
    }
    if (wcscpy_s(canonical, kWriterPathCapacity, path)) { error = ERROR_BAD_PATHNAME; return false; }
    if (length > 3 && canonical[length - 1] == L'\\') canonical[length - 1] = 0;
    wchar_t resolved[kWriterPathCapacity]{};
    const DWORD resolvedLength = GetFullPathNameW(canonical, kWriterPathCapacity, resolved, nullptr);
    if (!resolvedLength || resolvedLength >= kWriterPathCapacity || wcscmp(canonical, resolved)) {
        error = ERROR_BAD_PATHNAME; return false;
    }
    wchar_t root[4]{canonical[0], L':', L'\\', 0};
    if (GetDriveTypeW(root) != DRIVE_FIXED) { error = ERROR_NOT_SUPPORTED; return false; }
    if (!HoldDirectory(writer, root, false, false, nullptr, error)) return false;
    for (std::size_t index = 3, componentStart = 3; ; ++index) {
        const wchar_t ch = canonical[index];
        if (ch && ch != L'\\') {
            if (ch < 32 || ch == L'/' || ch == L':' || ch == L'?' || ch == L'*' || ch == L'"' ||
                ch == L'<' || ch == L'>' || ch == L'|') { error = ERROR_BAD_PATHNAME; return false; }
            continue;
        }
        if (index == componentStart || canonical[index - 1] == L'.' || canonical[index - 1] == L' ') {
            error = ERROR_BAD_PATHNAME; return false;
        }
        canonical[index] = 0;
        const bool ok = HoldDirectory(writer, canonical, false, false, nullptr, error);
        canonical[index] = ch;
        if (!ok) return false;
        if (!ch) break;
        componentStart = index + 1;
    }
    return true;
}
HANDLE CreateOwnedFile(const wchar_t* path, PrivateSecurity& security,
    DWORD access, DWORD share, DWORD& error) noexcept {
    const HANDLE file = CreateFileW(path, access | READ_CONTROL | FILE_READ_ATTRIBUTES,
        share, &security.attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); return INVALID_HANDLE_VALUE; }
    BY_HANDLE_FILE_INFORMATION identity{};
    if (!Identity(file, false, identity, error) || !CheckPrivateSecurity(file, security, error)) {
        CloseHandle(file); return INVALID_HANDLE_VALUE;
    }
    return file;
}
void CloseResources(Writer& writer) noexcept {
    if (writer.closed) return;
    writer.closed = true;
    if (writer.file != INVALID_HANDLE_VALUE && writer.file) CloseHandle(writer.file);
    writer.file = INVALID_HANDLE_VALUE;
    if (writer.algorithm) BCryptCloseAlgorithmProvider(writer.algorithm, 0);
    writer.algorithm = nullptr;
    SecureZeroMemory(writer.key, sizeof(writer.key));
    while (writer.directoryCount) CloseHandle(writer.directories[--writer.directoryCount]);
    // The wake/thread handles and POD itself remain process-lifetime: shutdown
    // signaling/snapshots can race worker exit, and no DllMain reclamation exists.
}
bool Token(Writer& writer, std::uint64_t id, char token[33]) noexcept {
    BCRYPT_HASH_HANDLE hash = nullptr;
    unsigned char input[8]{};
    unsigned char digest[32]{};
    for (unsigned i = 0; i < 8; ++i) input[i] = static_cast<unsigned char>(id >> (8 * i));
    NTSTATUS status = BCryptCreateHash(writer.algorithm, &hash, nullptr, 0,
        writer.key, sizeof(writer.key), 0);
    if (status >= 0) status = BCryptHashData(hash, input, sizeof(input), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (hash) BCryptDestroyHash(hash);
    if (status >= 0) Hex(digest, 16, token);
    SecureZeroMemory(input, sizeof(input));
    SecureZeroMemory(digest, sizeof(digest));
    return status >= 0;
}
WriterStatus Status(Writer& writer) noexcept {
    return static_cast<WriterStatus>(InterlockedCompareExchange(&writer.status, 0, 0));
}
void Fail(Writer& writer, WriterStatus status, DWORD error) noexcept {
#if defined(RS2_STEAM_REPORTING)
    if (writer.reportStatus) {
        // An actual admitted output failure stays sticky even across a later
        // normal stop. Console/log delivery cannot be required for this latch.
        reporting::LoseStatus(*writer.reportStatus, status == WriterStatus::Truncated ?
            reporting::Reason::LogLimit : reporting::Reason::WriterFailed);
    }
#endif
    if (Status(writer) == WriterStatus::Recording || Status(writer) == WriterStatus::Prepared) {
        InterlockedExchange(&writer.error, static_cast<LONG>(error));
        InterlockedExchange(&writer.status, static_cast<LONG>(status));
    }
}
void Notice(Writer& writer, unsigned index, const char* state, Reason reason) noexcept {
    if (writer.manual || index >= 4) return;
    ConsoleReportContext report{};
    const int length = std::snprintf(report.line, sizeof(report.line),
        "[RS2SteamObserve] v%s; status=%s; reason=%s; run_id=%s; pid=%lu\r\n",
        RS2FIX_VERSION_ASCII, state, ReasonName(reason), writer.runId, writer.pid);
    if (length > 0 && static_cast<std::size_t>(length) < sizeof(report.line)) {
        report.bytes = static_cast<DWORD>(length);
        TryStartReporter(&writer.reporters[index], report, ProductionConsoleStatusOps());
    }
}
bool WriteRecord(Writer& writer, DWORD length, bool footer = false) noexcept {
    const std::uint64_t used = Read64(&writer.bytesWritten);
    const std::uint64_t cap = writer.limit - (footer ? 0 : kFooterReserve);
    if (length > cap || used > cap - length) {
        if (!footer) Fail(writer, WriterStatus::Truncated, ERROR_FILE_TOO_LARGE);
        return false;
    }
    DWORD written = 0, error = ERROR_SUCCESS;
    const bool ok = writer.ops.write(writer.ops.context, writer.file,
        writer.formatBuffer, length, &written, &error);
    if (written > length) {
        Fail(writer, WriterStatus::Failed, ERROR_INVALID_DATA);
        writer.partialTail = true;
        return false;
    }
    Add64(&writer.bytesWritten, written);
    if (!ok || written != length) {
        // Never retry a partial append or append a footer onto its unfinished
        // JSON line. The fixed-prefix collector preserves and flags that tail.
        writer.partialTail = written != 0 && written != length;
        Fail(writer, WriterStatus::Failed, error ? error : ERROR_WRITE_FAULT);
        return false;
    }
    return true;
}
bool Startup(Writer& writer) noexcept {
    JsonBuffer json(writer.formatBuffer, kMetadataBytes);
    json.Append("{\"type\":\"startup\",\"schema\":1,\"version\":\"%s\",\"run_id\":\"%s\","
        "\"pid\":%lu,\"process_start_filetime\":%llu,\"utc_filetime\":%llu,\"qpc\":%lld,"
        "\"qpc_frequency\":%lld,\"max_log_bytes\":%llu,\"armed\":true,\"directory\":",
        RS2FIX_VERSION_ASCII, writer.runId, writer.pid, writer.processStart,
        UtcNow(), QpcNow(), writer.frequency, writer.limit);
    json.WideString(writer.directory);
    json.Append(",\"scope\":\"existing-calls-only\",\"authentication_changed\":false,"
        "\"unobserved_registration_slot\":25,\"unobserved_removal_slot\":26,"
        "\"external_capture_tokens_comparable\":false,\"termination_may_lose_tail\":true}\n");
    if (!json.Good()) { Fail(writer, WriterStatus::Failed, ERROR_INSUFFICIENT_BUFFER); return false; }
    return WriteRecord(writer, json.Size());
}
const char* StatusName(WriterStatus status) noexcept {
    switch (status) {
    case WriterStatus::Prepared: return "prepared";
    case WriterStatus::Recording: return "recording";
    case WriterStatus::Failed: return "failed";
    case WriterStatus::Truncated: return "truncated";
    case WriterStatus::Stopped: return "stopped";
    }
    return "unknown";
}
bool Anchor(Writer& writer, bool footer) noexcept {
    const auto counters = SnapshotCounters(*writer.dispatch);
    const auto snapshot = SnapshotWriter(&writer);
    JsonBuffer json(writer.formatBuffer, kAnchorBytes);
    json.Append("{\"type\":\"%s\",\"run_id\":\"%s\",\"pid\":%lu,\"utc_filetime\":%llu,\"qpc\":%lld,"
        "\"status\":\"%s\",\"error\":%lu,\"bytes_written\":%llu,\"events_written\":%llu,"
        "\"queue_depth\":%u,\"queue_dropped_contention\":%llu,\"queue_dropped_full\":%llu,"
        "\"queue_abandoned\":%llu,\"bindings_published\":%u,\"coverage_reasons\":%llu,"
        "\"unknown_lifecycle\":%s,\"lifecycle\":%llu,\"gate\":%ld,\"snapshots_atomic\":false,"
        "\"unobserved_slots_count\":35,\"partial_tail\":%s,\"counters\":[",
        footer ? "footer" : "anchor", writer.runId, writer.pid, UtcNow(), QpcNow(),
        StatusName(snapshot.status), snapshot.error, snapshot.bytesWritten, snapshot.eventsWritten,
        snapshot.queueDepth, snapshot.droppedContention, snapshot.droppedFull, snapshot.abandoned,
        counters.bindingsPublished, counters.coverageReasons, counters.unknownLifecycle ? "true" : "false",
        counters.lifecycle, static_cast<LONG>(counters.gate), writer.partialTail ? "true" : "false");
    bool first = true;
    for (Method method : kObservedMethods) {
        const auto slot = static_cast<std::size_t>(method);
        json.Append("%s{\"method\":%u,\"entered\":%llu,\"completed\":%llu}",
            first ? "" : ",", static_cast<unsigned>(method), counters.entered[slot], counters.completed[slot]);
        first = false;
    }
    json.Append("],\"logged_on_results\":[[%llu,%llu],[%llu,%llu],[%llu,%llu]]}\n",
        counters.loggedOnResults[0][0], counters.loggedOnResults[0][1],
        counters.loggedOnResults[1][0], counters.loggedOnResults[1][1],
        counters.loggedOnResults[2][0], counters.loggedOnResults[2][1]);
    if (!json.Good()) { Fail(writer, WriterStatus::Failed, ERROR_INSUFFICIENT_BUFFER); return false; }
    return WriteRecord(writer, json.Size(), footer);
}
bool FormatEvent(Writer& writer, const QueuedEvent& queued) noexcept {
    const Event& event = queued.event;
    JsonBuffer json(writer.formatBuffer, kEventBytes);
    json.Append("{\"type\":\"event\",\"queue_sequence\":%llu,\"call_id\":%llu,\"entry_qpc\":%lld,"
        "\"qpc\":%lld,\"entry_lifecycle\":%llu,\"lifecycle\":%llu,\"thread_id\":%u,\"caller_rva\":%u,"
        "\"binding_id\":%u,\"binding_sequence\":%u,\"method\":%u,\"phase\":%u,\"reason\":%u,"
        "\"flags\":%u,\"argument\":%lld,\"result\":%lld",
        queued.sequence, event.callId, event.entryQpc, event.qpc, event.entryLifecycle,
        event.lifecycle, event.threadId, event.callerRva, event.bindingId, event.bindingSequence,
        static_cast<unsigned>(event.method), static_cast<unsigned>(event.phase),
        static_cast<unsigned>(event.reason), event.flags, event.argument, event.result);
    if (event.flags & HasSteamId) {
        char token[33]{};
        if (!Token(writer, event.steamId, token)) {
            Fail(writer, WriterStatus::Failed, ERROR_GEN_FAILURE); return false;
        }
        json.Append(",\"steam_token\":\"%s\"", token);
    }
    json.Append("}\n");
    if (!json.Good()) { Fail(writer, WriterStatus::Failed, ERROR_INSUFFICIENT_BUFFER); return false; }
    return WriteRecord(writer, json.Size());
}
void Publish(void* context, const Event& event) noexcept {
    auto& writer = *static_cast<Writer*>(context);
    const WriterStatus status = Status(writer);
    if (status != WriterStatus::Prepared && status != WriterStatus::Recording) {
        Add64(&writer.abandoned, 1); return;
    }
    if (!TryAcquireSRWLockExclusive(&writer.queueLock)) {
        Add64(&writer.droppedContention, 1); return;
    }
    // No allocation/formatting/hash/I/O or producer wake occurs under this lock.
    const WriterStatus lockedStatus = Status(writer);
    if (lockedStatus != WriterStatus::Prepared && lockedStatus != WriterStatus::Recording) {
        ReleaseSRWLockExclusive(&writer.queueLock);
        Add64(&writer.abandoned, 1); return;
    }
    if (writer.count == kQueueCapacity) {
        ReleaseSRWLockExclusive(&writer.queueLock);
        Add64(&writer.droppedFull, 1); return;
    }
    const std::size_t tail = (writer.head + writer.count) % kQueueCapacity;
    writer.queue[tail] = {event, ++writer.nextQueueSequence};
    ++writer.count;
    InterlockedExchange(&writer.queueDepth, static_cast<LONG>(writer.count));
    ReleaseSRWLockExclusive(&writer.queueLock);
}
std::size_t TakeBatch(Writer& writer) noexcept {
    AcquireSRWLockExclusive(&writer.queueLock);
    const std::size_t count = writer.count < kBatchCount ? writer.count : kBatchCount;
    for (std::size_t i = 0; i < count; ++i) {
        writer.batch[i] = writer.queue[writer.head];
        SecureZeroMemory(&writer.queue[writer.head], sizeof(QueuedEvent));
        writer.head = (writer.head + 1) % kQueueCapacity;
    }
    writer.count -= count;
    InterlockedExchange(&writer.queueDepth, static_cast<LONG>(writer.count));
    ReleaseSRWLockExclusive(&writer.queueLock);
    return count;
}
void AbandonQueue(Writer& writer) noexcept {
    // Keep the same 256-record lock-hold bound during terminal cleanup. The
    // terminal status is already visible, so producers cannot replenish it.
    for (;;) {
        const std::size_t count = TakeBatch(writer);
        if (!count) return;
        SecureZeroMemory(writer.batch, count * sizeof(QueuedEvent));
        Add64(&writer.abandoned, count);
    }
}
void Terminal(Writer& writer) noexcept {
    AbandonQueue(writer);
    if (!writer.footerWritten && !writer.partialTail && writer.started) {
        writer.footerWritten = true;
        Anchor(writer, true);
    }
    Notice(writer, 3, StatusName(Status(writer)),
        Status(writer) == WriterStatus::Truncated ? Reason::LogLimit : Reason::WriterFailed);
    CloseResources(writer);
}
#if defined(RS2_STEAM_REPORTING)
void ReportNotice(const reporting::StatusHeader* header, bool ready,
    reporting::Reason reason) noexcept {
    auto* storage=ready ? &g_reportReadyReporter : &g_reportDisabledReporter;
    if (InterlockedCompareExchange(&storage->claimed,0,0)) return;
    ConsoleReportContext report{};
    char runId[33]{};
    const bool identified = header &&
        (header->validity & reporting::CompleteHeaderIdentity) == reporting::CompleteHeaderIdentity;
    if (identified) Hex(header->runId, sizeof(header->runId), runId);
    const auto mode = header ? static_cast<reporting::Mode>(header->configuredMode) : reporting::Mode::Invalid;
    const int count = std::snprintf(report.line, sizeof(report.line),
        "[RS2SteamReport] v0.4.1.0; status=%s; mode=%s; reason=%s; run_id=%s; pid=%lu\r\n",
        ready ? "ready" : "disabled", reporting::ModeName(mode), reporting::ReasonName(reason),
        identified ? runId : "unavailable", header ? static_cast<DWORD>(header->pid) : 0UL);
    if (count > 0 && static_cast<std::size_t>(count) < sizeof(report.line)) {
        report.bytes = static_cast<DWORD>(count);
        TryStartReporter(storage,report,ProductionConsoleStatusOps());
    }
}
void ReportingNotices(Writer& writer) noexcept {
    if (writer.manual) return;
    auto& status = *writer.reportStatus;
    const auto adverse = reporting::ReadStatusWord(status.revokeReasons) |
        reporting::ReadStatusWord(status.lossReasons);
    if (adverse || InterlockedCompareExchange(&writer.reportDisabledNotice, 0, 0)) {
        auto reason = static_cast<reporting::Reason>(
            InterlockedCompareExchange(&writer.reportNoticeReason, 0, 0));
        if (adverse) {
            for (std::size_t i = 0; i < reporting::kReasonCount; ++i) {
                if (adverse & (std::uint64_t{1} << i)) { reason = static_cast<reporting::Reason>(i); break; }
            }
        }
        ReportNotice(&writer.reportHeader, false, reason);
    } else if (!reporting::ReadStatusWord(status.stopping) &&
        InterlockedCompareExchange(&writer.reportReadyNotice, 0, 0)) {
        ReportNotice(&writer.reportHeader, true, reporting::Reason::None);
    }
}
bool ReportingStartup(Writer& writer) noexcept {
    const auto& header = writer.reportHeader;
    const auto& identities = reporting::SelectedReportingIdentities();
    char host[65]{}, sdk[65]{}, client[65]{};
    Hex(header.hostDigest, sizeof(header.hostDigest), host);
    Hex(identities.steamApiDigest.data(), identities.steamApiDigest.size(), sdk);
    Hex(identities.steamClientDigest.data(), identities.steamClientDigest.size(), client);
    JsonBuffer json(writer.formatBuffer, kAnchorBytes);
    json.Append("{\"type\":\"startup\",\"schema\":2,\"artifact\":\"RS2ServerFix-steam-reporting\","
        "\"version\":\"0.4.1.0\",\"artifact_version\":%u,\"run_id\":\"%s\",\"pid\":%u,"
        "\"process_start_filetime\":%llu,\"qpc_frequency\":%llu,\"utc_filetime\":%llu,"
        "\"qpc\":%lld,\"mode\":\"%s\",\"configured_mode\":%u,\"header_validity\":%u,"
        "\"host_sha256\":\"%s\",\"qualified_steam_api_sha256\":\"%s\","
        "\"qualified_steamclient_sha256\":\"%s\",\"max_log_bytes\":%llu,"
        "\"record_bytes\":256,\"ring_capacity\":256,\"batch_limit\":32,"
        "\"authentication_changed\":false,\"verbose_observer_trace\":false,"
        "\"termination_may_lose_tail\":true,\"directory\":",
        header.artifactVersion, writer.runId, header.pid, header.processCreation,
        header.qpcFrequency, UtcNow(), QpcNow(),
        reporting::ModeName(static_cast<reporting::Mode>(header.configuredMode)),
        header.configuredMode, header.validity, host, sdk, client, writer.limit);
    json.WideString(writer.directory); json.Append("}\n");
    if (!json.Good()) { Fail(writer, WriterStatus::Failed, ERROR_INSUFFICIENT_BUFFER); return false; }
    return WriteRecord(writer, json.Size());
}
bool FormatReport(Writer& writer, const reporting::ReportRecord& record) noexcept {
    using reporting::RecordKind;
    const auto kind = static_cast<RecordKind>(record.header.kind);
    const char* type = nullptr;
    switch (kind) {
    case RecordKind::State: type = "state"; break;
    case RecordKind::Request: type = "request"; break;
    case RecordKind::Witness: type = "witness"; break;
    case RecordKind::BuilderEnter: type = "builder-enter"; break;
    case RecordKind::BuilderReturn: type = "builder-return"; break;
    case RecordKind::BuilderUnwind: type = "builder-unwind"; break;
    case RecordKind::Anchor: type = "anchor"; break;
    case RecordKind::Count: break;
    }
    if (!type || writer.lastReportSequence == UINT64_MAX ||
        record.header.sequence != writer.lastReportSequence + 1) {
        reporting::LoseStatus(*writer.reportStatus, reporting::Reason::RecordLoss);
        Fail(writer, WriterStatus::Failed, ERROR_INVALID_DATA); return false;
    }
    JsonBuffer json(writer.formatBuffer, kAnchorBytes);
    json.Append("{\"type\":\"%s\",\"schema\":2,\"run_id\":\"%s\",\"pid\":%lu,"
        "\"sequence\":%llu,\"qpc\":%llu,\"source_epoch\":%llu,\"binding_epoch\":%llu,"
        "\"kind\":%u,\"reason\":%u,\"flags\":%u,\"thread_id\":%u",
        type, writer.runId, writer.pid, record.header.sequence, record.header.qpc,
        record.header.sourceEpoch, record.header.bindingEpoch, record.header.kind,
        record.header.reason, record.header.flags, record.header.threadId);
    const auto scalar = [&json](const char* name, std::uint64_t value) noexcept {
        json.Append(",\"%s\":%llu", name, value);
    };
    switch (kind) {
    case RecordKind::State: {
        const auto& p = record.payload.state;
        scalar("phase",p.phase); scalar("request_sequence",p.requestSequence);
        scalar("witness_sequence",p.witnessSequence); scalar("build_sequence",p.buildSequence);
        scalar("pending_since_qpc",p.pendingSinceQpc); scalar("fresh_since_qpc",p.freshSinceQpc);
        scalar("qualification_flags",p.qualificationFlags); scalar("native_task_state",p.nativeTaskState);
        scalar("client_qualification_ms",p.clientQualificationMs);
        scalar("native_schedule_valid",p.nativeScheduleValid);
        scalar("native_schedule_anchor_bits",p.nativeScheduleAnchorBits);
        scalar("native_errors_bits",p.nativeErrorsBits); scalar("native_throttles_bits",p.nativeThrottlesBits);
        scalar("native_expedite",p.nativeExpedite); scalar("native_retry_limit",p.nativeRetryLimit);
        scalar("native_interval_units",p.nativeIntervalUnits);
        scalar("native_interval_override_bits",p.nativeIntervalOverrideBits);
        scalar("native_retry_override_bits",p.nativeRetryOverrideBits);
        scalar("native_delay_units",p.nativeDelayUnits); scalar("native_tier",p.nativeTier);
        scalar("mode",p.mode); scalar("classification",p.classification);
        scalar("pi",p.pi); scalar("bots",p.bots); scalar("maximum",p.maximum);
        scalar("pending",p.pending); scalar("fresh",p.fresh); scalar("bound",p.bound);
        break;
    }
    case RecordKind::Request: case RecordKind::Witness: {
        const auto& p = record.payload.request;
        scalar("request_sequence",p.requestSequence); scalar("witness_sequence",p.witnessSequence);
        scalar("staged_qpc",p.stagedQpc); scalar("previous_sample_qpc",p.previousSampleQpc);
        scalar("observed_qpc",p.observedQpc); scalar("fresh_since_qpc",p.freshSinceQpc);
        scalar("source_age_ticks",p.sourceAgeTicks); scalar("pi",p.pi); scalar("bots",p.bots);
        scalar("maximum",p.maximum); scalar("staged_bots",p.stagedBots);
        scalar("human_players",p.humanPlayers); scalar("world_bots",p.worldBots);
        scalar("classification",p.classification); scalar("pending",p.pending);
        break;
    }
    case RecordKind::BuilderEnter: case RecordKind::BuilderReturn: case RecordKind::BuilderUnwind: {
        const auto& p = record.payload.builder;
        scalar("build_sequence",p.buildSequence); scalar("request_sequence",p.requestSequence);
        scalar("witness_sequence",p.witnessSequence); scalar("source_age_ticks",p.sourceAgeTicks);
        scalar("probe_elapsed_ticks",p.probeElapsedTicks);
        scalar("classification_elapsed_ticks",p.classificationElapsedTicks);
        scalar("original_elapsed_ticks",p.originalElapsedTicks);
        scalar("entry_qpc",p.entryQpc); scalar("return_qpc",p.returnQpc);
        scalar("pi",p.pi); scalar("bots",p.bots); scalar("maximum",p.maximum);
        scalar("classification",p.classification); scalar("selected",p.selected);
        scalar("result",p.result); scalar("pending",p.pending); scalar("fresh",p.fresh);
        break;
    }
    case RecordKind::Anchor: {
        // This is an owner-produced scalar copy. Never borrow status.owner or
        // infer a fresh anchor from mutable live owner fields on this worker.
        const auto& p = record.payload.anchor;
        scalar("normal_attempts",p.normalAttempts); scalar("full_selected",p.fullSelected);
        scalar("selected_true",p.selectedTrue); scalar("normal_returns",p.normalReturns);
        scalar("false_returns",p.falseReturns); scalar("native_unwinds",p.nativeUnwinds);
        scalar("request_sequence",p.requestSequence); scalar("witness_sequence",p.witnessSequence);
        scalar("build_sequence",p.buildSequence);
        scalar("distinct_selected_witnesses",p.distinctSelectedWitnesses);
        json.Append(",\"durations\":[");
        for (std::size_t i=0; i<reporting::kStatusDurationClasses; ++i) {
            const auto& duration=p.durations[i];
            json.Append("%s{\"class\":%u,\"calls\":%llu,\"elapsed_ticks\":%llu,"
                "\"maximum_ticks\":%llu,\"over_five_milliseconds\":%llu}",
                i ? "," : "", static_cast<unsigned>(i), duration.calls, duration.elapsedTicks,
                duration.maximumTicks, duration.overFiveMilliseconds);
        }
        json.Append("]"); break;
    }
    case RecordKind::Count: break;
    }
    json.Append("}\n");
    if (!json.Good()) { Fail(writer, WriterStatus::Failed, ERROR_INSUFFICIENT_BUFFER); return false; }
    if (!WriteRecord(writer,json.Size())) return false;
    writer.lastReportSequence=record.header.sequence;
    Add64(&writer.eventsWritten,1);
    reporting::StoreStatusWord(writer.reportStatus->recordsWritten,writer.lastReportSequence);
    return true;
}
bool FlushReporting(Writer& writer) noexcept {
    DWORD error = ERROR_SUCCESS;
    if (!writer.ops.flush(writer.ops.context,writer.file,&error)) {
        Fail(writer,WriterStatus::Failed,error ? error : ERROR_WRITE_FAULT); return false;
    }
    reporting::StoreStatusWord(writer.reportStatus->lastFlushedSequence,writer.lastReportSequence);
    return true;
}
void ReportingTerminal(Writer& writer) noexcept {
    // Never append to a partial JSON tail or label an uncollected pre-stop
    // prefix complete. Current status, not this historical file, owns liveness.
    ReportingNotices(writer);
    CloseResources(writer);
}
void PumpReporting(Writer& writer) noexcept {
    if (writer.closed || !InterlockedCompareExchange(&writer.armed,0,0)) return;
    if (!writer.started) {
        writer.started=true;
        InterlockedExchange(&writer.status,static_cast<LONG>(WriterStatus::Recording));
        if (!ReportingStartup(writer)) { ReportingTerminal(writer); return; }
    }
    std::size_t count=0;
    for (; count<reporting::kReportBatchLimit; ++count) {
        const auto result=reporting::DequeueReport(*writer.reportRing,&writer.reportBatch[count]);
        if (result==reporting::ReportReadResult::Empty) break;
        if (result!=reporting::ReportReadResult::Record) {
            reporting::LoseStatus(*writer.reportStatus,reporting::Reason::RecordLoss);
            Fail(writer,WriterStatus::Failed,ERROR_INVALID_DATA); break;
        }
    }
    std::size_t complete=0;
    if (Status(writer)==WriterStatus::Recording) {
        for (; complete<count; ++complete) if (!FormatReport(writer,writer.reportBatch[complete])) break;
    }
    Add64(&writer.abandoned,count-complete);
    SecureZeroMemory(writer.reportBatch,sizeof(writer.reportBatch));
    if (Status(writer)!=WriterStatus::Recording) { ReportingTerminal(writer); return; }
    const auto committed=reporting::ReadStatusWord(writer.reportRing->reportWriteSequence);
    const auto consumed=reporting::ReadStatusWord(writer.reportRing->reportReadSequence);
    const bool stopping=reporting::ReadStatusWord(writer.reportStatus->stopping)!=0 ||
        InterlockedCompareExchange(&writer.stop,0,0)!=0;
    const auto now=GetTickCount64();
    if (now-writer.lastFlush>=1000 || (stopping && committed==consumed)) {
        writer.lastFlush=now;
        if (!FlushReporting(writer)) { ReportingTerminal(writer); return; }
    }
    ReportingNotices(writer);
    if (stopping && committed==consumed) {
        // A final-admission/stop race may still publish a terminal record later;
        // no completeness footer is invented and no expected suppression loss
        // is fabricated. Already written/flush-confirmed sequence stays exact.
        InterlockedExchange(&writer.status,static_cast<LONG>(WriterStatus::Stopped));
        CloseResources(writer);
    }
}
#endif
void Pump(Writer& writer) noexcept {
#if defined(RS2_STEAM_REPORTING)
    if (writer.reportStatus) { PumpReporting(writer); return; }
#endif
    if (writer.closed || !InterlockedCompareExchange(&writer.armed, 0, 0)) return;
    if (!writer.started) {
        writer.started = true;
        InterlockedExchange(&writer.status, static_cast<LONG>(WriterStatus::Recording));
        if (!Startup(writer)) { Terminal(writer); return; }
        Notice(writer, 0, "armed", Reason::None);
    }
    for (unsigned batch = 0; batch < 4 && Status(writer) == WriterStatus::Recording; ++batch) {
        const std::size_t count = TakeBatch(writer);
        if (!count) break;
        std::size_t complete = 0;
        for (; complete < count; ++complete) {
            if (!FormatEvent(writer, writer.batch[complete])) break;
            Add64(&writer.eventsWritten, 1);
        }
        Add64(&writer.abandoned, count - complete);
        SecureZeroMemory(writer.batch, count * sizeof(QueuedEvent));
    }
    if (Status(writer) != WriterStatus::Recording) { Terminal(writer); return; }
    const ULONGLONG now = GetTickCount64();
    if (now - writer.lastAnchor >= 1000) {
        writer.lastAnchor = now;
        if (!Anchor(writer, false)) { Terminal(writer); return; }
    }
    if (now - writer.lastFlush >= 1000) {
        writer.lastFlush = now;
        DWORD error = ERROR_SUCCESS;
        if (!writer.ops.flush(writer.ops.context, writer.file, &error)) {
            Fail(writer, WriterStatus::Failed, error ? error : ERROR_WRITE_FAULT);
            Terminal(writer); return;
        }
    }
    const auto snapshot = SnapshotCounters(*writer.dispatch);
    if (!writer.noticedBound && snapshot.bindingsPublished) {
        writer.noticedBound = true;
        Notice(writer, 1, "bound", Reason::None);
    }
    if (!writer.noticedCalls) {
        for (Method method : kObservedMethods) {
            if (static_cast<unsigned>(method) < kSlotCount &&
                snapshot.entered[static_cast<std::size_t>(method)]) {
                writer.noticedCalls = true;
                Notice(writer, 2, "calls-observed", Reason::None);
                break;
            }
        }
    }
}
DWORD WINAPI WriterThread(void* context) noexcept {
    auto& writer = *static_cast<Writer*>(context);
    for (;;) {
        if (InterlockedCompareExchange(&writer.stop, 0, 0)) {
#if defined(RS2_STEAM_REPORTING)
            if (writer.reportStatus && InterlockedCompareExchange(&writer.armed,0,0)) {
                PumpReporting(writer); // Drain already committed records in <=32-record batches.
                if (!writer.closed) continue;
                return static_cast<DWORD>(InterlockedCompareExchange(&writer.error,0,0));
            }
#endif
            InterlockedExchange(&writer.status, static_cast<LONG>(WriterStatus::Stopped));
            AbandonQueue(writer);
            CloseResources(writer);
            return ERROR_SUCCESS;
        }
        if (InterlockedCompareExchange(&writer.armed, 0, 0)) {
            Pump(writer);
            if (writer.closed) return static_cast<DWORD>(InterlockedCompareExchange(&writer.error, 0, 0));
#if defined(RS2_STEAM_REPORTING)
            if (writer.reportRing && reporting::ReadStatusWord(writer.reportRing->reportWriteSequence) !=
                reporting::ReadStatusWord(writer.reportRing->reportReadSequence)) { Sleep(0); continue; }
#endif
            if (InterlockedCompareExchange(&writer.queueDepth, 0, 0)) { Sleep(0); continue; }
        }
        // Manual-reset event signals only startup arm/stop, never a hook. Reset
        // does not lose stop/arm because their interlocked flags are re-read.
        ResetEvent(writer.wakeEvent);
        if (!InterlockedCompareExchange(&writer.stop, 0, 0)) WaitForSingleObject(writer.wakeEvent, 50);
    }
}
Writer* Prepare(const wchar_t* executableDirectory, std::uint32_t maxLogMiB,
    DispatchState* dispatch, bool manual, const FileOps& ops, std::uint64_t testLimit,
    Reason* reason, DWORD* outputError
#if defined(RS2_STEAM_REPORTING)
    , reporting::StatusWire* reportStatus = nullptr, reporting::ReportRing* reportRing = nullptr
#endif
    ) noexcept {
    if (reason) *reason = Reason::PreparationFailed;
    if (outputError) *outputError = ERROR_INVALID_PARAMETER;
    if (!executableDirectory || !dispatch || maxLogMiB < 16 || maxLogMiB > 1024) return nullptr;
    auto writer = static_cast<Writer*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Writer)));
    if (!writer) { if (outputError) *outputError = ERROR_NOT_ENOUGH_MEMORY; return nullptr; }
    writer->dispatch = dispatch;
#if defined(RS2_STEAM_REPORTING)
    writer->reportStatus=reportStatus; writer->reportRing=reportRing;
    if (reportStatus) writer->reportHeader=reportStatus->header;
#endif
    writer->manual = manual;
    writer->file = INVALID_HANDLE_VALUE;
    writer->ops = ops;
    writer->limit = testLimit ? testLimit : static_cast<std::uint64_t>(maxLogMiB) * 1024 * 1024;
    writer->pid = GetCurrentProcessId();
    writer->lastFlush = writer->lastAnchor = GetTickCount64();
    DWORD error = ERROR_SUCCESS;
    Reason failureReason = Reason::PreparationFailed;
    PrivateSecurity security{};
    wchar_t canonical[kWriterPathCapacity]{};
    wchar_t results[kWriterPathCapacity]{};
    wchar_t keys[kWriterPathCapacity]{};
    wchar_t keyPath[kWriterPathCapacity]{};
    wchar_t eventsPath[kWriterPathCapacity]{};
    wchar_t leaf[128]{};
    unsigned char random[16]{};
    FILETIME creation{}, exit{}, kernel{}, user{};
    LARGE_INTEGER frequency{};
    bool ok = writer->limit >= 2 * kFooterReserve &&
        GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) &&
        QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0;
    if (!ok) error = ERROR_INVALID_DATA;
    writer->processStart = FiletimeValue(creation);
    writer->frequency = frequency.QuadPart;
#if defined(RS2_STEAM_REPORTING)
    if (ok && reportStatus) {
        const auto& header=writer->reportHeader;
        // Bind to the single existing startup identity, not merely a supplied
        // filename/run label. No entropy retry or alternate identity is allowed.
        ok=header.pid==writer->pid && header.processCreation==writer->processStart &&
            header.qpcFrequency==static_cast<std::uint64_t>(frequency.QuadPart);
        if (!ok) error=ERROR_INVALID_DATA;
        Hex(header.runId,sizeof(header.runId),writer->runId);
    }
#endif
    // Preserve the failing preparation step through cleanup. A path obstruction
    // or worker failure must not misleadingly diagnose the private key store.
    if (ok) {
        failureReason = Reason::OutputPathFailed;
        ok = HoldAncestors(*writer, executableDirectory, canonical, error);
    }
    if (ok) {
        failureReason = Reason::KeyStoreFailed;
#if defined(RS2_STEAM_REPORTING)
        if (reportStatus) failureReason=Reason::OutputPathFailed;
#endif
        ok = MakePrivateSecurity(security, error);
    }
    if (ok
#if defined(RS2_STEAM_REPORTING)
        && !reportStatus
#endif
        ) {
        failureReason = Reason::CryptoFailed;
        ok = BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 &&
            BCryptGenRandom(nullptr, writer->key, sizeof(writer->key), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 &&
            BCryptOpenAlgorithmProvider(&writer->algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0;
        if (!ok) error = ERROR_GEN_FAILURE;
    }
    if (ok) {
        failureReason = Reason::OutputPathFailed;
#if defined(RS2_STEAM_REPORTING)
        if (!reportStatus)
#endif
            Hex(random, sizeof(random), writer->runId);
        SYSTEMTIME utc{};
        GetSystemTime(&utc);
        _snwprintf_s(leaf, _countof(leaf), _TRUNCATE, L"%04u%02u%02uT%02u%02u%02uZ-PID%lu-%S",
            utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond, writer->pid, writer->runId);
        const wchar_t* resultsName=L"RS2SteamObserve";
#if defined(RS2_STEAM_REPORTING)
        if (reportStatus) resultsName=L"RS2SteamReport";
#endif
        ok = JoinPath(results, canonical, resultsName) &&
            JoinPath(writer->directory, results, leaf) &&
            JoinPath(eventsPath, writer->directory, L"events.jsonl");
#if defined(RS2_STEAM_REPORTING)
        if (!reportStatus)
#endif
        {
            _snwprintf_s(leaf, _countof(leaf), _TRUNCATE, L"%S.key", writer->runId);
            ok = ok && JoinPath(keys, canonical, L"RS2SteamObserveKeys") && JoinPath(keyPath, keys, leaf);
        }
        if (!ok) error = ERROR_FILENAME_EXCED_RANGE;
    }
    if (ok) {
        failureReason = Reason::OutputPathFailed;
        ok = HoldDirectory(*writer, results, true, false, &security, error);
    }
    if (ok
#if defined(RS2_STEAM_REPORTING)
        && !reportStatus
#endif
        ) {
        failureReason = Reason::KeyStoreFailed;
        ok = HoldDirectory(*writer, keys, true, false, &security, error);
    }
    if (ok) {
        failureReason = Reason::OutputPathFailed;
        ok = HoldDirectory(*writer, writer->directory, true, true, &security, error);
    }
    if (ok
#if defined(RS2_STEAM_REPORTING)
        && !reportStatus
#endif
        ) {
        failureReason = Reason::KeyStoreFailed;
        const HANDLE keyFile = CreateOwnedFile(keyPath, security, FILE_WRITE_DATA,
            FILE_SHARE_READ, error);
        if (keyFile == INVALID_HANDLE_VALUE) ok = false;
        else {
            DWORD written = 0;
            ok = WriteNative(nullptr, keyFile, writer->key, sizeof(writer->key), &written, &error) &&
                written == sizeof(writer->key);
            // Persist the private key before any main-log pseudonyms can exist.
            if (ok) ok = FlushNative(nullptr, keyFile, &error);
            CloseHandle(keyFile);
            if (!ok && !error) error = ERROR_WRITE_FAULT;
        }
    }
    if (ok) {
        failureReason = Reason::LogFileFailed;
        writer->file = CreateOwnedFile(eventsPath, security, FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ, error);
        ok = writer->file != INVALID_HANDLE_VALUE;
    }
    if (ok && !manual) {
        failureReason = Reason::WorkerStartFailed;
        writer->wakeEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ok = writer->wakeEvent != nullptr;
        if (!ok) error = GetLastError();
        if (ok) {
            writer->thread = CreateThread(nullptr, 0, WriterThread, writer, 0, nullptr);
            ok = writer->thread != nullptr;
            if (!ok) error = GetLastError();
        }
    }
    SecureZeroMemory(&security, sizeof(security));
    SecureZeroMemory(random, sizeof(random));
    if (!ok) {
        CloseResources(*writer);
        if (writer->wakeEvent) CloseHandle(writer->wakeEvent);
        HeapFree(GetProcessHeap(), 0, writer);
        if (reason) *reason = failureReason;
        if (outputError) *outputError = error ? error : ERROR_GEN_FAILURE;
        return nullptr;
    }
    if (reason) *reason = Reason::None;
    if (outputError) *outputError = ERROR_SUCCESS;
    return writer;
}
} // namespace

Writer* PrepareWriter(const wchar_t* directory, std::uint32_t maxMiB,
    DispatchState* dispatch, Reason* reason, DWORD* error) noexcept {
    return Prepare(directory, maxMiB, dispatch, false, {nullptr, WriteNative, FlushNative},
        0, reason, error);
}
EventSink GetWriterSink(Writer* writer) noexcept {
#if defined(RS2_STEAM_REPORTING)
    if (writer && writer->reportStatus) return {}; // Never expose a legacy identity-carrying sink.
#endif
    return writer ? EventSink{writer, Publish} : EventSink{};
}
void ArmWriter(Writer* writer) noexcept {
    if (!writer || ReadGate(*writer->dispatch) != Gate::Armed) return;
    InterlockedExchange(&writer->armed, 1);
    if (writer->wakeEvent) SetEvent(writer->wakeEvent);
}
void StopUnarmedWriter(Writer* writer) noexcept {
    if (!writer || InterlockedCompareExchange(&writer->armed, 0, 0)) return;
    InterlockedExchange(&writer->stop, 1);
    if (writer->wakeEvent) SetEvent(writer->wakeEvent);
}
const wchar_t* GetWriterDirectory(const Writer* writer) noexcept {
    return writer ? writer->directory : L"";
}
WriterSnapshot SnapshotWriter(Writer* writer) noexcept {
    if (!writer) return {};
    auto depth=static_cast<std::uint32_t>(InterlockedCompareExchange(&writer->queueDepth,0,0));
#if defined(RS2_STEAM_REPORTING)
    if (writer->reportRing) {
        const auto read=reporting::ReadStatusWord(writer->reportRing->reportReadSequence);
        const auto written=reporting::ReadStatusWord(writer->reportRing->reportWriteSequence);
        depth=written>=read && written-read<=reporting::kReportRecordCapacity ?
            static_cast<std::uint32_t>(written-read) : 0;
    }
#endif
    return {Status(*writer), static_cast<DWORD>(InterlockedCompareExchange(&writer->error, 0, 0)),
        Read64(&writer->bytesWritten), Read64(&writer->eventsWritten), Read64(&writer->droppedContention),
        Read64(&writer->droppedFull), Read64(&writer->abandoned),
        depth};
}
void ScheduleObserverDisabledNotice(Reason reason) noexcept {
    ConsoleReportContext report{};
    const int count = std::snprintf(report.line, sizeof(report.line),
        "[RS2SteamObserve] v%s; status=disabled; reason=%s\r\n", RS2FIX_VERSION_ASCII, ReasonName(reason));
    if (count > 0 && static_cast<std::size_t>(count) < sizeof(report.line)) {
        report.bytes = static_cast<DWORD>(count);
        TryStartReporter(&g_disabledReporter, report, ProductionConsoleStatusOps());
    }
}
#if defined(RS2_OBSERVER_TESTING)
Writer* PrepareWriterForTest(const wchar_t* directory, DispatchState* dispatch,
    const WriterTestOptions& options, Reason* reason, DWORD* error) noexcept {
    return Prepare(directory, 16, dispatch, true,
        {options.context, options.write ? options.write : WriteNative,
            options.flush ? options.flush : FlushNative}, options.byteLimit, reason, error);
}
void PumpWriterForTest(Writer* writer) noexcept { if (writer && writer->manual) Pump(*writer); }
void FinishWriterForTest(Writer* writer) noexcept {
    if (!writer || !writer->manual) return;
#if defined(RS2_STEAM_REPORTING)
    if (writer->reportStatus) {
        if (!writer->closed) {
            reporting::StopReportingWriter(writer);
            if (InterlockedCompareExchange(&writer->armed,0,0)) {
                for (std::size_t i=0; i<reporting::kReportRecordCapacity/reporting::kReportBatchLimit+2 &&
                    !writer->closed; ++i) PumpReporting(*writer);
            } else {
                InterlockedExchange(&writer->status,static_cast<LONG>(WriterStatus::Stopped));
                CloseResources(*writer);
            }
        }
        return;
    }
#endif
    if (!writer->closed) {
        InterlockedExchange(&writer->status, static_cast<LONG>(WriterStatus::Stopped));
        if (writer->started) Terminal(*writer); else { AbandonQueue(*writer); CloseResources(*writer); }
    }
}
void LockWriterQueueForTest(Writer* writer) noexcept { AcquireSRWLockExclusive(&writer->queueLock); }
void UnlockWriterQueueForTest(Writer* writer) noexcept { ReleaseSRWLockExclusive(&writer->queueLock); }
bool HmacSteamIdForTest(const unsigned char key[32], std::uint64_t id, char token[33]) noexcept {
    auto writer = static_cast<Writer*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Writer)));
    if (!writer) return false;
    std::memcpy(writer->key, key, sizeof(writer->key));
    bool ok = BCryptOpenAlgorithmProvider(&writer->algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0;
    if (ok) ok = Token(*writer, id, token);
    CloseResources(*writer);
    HeapFree(GetProcessHeap(), 0, writer);
    return ok;
}
#endif
} // namespace rs2fix::observer
#if defined(RS2_STEAM_REPORTING)
namespace rs2fix::reporting {
namespace {
bool ReportingWriterIdentity(const StatusWire& status, const ReportRing& ring) noexcept {
    if (ReadStatusWord(status.headerReady)!=1 || ReadStatusWord(ring.ready)!=1 ||
        ring.status!=&status || ring.ownerThreadId!=GetCurrentThreadId() ||
        ReadStatusWord(status.recordsWritten) || ReadStatusWord(status.lastFlushedSequence) ||
        StatusRevoked(status)) return false;
    const auto& header=status.header;
    if (header.magic!=kStatusMagic || header.schema!=kStatusSchema || header.bytes!=sizeof(StatusWire) ||
        header.artifactVersion!=kReportingArtifactVersion || header.validity!=CompleteHeaderIdentity ||
        (header.configuredMode!=static_cast<std::uint32_t>(Mode::Observe) &&
            header.configuredMode!=static_cast<std::uint32_t>(Mode::Repair)) ||
        !header.pid || !header.processCreation || !header.qpcFrequency ||
        header.qpcFrequency>static_cast<std::uint64_t>(INT64_MAX) ||
        std::memcmp(header.hostDigest,SelectedReportingIdentities().hostDigest.data(),sizeof(header.hostDigest)))
        return false;
    bool runPresent=false;
    for (const auto byte:header.runId) if (byte) runPresent=true;
    return runPresent;
}
observer::Writer* PrepareReport(const wchar_t* directory, std::uint32_t quota,
    StatusWire& status, ReportRing& ring, observer::DispatchState& dispatch,
    bool manual, const observer::FileOps& ops, std::uint64_t testLimit, Reason* reason, DWORD* error) noexcept {
    if (reason) *reason=Reason::IdentityIncomplete;
    if (error) *error=ERROR_INVALID_DATA;
    if (!ReportingWriterIdentity(status,ring)) {
        RevokeStatus(status,Reason::IdentityIncomplete); return nullptr;
    }
    observer::Reason failure{};
    auto* writer=observer::Prepare(directory,quota,&dispatch,manual,ops,testLimit,&failure,error,&status,&ring);
    if (!writer) {
        LoseStatus(status,Reason::WriterFailed);
        if (reason) *reason=Reason::WriterFailed;
        return nullptr;
    }
    if (reason) *reason=Reason::None;
    return writer;
}
} // namespace
observer::Writer* PrepareReportingWriter(const wchar_t* directory, std::uint32_t quota,
    StatusWire& status, ReportRing& ring, observer::DispatchState& dispatch, Reason* reason, DWORD* error) noexcept {
    return PrepareReport(directory,quota,status,ring,dispatch,false,
        {nullptr,observer::WriteNative,observer::FlushNative},0,reason,error);
}
ReportSink GetReportingWriterSink(observer::Writer* writer) noexcept {
    return writer && writer->reportRing ? ReportRingSink(*writer->reportRing) : ReportSink{};
}
void ArmReportingWriter(observer::Writer* writer) noexcept {
    if (!writer || !writer->reportStatus) return;
    if (writer->dispatch->sink.publish || writer->dispatch->sink.context) {
        RevokeStatus(*writer->reportStatus,Reason::PreparationFailed);
        observer::StopUnarmedWriter(writer); return;
    }
    if (!StatusRevoked(*writer->reportStatus)) observer::ArmWriter(writer);
}
void StopReportingWriter(observer::Writer* writer) noexcept {
    if (!writer || !writer->reportStatus) return;
    const auto qpc=observer::QpcNow();
    StopStatus(*writer->reportStatus,qpc>0 ? static_cast<std::uint64_t>(qpc) : 0);
    InterlockedExchange(&writer->stop,1);
    if (writer->wakeEvent) SetEvent(writer->wakeEvent);
}
void RequestReportingNotice(observer::Writer* writer, bool ready, Reason reason) noexcept {
    if (!writer || !writer->reportStatus) return;
    if (ready) InterlockedExchange(&writer->reportReadyNotice,1);
    else {
        InterlockedExchange(&writer->reportNoticeReason,static_cast<LONG>(reason));
        InterlockedExchange(&writer->reportDisabledNotice,1);
    }
}
void ScheduleReportingDisabledNotice(const StatusWire& status, Reason reason) noexcept {
    observer::ReportNotice(ReadStatusWord(status.headerReady)==1 ? &status.header : nullptr,false,reason);
}
#if defined(RS2_OBSERVER_TESTING)
observer::Writer* PrepareReportingWriterForTest(const wchar_t* directory, StatusWire& status,
    ReportRing& ring, observer::DispatchState& dispatch, const observer::WriterTestOptions& options,
    Reason* reason, DWORD* error) noexcept {
    return PrepareReport(directory,16,status,ring,dispatch,true,
        {options.context,options.write ? options.write : observer::WriteNative,
            options.flush ? options.flush : observer::FlushNative},options.byteLimit,reason,error);
}
#endif
} // namespace rs2fix::reporting
#endif
