#include "companion/leech_recovery_control.h"
#include "shared/path_identity.h"
#include <AclAPI.h>
#include <sddl.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <type_traits>

namespace rs2fix::recovery {
static_assert(std::is_trivial_v<ControlState> && std::is_standard_layout_v<ControlState>);
namespace {
constexpr DWORD kMutation = DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA |
    FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
constexpr DWORD kKnownAccess = FILE_ALL_ACCESS | GENERIC_ALL | GENERIC_READ |
    GENERIC_WRITE | GENERIC_EXECUTE;
bool Equal(const char* bytes, std::size_t count, const char* expected) noexcept {
    return std::strlen(expected) == count && std::memcmp(bytes, expected, count) == 0;
}
bool SidEqual(PSID left, PSID right) noexcept {
    return left && right && IsValidSid(left) && IsValidSid(right) && EqualSid(left, right);
}
bool WellKnown(PSID sid, WELL_KNOWN_SID_TYPE kind) noexcept {
    return sid && IsValidSid(sid) && IsWellKnownSid(sid, kind);
}
bool Trusted(PSID sid, const ControlSecurity& policy, bool permissionFile) noexcept {
    return WellKnown(sid, WinBuiltinAdministratorsSid) || WellKnown(sid, WinLocalSystemSid) ||
        (policy.administratorSidBytes && SidEqual(sid, const_cast<BYTE*>(policy.administratorSid))) ||
        (!permissionFile && policy.operatorSidBytes && SidEqual(sid, const_cast<BYTE*>(policy.operatorSid)));
}
bool ValidateSecurity(PSECURITY_DESCRIPTOR descriptor, const ControlSecurity& policy,
    bool permissionFile) noexcept {
    if (!descriptor || !IsValidSecurityDescriptor(descriptor)) return false;
    PSID owner{}; BOOL defaulted{};
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        !Trusted(owner, policy, permissionFile)) return false;
    PACL acl{}; BOOL present{};
    if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) ||
        !present || !acl || !IsValidAcl(acl)) return false;
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw{};
        if (!GetAce(acl, i, &raw)) return false;
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE)) return false;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)
            return false; // Conditional/object/callback permissions are unsupported.
        if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8) return false;
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        auto* sid = const_cast<DWORD*>(&ace->SidStart);
        const auto* sidHeader = reinterpret_cast<const SID*>(sid);
        if (sidHeader->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
            8u + 4u * sidHeader->SubAuthorityCount > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) ||
            !IsValidSid(sid) ||
            (ace->Mask & ~kKnownAccess)) return false;
        auto mask = ace->Mask;
        MapGenericMask(&mask, &mapping);
        // Include inherit-only grants: they may create writable control children.
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE && (mask & kMutation) &&
            !Trusted(sid, policy, permissionFile)) return false;
    }
    return true;
}
bool ObserveSecurity(HANDLE file, const ControlSecurity& policy, bool permissionFile,
    wchar_t* observed, std::size_t capacity, DWORD* error) noexcept {
    if (!observed || !capacity) { *error = ERROR_INVALID_PARAMETER; return false; }
    observed[0] = L'\0';
    PSECURITY_DESCRIPTOR descriptor{};
    const auto code = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr,
        nullptr, nullptr, &descriptor);
    if (code != ERROR_SUCCESS) { *error = code; return false; }
    wchar_t* text{}; ULONG length{};
    const bool converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,
        SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, &length) != FALSE;
    bool captured = false;
    if (converted && length && length <= capacity) {
        std::wmemcpy(observed, text, length);
        captured = observed[length - 1] == L'\0';
    }
    const bool valid = captured && ValidateSecurity(descriptor, policy, permissionFile);
    if (!valid) *error = captured ? ERROR_ACCESS_DENIED :
        (converted ? ERROR_INSUFFICIENT_BUFFER : GetLastError());
    if (text) LocalFree(text);
    LocalFree(descriptor);
    return valid;
}
bool AdministratorIdentity(ControlSecurity* policy, DWORD* error) noexcept {
    // Startup permission and the new worker must use the same process identity.
    // An impersonated startup thread cannot approve its underlying account.
    HANDLE threadToken{};
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken)) {
        CloseHandle(threadToken); *error = ERROR_BAD_IMPERSONATION_LEVEL; return false;
    }
    if (GetLastError() != ERROR_NO_TOKEN) { *error = GetLastError(); return false; }
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)) { *error = GetLastError(); return false; }
    alignas(TOKEN_USER) BYTE buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]{};
    DWORD returned{};
    bool okay = GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &returned) != FALSE;
    if (!okay) *error = GetLastError();
    BYTE administrators[SECURITY_MAX_SID_SIZE]{}; DWORD size = sizeof(administrators); BOOL member{};
    HANDLE membershipToken{};
    if (okay && (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &size) ||
            !DuplicateToken(token, SecurityIdentification, &membershipToken) ||
            !CheckTokenMembership(membershipToken, administrators, &member))) { okay = false; *error = GetLastError(); }
    if (membershipToken && !CloseHandle(membershipToken)) { okay = false; *error = GetLastError(); }
    if (okay && member) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer);
        const auto bytes = GetLengthSid(user->User.Sid);
        if (bytes > sizeof(policy->administratorSid) ||
            !CopySid(sizeof(policy->administratorSid), policy->administratorSid, user->User.Sid)) {
            okay = false; *error = GetLastError();
        } else policy->administratorSidBytes = bytes;
    }
    if (!CloseHandle(token)) { okay = false; *error = GetLastError(); }
    return okay;
}
bool FinalPath(HANDLE file, const wchar_t* expected, DWORD* error) noexcept {
    wchar_t finalPath[kControlPathBytes]{};
    const auto length = GetFinalPathNameByHandleW(file, finalPath, static_cast<DWORD>(std::size(finalPath)),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!length || length >= std::size(finalPath)) {
        *error = length ? ERROR_INSUFFICIENT_BUFFER : GetLastError(); return false;
    }
    if (std::wcsncmp(finalPath, L"\\\\?\\", 4) != 0 ||
        CompareStringOrdinal(finalPath + 4, -1, expected, -1, TRUE) != CSTR_EQUAL) {
        *error = ERROR_INVALID_NAME; return false;
    }
    return true;
}
bool FileMetadata(HANDLE file, const wchar_t* exactPath, bool directory,
    DWORD* size, DWORD* error) noexcept {
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(file) != FILE_TYPE_DISK) { *error = ERROR_INVALID_HANDLE; return false; }
    if (!GetFileInformationByHandle(file, &info)) { *error = GetLastError(); return false; }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        (!directory && info.nNumberOfLinks != 1)) { *error = ERROR_INVALID_DATA; return false; }
    if (!FinalPath(file, exactPath, error)) return false;
    if (!directory) {
        LARGE_INTEGER bytes{};
        if (!GetFileSizeEx(file, &bytes)) { *error = GetLastError(); return false; }
        if (bytes.QuadPart <= 0 || bytes.QuadPart > kControlFileBytes) {
            *error = ERROR_INVALID_DATA; return false;
        }
        *size = static_cast<DWORD>(bytes.QuadPart);
    }
    return true;
}
ControlResult ReadBounded(const wchar_t* exactPath, const ControlSecurity& policy,
    bool permissionFile, char (&bytes)[kControlFileBytes], DWORD* count,
    wchar_t* observed, std::size_t aclCapacity, DWORD* error,
    bool enforceFileAcl = true) noexcept {
    *count = 0; *error = ERROR_SUCCESS;
    const auto file = CreateFileW(exactPath, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        *error = GetLastError();
        if (*error == ERROR_SHARING_VIOLATION || *error == ERROR_LOCK_VIOLATION) return ControlResult::PendingWrite;
        return *error == ERROR_FILE_NOT_FOUND || *error == ERROR_PATH_NOT_FOUND ?
            ControlResult::Missing : ControlResult::ReadFailure;
    }
    DWORD size{};
    ControlResult result = ControlResult::ReadFailure;
    if (!FileMetadata(file, exactPath, false, &size, error)) result = ControlResult::InvalidPath;
    else if (enforceFileAcl && !ObserveSecurity(file, policy, permissionFile, observed, aclCapacity, error))
        result = ControlResult::SecurityRejected;
    else {
        DWORD read{};
        if (!ReadFile(file, bytes, size, &read, nullptr)) {
            *error = GetLastError();
            if (*error == ERROR_LOCK_VIOLATION) result = ControlResult::PendingWrite;
        }
        else if (read != size) *error = ERROR_HANDLE_EOF;
        else { *count = read; result = ControlResult::Ready; }
    }
    // FILE_SHARE_READ pins the same file against writes, replacement and delete.
    if (!CloseHandle(file)) { *error = GetLastError(); result = ControlResult::ReadFailure; *count = 0; }
    return result;
}
bool ParseSid(const char* bytes, std::size_t count, ControlConfig* output) noexcept {
    wchar_t stringSid[184]{};
    if (!count || count >= std::size(stringSid)) return false;
    for (std::size_t i = 0; i < count; ++i) stringSid[i] = static_cast<unsigned char>(bytes[i]);
    PSID sid{};
    if (!ConvertStringSidToSidW(stringSid, &sid)) return false;
    wchar_t* canonical{};
    bool valid = ConvertSidToStringSidW(sid, &canonical) != FALSE && canonical &&
        std::wcscmp(canonical, stringSid) == 0 &&
        !WellKnown(sid, WinWorldSid) && !WellKnown(sid, WinAuthenticatedUserSid) &&
        !WellKnown(sid, WinBuiltinUsersSid) && !WellKnown(sid, WinAnonymousSid);
    if (valid) {
        const auto size = GetLengthSid(sid);
        valid = size <= sizeof(output->operatorSid) &&
            CopySid(sizeof(output->operatorSid), output->operatorSid, sid) != FALSE;
        if (valid) output->operatorSidBytes = size;
    }
    if (canonical) LocalFree(canonical);
    LocalFree(sid);
    return valid;
}
struct Json {
    const char* bytes; std::size_t size; std::size_t cursor;
    void Space() noexcept {
        while (cursor < size && (bytes[cursor] == ' ' || bytes[cursor] == '\t' ||
            bytes[cursor] == '\r' || bytes[cursor] == '\n')) ++cursor;
    }
    bool Take(char c) noexcept { Space(); if (cursor >= size || bytes[cursor] != c) return false; ++cursor; return true; }
    bool String(char* value, std::size_t capacity) noexcept {
        if (!Take('"')) return false;
        std::size_t length{};
        while (cursor < size) {
            auto c = bytes[cursor++];
            if (c == '"') { value[length] = '\0'; return true; }
            if (c == '\\') {
                if (cursor >= size || bytes[cursor] != '\\') return false;
                c = bytes[cursor++];
            }
            if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126 || length + 1 >= capacity)
                return false;
            value[length++] = c;
        }
        return false;
    }
    bool Number(DWORD* value) noexcept {
        Space(); const auto start = cursor; DWORD number{};
        while (cursor < size && bytes[cursor] >= '0' && bytes[cursor] <= '9') {
            const auto digit = static_cast<DWORD>(bytes[cursor++] - '0');
            if (number > (MAXDWORD - digit) / 10) return false;
            number = number * 10 + digit;
        }
        if (cursor == start || (cursor - start > 1 && bytes[start] == '0')) return false;
        *value = number; return true;
    }
};
bool ValidIdentity(const ControlRequest& identity) noexcept {
    bool nonzero = false;
    for (const auto byte : identity.runId) nonzero |= byte != 0;
    return identity.pid && nonzero;
}
void CloseDirectories(ControlState& state) noexcept {
    for (auto& handle : state.directories) {
        if (handle) CloseHandle(handle);
        handle = nullptr;
    }
}
bool PeerMatches(const ControlSecurity& policy, PSID sid) noexcept {
    return policy.operatorSidBytes && SidEqual(sid, const_cast<BYTE*>(policy.operatorSid));
}
ControlResult PreparePipe(ControlState& state, DWORD* error) noexcept {
    char run[33]{};
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < 16; ++i) {
        run[i * 2] = hex[state.identity.runId[i] >> 4];
        run[i * 2 + 1] = hex[state.identity.runId[i] & 15];
    }
    if (swprintf_s(state.requestPath, L"\\\\.\\pipe\\RS2LeechRecovery.%lu.%hs",
        state.identity.pid, run) < 0) {
        *error = ERROR_INVALID_NAME; return ControlResult::InvalidPath;
    }
    wchar_t* operatorText{};
    if (!ConvertSidToStringSidW(state.security.operatorSid, &operatorText)) {
        *error = GetLastError(); return ControlResult::SecurityRejected;
    }
    wchar_t sddl[256]{};
    // A separate kernel object is the authority boundary. Never mutate existing
    // file/folder ACLs. The operator grant excludes CREATE_PIPE_INSTANCE.
    const bool formatted = swprintf_s(sddl,
        L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120182;;;%s)", operatorText) >= 0;
    LocalFree(operatorText);
    PSECURITY_DESCRIPTOR descriptor{};
    if (!formatted || !ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
        *error = formatted ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        return ControlResult::SecurityRejected;
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    state.pipe = CreateNamedPipeW(state.requestPath,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 0, static_cast<DWORD>(kControlFileBytes + 1), 0, &attributes);
    LocalFree(descriptor);
    if (state.pipe == INVALID_HANDLE_VALUE) {
        state.pipe = nullptr; *error = GetLastError(); return ControlResult::EndpointUnavailable;
    }
    if (!ObserveSecurity(state.pipe, state.security, false, state.requestAcl,
        std::size(state.requestAcl), error)) {
        CloseHandle(state.pipe); state.pipe = nullptr; return ControlResult::SecurityRejected;
    }
    state.ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    state.stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!state.ioEvent || !state.stopEvent) {
        *error = GetLastError();
        if (state.ioEvent) CloseHandle(state.ioEvent);
        if (state.stopEvent) CloseHandle(state.stopEvent);
        CloseHandle(state.pipe);
        state.pipe = state.ioEvent = state.stopEvent = nullptr;
        return ControlResult::WorkerFailure;
    }
    return ControlResult::Ready;
}
bool WaitPipeIo(ControlState& state, OVERLAPPED& operation, DWORD timeout,
    DWORD* transferred) noexcept {
    const HANDLE waits[]{state.stopEvent, state.ioEvent};
    const auto wait = WaitForMultipleObjects(2, waits, FALSE, timeout);
    if (wait == WAIT_OBJECT_0 + 1 && !InterlockedCompareExchange(&state.stop, 0, 0)) {
        if (GetOverlappedResult(state.pipe, &operation, transferred, FALSE)) return true;
        state.error = GetLastError(); return false;
    }
    const DWORD failure = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT :
        wait == WAIT_FAILED ? GetLastError() : ERROR_OPERATION_ABORTED;
    // Drain before stack-owned OVERLAPPED and its buffer can end. Storage and
    // the stop event remain resident; StopControl never waits on this worker.
    CancelIoEx(state.pipe, &operation);
    DWORD ignored{};
    GetOverlappedResult(state.pipe, &operation, &ignored, TRUE);
    state.error = failure; return false;
}
bool AuthenticatePeer(ControlState& state) noexcept {
    if (!ImpersonateNamedPipeClient(state.pipe)) { state.error = GetLastError(); return false; }
    HANDLE token{};
    alignas(TOKEN_USER) BYTE buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]{};
    DWORD returned{};
    bool accepted = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) != FALSE;
    if (accepted) accepted = GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &returned) != FALSE;
    if (accepted) accepted = PeerMatches(state.security, reinterpret_cast<const TOKEN_USER*>(buffer)->User.Sid);
    const DWORD failure = accepted ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
    if (token && !CloseHandle(token)) accepted = false;
    // No latch/publication/native work under client impersonation. Returning
    // failure terminates this worker even if Windows could not revert it.
    if (!RevertToSelf()) { state.error = GetLastError(); return false; }
    state.error = accepted ? ERROR_SUCCESS : failure;
    return accepted;
}
ControlResult ReceivePipe(ControlState& state) noexcept {
    OVERLAPPED operation{}; operation.hEvent = state.ioEvent;
    DWORD count{};
    const bool connected = ConnectNamedPipe(state.pipe, &operation) != FALSE;
    if (!connected) {
        const auto error = GetLastError();
        if (error != ERROR_PIPE_CONNECTED && (error != ERROR_IO_PENDING ||
            !WaitPipeIo(state, operation, INFINITE, &count))) {
            if (error != ERROR_IO_PENDING) state.error = error;
            return state.stop ? ControlResult::Stopped : ControlResult::ReadFailure;
        }
    }
    char bytes[kControlFileBytes + 1]{};
    if (!ResetEvent(state.ioEvent)) { state.error = GetLastError(); return ControlResult::WorkerFailure; }
    operation = {}; operation.hEvent = state.ioEvent;
    const bool read = ReadFile(state.pipe, bytes, static_cast<DWORD>(sizeof(bytes)), &count, &operation) != FALSE;
    if (!read) {
        const auto error = GetLastError();
        if (error != ERROR_IO_PENDING || !WaitPipeIo(state, operation, 10000, &count)) {
            if (error != ERROR_IO_PENDING) state.error = error;
            return state.stop ? ControlResult::Stopped :
                state.error == ERROR_MORE_DATA ? ControlResult::InvalidRequest : ControlResult::ReadFailure;
        }
    }
    if (InterlockedCompareExchange(&state.stop, 0, 0)) return ControlResult::Stopped;
    if (!AuthenticatePeer(state)) return ControlResult::SecurityRejected;
    ControlRequest request{};
    const auto result = ParseControlRequest(bytes, count, state.identity, &request);
    if (result != ControlResult::Ready) { state.error = ERROR_INVALID_DATA; return result; }
    state.request = request;
    InterlockedExchange(&state.latched, 1);
    return ControlResult::Latched;
}
DWORD WINAPI Worker(void* parameter) noexcept {
    auto& state = *static_cast<ControlState*>(parameter);
    const auto result = ReceivePipe(state);
    DisconnectNamedPipe(state.pipe);
    CloseHandle(state.pipe);
    InterlockedExchange(&state.result, static_cast<LONG>(result));
    return 0;
}
} // namespace

ControlResult ParseControlConfig(const char* bytes, std::size_t size, ControlConfig* output) noexcept {
    if (output) *output = {};
    if (!bytes || !size || size > kControlFileBytes || !output) return ControlResult::InvalidConfig;
    ControlConfig parsed{}; unsigned fields{}; bool none{};
    for (std::size_t cursor = 0; cursor < size;) {
        const auto start = cursor;
        while (cursor < size && bytes[cursor] != '\n') {
            const auto c = static_cast<unsigned char>(bytes[cursor++]);
            if (!c || c > 127 || (c < 32 && c != '\t' && c != '\r')) return ControlResult::InvalidConfig;
        }
        auto first = start, last = cursor;
        if (cursor < size) ++cursor;
        if (last > first && bytes[last - 1] == '\r') --last;
        while (first < last && (bytes[first] == ' ' || bytes[first] == '\t')) ++first;
        while (last > first && (bytes[last - 1] == ' ' || bytes[last - 1] == '\t')) --last;
        if (first == last) continue;
        auto separator = first;
        while (separator < last && bytes[separator] != '=') ++separator;
        if (separator == last) return ControlResult::InvalidConfig;
        auto keyEnd = separator, value = separator + 1;
        while (keyEnd > first && (bytes[keyEnd - 1] == ' ' || bytes[keyEnd - 1] == '\t')) --keyEnd;
        while (value < last && (bytes[value] == ' ' || bytes[value] == '\t')) ++value;
        unsigned field{}; bool valid{};
        if (Equal(bytes + first, keyEnd - first, "schema")) {
            field = 1; valid = Equal(bytes + value, last - value, "1");
        } else if (Equal(bytes + first, keyEnd - first, "permission")) {
            field = 2;
            parsed.enabled = Equal(bytes + value, last - value, "training-finish-recreate");
            valid = parsed.enabled || Equal(bytes + value, last - value, "disabled");
        } else if (Equal(bytes + first, keyEnd - first, "training_root")) {
            field = 4; valid = Equal(bytes + value, last - value, "E:\\rs2v_trainingsrv");
        } else if (Equal(bytes + first, keyEnd - first, "operator_sid")) {
            field = 8; none = Equal(bytes + value, last - value, "none");
            valid = none || ParseSid(bytes + value, last - value, &parsed);
        }
        if (!field || !valid || (fields & field)) return ControlResult::InvalidConfig;
        fields |= field;
    }
    if (fields != 15 || (parsed.enabled && none)) return ControlResult::InvalidConfig;
    *output = parsed;
    return parsed.enabled ? ControlResult::Ready : ControlResult::Disabled;
}
ControlResult ParseControlRequest(const char* bytes, std::size_t size,
    const ControlRequest& identity, ControlRequest* output) noexcept {
    if (output) *output = {};
    if (!bytes || !size || size > kControlFileBytes || !output || !ValidIdentity(identity))
        return ControlResult::InvalidRequest;
    Json json{bytes, size, 0}; unsigned fields{};
    if (!json.Take('{')) return ControlResult::InvalidRequest;
    for (;;) {
        char key[32]{}, value[184]{}; DWORD number{}; unsigned field{}; bool valid{};
        if (!json.String(key, std::size(key)) || !json.Take(':')) return ControlResult::InvalidRequest;
        if (std::strcmp(key, "schema") == 0) { field = 1; valid = json.Number(&number) && number == 1; }
        else if (std::strcmp(key, "action") == 0) {
            field = 2; valid = json.String(value, std::size(value)) && std::strcmp(value, "finish-recreate") == 0;
        } else if (std::strcmp(key, "pid") == 0) { field = 4; valid = json.Number(&number) && number == identity.pid; }
        else if (std::strcmp(key, "run_id") == 0) {
            field = 8; valid = json.String(value, std::size(value)) && std::strlen(value) == 32;
            if (valid) for (std::size_t i = 0; i < 16; ++i) {
                constexpr char hex[] = "0123456789abcdef";
                valid &= value[i * 2] == hex[identity.runId[i] >> 4] && value[i * 2 + 1] == hex[identity.runId[i] & 15];
            }
        } else if (std::strcmp(key, "training_root") == 0) {
            field = 16; valid = json.String(value, std::size(value)) && std::strcmp(value, "E:\\rs2v_trainingsrv") == 0;
        }
        if (!field || !valid || (fields & field)) return ControlResult::InvalidRequest;
        fields |= field;
        json.Space();
        if (json.cursor < size && json.bytes[json.cursor] == '}') { ++json.cursor; break; }
        if (!json.Take(',')) return ControlResult::InvalidRequest;
    }
    json.Space();
    if (fields != 31 || json.cursor != size) return ControlResult::InvalidRequest;
    *output = identity;
    return ControlResult::Ready;
}
ControlResult InitializeControl(ControlState& state, const wchar_t* executableDirectory,
    DWORD pid, const BYTE (&runId)[16], DWORD* error) noexcept {
    DWORD localError = ERROR_SUCCESS;
    if (error) *error = ERROR_SUCCESS;
    if (state.enabled || state.started || state.result != static_cast<LONG>(ControlResult::Uninitialized)) {
        if (error) *error = ERROR_INVALID_STATE; return ControlResult::InvalidIdentity;
    }
    state.identity.pid = pid; std::memcpy(state.identity.runId, runId, sizeof(runId));
    ControlResult result = ControlResult::InvalidIdentity;
    wchar_t configPath[kControlPathBytes]{};
    constexpr wchar_t configLeaf[] = L"RS2LeechRecovery.ini";
    if (!ValidIdentity(state.identity)) localError = ERROR_INVALID_DATA;
    else if (!executableDirectory || !AppendPathLeaf(executableDirectory, kControlPathBytes,
            configLeaf, std::size(configLeaf), configPath, std::size(configPath), &localError))
        result = ControlResult::InvalidPath;
    else if (!AdministratorIdentity(&state.security, &localError)) result = ControlResult::SecurityRejected;
    else {
        char bytes[kControlFileBytes]{}; DWORD count{}; ControlConfig config{};
        // INI is operational opt-in only; it cannot authorize an arbitrary
        // caller. Actual process/client SID equality authenticates the command.
        result = ReadBounded(configPath, state.security, true, bytes, &count,
            state.configAcl, std::size(state.configAcl), &localError, false);
        if (result == ControlResult::Ready) result = ParseControlConfig(bytes, count, &config);
        if (result == ControlResult::Ready) {
            if (CompareStringOrdinal(executableDirectory, -1, kTrainingExecutableDirectory, -1, TRUE) != CSTR_EQUAL) {
                result = ControlResult::InvalidPath; localError = ERROR_INVALID_NAME;
            } else if (!state.security.administratorSidBytes) {
                result = ControlResult::SecurityRejected; localError = ERROR_ACCESS_DENIED;
            } else if (!SidEqual(config.operatorSid, state.security.administratorSid)) {
                result = ControlResult::InvalidIdentity; localError = ERROR_ACCESS_DENIED;
            } else {
                state.security.operatorSidBytes = config.operatorSidBytes;
                std::memcpy(state.security.operatorSid, config.operatorSid, sizeof(config.operatorSid));
                constexpr const wchar_t* paths[] = { L"E:\\", kTrainingRoot,
                    L"E:\\rs2v_trainingsrv\\Binaries", kTrainingExecutableDirectory };
                for (std::size_t i = 0; i < std::size(paths) && result == ControlResult::Ready; ++i) {
                    auto file = CreateFileW(paths[i], FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                    if (file == INVALID_HANDLE_VALUE) { result = ControlResult::InvalidPath; localError = GetLastError(); break; }
                    state.directories[i] = file;
                    DWORD ignored{};
                    if (!FileMetadata(file, paths[i], true, &ignored, &localError)) result = ControlResult::InvalidPath;
                    // Pin exact existing paths against replacement, but their
                    // inherited writer grants do not authorize pipe commands.
                }
                if (result == ControlResult::Ready) {
                    result = PreparePipe(state, &localError);
                    if (result == ControlResult::Ready) state.enabled = true;
                }
            }
        }
    }
    if (result != ControlResult::Ready) CloseDirectories(state);
    state.error = localError;
    InterlockedExchange(&state.result, static_cast<LONG>(result));
    if (error) *error = localError;
    return result;
}
bool StartControl(ControlState& state, DWORD* error) noexcept {
    if (error) *error = ERROR_SUCCESS;
    if (!state.enabled || InterlockedCompareExchange(&state.result, 0, 0) != static_cast<LONG>(ControlResult::Ready) ||
        InterlockedCompareExchange(&state.stop, 0, 0) || InterlockedCompareExchange(&state.started, 1, 0)) {
        if (error) *error = ERROR_INVALID_STATE;
        return false;
    }
    state.thread = CreateThread(nullptr, 0, Worker, &state, 0, nullptr);
    if (!state.thread) {
        state.error = GetLastError(); state.enabled = false; CloseDirectories(state);
        InterlockedExchange(&state.result, static_cast<LONG>(ControlResult::WorkerFailure));
        if (error) *error = state.error;
        return false;
    }
    // Thread and pinned directories deliberately remain process-resident. A
    // stop signal never frees storage while the worker could still be reading.
    return true;
}
void StopControl(ControlState& state) noexcept {
    InterlockedExchange(&state.stop, 1);
    if (state.stopEvent) SetEvent(state.stopEvent);
}
bool ReadLatchedControl(const ControlState& state, ControlRequest* output) noexcept {
    if (output) *output = {};
    if (!output || !InterlockedCompareExchange(const_cast<volatile LONG*>(&state.latched), 0, 0)) return false;
    *output = state.request;
    return true;
}
#ifdef RS2_REPORTING_TESTING
ControlResult PrepareControlPipeForTesting(ControlState& state, DWORD* error) noexcept {
    if (!error || !ValidIdentity(state.identity)) return ControlResult::InvalidIdentity;
    return PreparePipe(state, error);
}
bool ControlPeerMatchesForTesting(const ControlSecurity& security, PSID sid) noexcept {
    return PeerMatches(security, sid);
}
ControlResult ReadControlConfigForTesting(const wchar_t* path, const ControlSecurity& security,
    ControlConfig* output, DWORD* error) noexcept {
    if (!path || !output || !error) return ControlResult::InvalidConfig;
    char bytes[kControlFileBytes]{}; DWORD count{}; wchar_t observed[kControlAclCharacters]{};
    const auto read = ReadBounded(path, security, true, bytes, &count,
        observed, std::size(observed), error, false);
    return read == ControlResult::Ready ? ParseControlConfig(bytes, count, output) : read;
}
bool ValidateControlSecurityForTesting(PSECURITY_DESCRIPTOR descriptor,
    const ControlSecurity& security, bool permissionFile) noexcept {
    return ValidateSecurity(descriptor, security, permissionFile);
}
ControlResult ReadControlRequestForTesting(const wchar_t* path, const ControlSecurity& security,
    const ControlRequest& identity, ControlRequest* output, wchar_t* acl, std::size_t capacity,
    DWORD* error) noexcept {
    if (output) *output = {};
    if (!path || !output || !error) return ControlResult::InvalidRequest;
    char bytes[kControlFileBytes]{}; DWORD count{};
    const auto result = ReadBounded(path, security, false, bytes, &count, acl, capacity, error);
    return result == ControlResult::Ready ? ParseControlRequest(bytes, count, identity, output) : result;
}
#endif
} // namespace rs2fix::recovery
