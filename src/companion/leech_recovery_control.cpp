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
bool ClaimControl(ControlState&, RequestOrigin) noexcept;
constexpr DWORD kMutation = DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA |
    FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
constexpr DWORD kKnownAccess = FILE_ALL_ACCESS | GENERIC_ALL | GENERIC_READ |
    GENERIC_WRITE | GENERIC_EXECUTE;
bool Equal(const char* bytes, std::size_t count, const char* expected) noexcept {
    return std::strlen(expected) == count && std::memcmp(bytes, expected, count) == 0;
}
bool PilotRoot(const wchar_t* root) noexcept {
    if(!root) return false;
    std::size_t length{};
    while(length<kControlRootCharacters && root[length]) ++length;
    if(length<4 || length>=kControlRootCharacters || root[1]!=L':' || root[2]!=L'\\' ||
        !((root[0]>=L'A' && root[0]<=L'Z') || (root[0]>=L'a' && root[0]<=L'z'))) return false;
    for(std::size_t i=3;i<length;++i) {
        const auto c=root[i];
        if(!((c>=L'A' && c<=L'Z') || (c>=L'a' && c<=L'z') || (c>=L'0' && c<=L'9') || c==L'_' || c==L'-')) return false;
    }
    return true;
}
bool AsciiRoot(const char* bytes,std::size_t count,wchar_t (&root)[kControlRootCharacters]) noexcept {
    if(!bytes || count>=std::size(root)) return false;
    for(std::size_t i=0;i<count;++i) root[i]=static_cast<unsigned char>(bytes[i]);
    root[count]=L'\0';return PilotRoot(root);
}
bool ValidScope(const ControlScope& scope) noexcept {
    return PilotRoot(scope.serverRoot) && (scope.schema==2 ||
        (scope.schema==1 && std::wcscmp(scope.serverRoot,kTrainingRoot)==0));
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
    if (!ResetEvent(state.ioEvent)) { state.error = GetLastError(); return ControlResult::WorkerFailure; }
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
    const auto result = ParseControlRequest(bytes, count, state.identity, &request, &state.scope);
    if (result != ControlResult::Ready) { state.error = ERROR_INVALID_DATA; return result; }
    // ParseControlRequest returned the immutable armed identity. Claiming just
    // the origin publishes everything the owner needs in one atomic operation.
    // A console winner (once explicitly enabled) cannot be overwritten here.
    if (ClaimControl(state, RequestOrigin::Pipe)) return ControlResult::Latched;
    if (InterlockedCompareExchange(&state.stop, 0, 0)) return ControlResult::Stopped;
    // The owner may release a preflight claim immediately after our CAS lost.
    // A second latch read must not turn that valid concurrent request into a
    // malformed-message failure which permanently closes the shared endpoint.
    if (state.scope.schema == 2) return ControlResult::AlreadyClaimed;
    return InterlockedCompareExchange(&state.latched, 0, 0) ?
        ControlResult::AlreadyClaimed : ControlResult::InvalidRequest;
}
DWORD WINAPI Worker(void* parameter) noexcept {
    auto& state = *static_cast<ControlState*>(parameter);
    ControlResult result{};
    do {
        result = ReceivePipe(state);
        const bool disconnected = DisconnectNamedPipe(state.pipe) != FALSE;
        if (!disconnected && GetLastError() != ERROR_PIPE_NOT_CONNECTED) {
            state.error = GetLastError(); result = ControlResult::WorkerFailure; break;
        }
        // Schema2 permits later EXPLICIT requests after an owner-qualified
        // preflight rejection. Every connection is authenticated anew. The
        // common CAS still admits only one request, and a native recipe never
        // releases its claim. Legacy training remains one-shot.
        if (state.scope.schema != 2 ||
            (result != ControlResult::Latched && result != ControlResult::AlreadyClaimed)) break;
    } while (!InterlockedCompareExchange(&state.stop, 0, 0));
    if (InterlockedCompareExchange(&state.stop, 0, 0)) result = ControlResult::Stopped;
    CloseHandle(state.pipe);
    InterlockedExchange(&state.result, static_cast<LONG>(result));
    return 0;
}
} // namespace

ControlResult ParseControlConfig(const char* bytes, std::size_t size, ControlConfig* output) noexcept {
    if (output) *output = {};
    if (!bytes || !size || size > kControlFileBytes || !output) return ControlResult::InvalidConfig;
    ControlConfig parsed{}; unsigned fields{},permission{}; bool none{};
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
            field = 1;
            if(Equal(bytes+value,last-value,"1")) parsed.scope.schema=1;
            else if(Equal(bytes+value,last-value,"2")) parsed.scope.schema=2;
            valid=parsed.scope.schema!=0;
        } else if (Equal(bytes + first, keyEnd - first, "permission")) {
            field = 2;
            if(Equal(bytes+value,last-value,"training-finish-recreate")) permission=1;
            else if(Equal(bytes+value,last-value,"manual-pilot-finish-recreate")) permission=2;
            parsed.enabled=permission!=0;
            valid=parsed.enabled || Equal(bytes+value,last-value,"disabled");
        } else if (Equal(bytes + first, keyEnd - first, "training_root")) {
            field = 4; valid = Equal(bytes + value, last - value, "E:\\rs2v_trainingsrv") &&
                AsciiRoot(bytes+value,last-value,parsed.scope.serverRoot);
        } else if (Equal(bytes + first, keyEnd - first, "server_root")) {
            field = 16; valid = AsciiRoot(bytes+value,last-value,parsed.scope.serverRoot);
        } else if (Equal(bytes + first, keyEnd - first, "operator_sid")) {
            field = 8; none = Equal(bytes + value, last - value, "none");
            valid = none || ParseSid(bytes + value, last - value, &parsed);
        } else if (Equal(bytes + first, keyEnd - first, "console_trigger")) {
            field = 32;
            parsed.consoleRequested = Equal(bytes + value, last - value, "server-admin");
            valid = parsed.consoleRequested || Equal(bytes + value, last - value, "disabled");
        }
        if (!field || !valid || (fields & field)) return ControlResult::InvalidConfig;
        fields |= field;
    }
    if(!ValidScope(parsed.scope) || (fields & ~32u)!=(parsed.scope.schema==1 ? 15u : 27u) ||
        ((fields & 32u) && parsed.scope.schema!=2) ||
        (parsed.enabled && (none || permission!=parsed.scope.schema))) return ControlResult::InvalidConfig;
    *output = parsed;
    return parsed.enabled ? ControlResult::Ready : ControlResult::Disabled;
}
ControlResult ParseControlRequest(const char* bytes, std::size_t size,
    const ControlRequest& identity, ControlRequest* output, const ControlScope* scope) noexcept {
    if (output) *output = {};
    const auto& expected=scope?*scope:kTrainingControlScope;
    if (!bytes || !size || size > kControlFileBytes || !output || !ValidIdentity(identity) || !ValidScope(expected))
        return ControlResult::InvalidRequest;
    Json json{bytes, size, 0}; unsigned fields{};
    if (!json.Take('{')) return ControlResult::InvalidRequest;
    for (;;) {
        char key[32]{}, value[184]{}; DWORD number{}; unsigned field{}; bool valid{};
        if (!json.String(key, std::size(key)) || !json.Take(':')) return ControlResult::InvalidRequest;
        if (std::strcmp(key, "schema") == 0) { field = 1; valid = json.Number(&number) && number == expected.schema; }
        else if (std::strcmp(key, "action") == 0) {
            field = 2; valid = json.String(value, std::size(value)) && std::strcmp(value, "finish-recreate") == 0;
        } else if (std::strcmp(key, "pid") == 0) { field = 4; valid = json.Number(&number) && number == identity.pid; }
        else if (std::strcmp(key, "run_id") == 0) {
            field = 8; valid = json.String(value, std::size(value)) && std::strlen(value) == 32;
            if (valid) for (std::size_t i = 0; i < 16; ++i) {
                constexpr char hex[] = "0123456789abcdef";
                valid &= value[i * 2] == hex[identity.runId[i] >> 4] && value[i * 2 + 1] == hex[identity.runId[i] & 15];
            }
        } else if (std::strcmp(key, expected.schema==1 ? "training_root" : "server_root") == 0) {
            wchar_t root[kControlRootCharacters]{};
            field=16;valid=json.String(value,std::size(value)) && AsciiRoot(value,std::strlen(value),root) &&
                (expected.schema==1 ? std::wcscmp(root,expected.serverRoot)==0 :
                    CompareStringOrdinal(root,-1,expected.serverRoot,-1,TRUE)==CSTR_EQUAL);
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
    DWORD pid, const BYTE (&runId)[16], DWORD* error, bool allowManualPilot) noexcept {
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
        // Deliberately trusted-local configuration, including console opt-in.
        // Pipe peers authenticate the Windows SID; console requests instead
        // trust the game's existing WebAdmin authorization. File ownership is
        // not proof of authorship when inherited grants permit byte writes.
        result = ReadBounded(configPath, state.security, true, bytes, &count,
            state.configAcl, std::size(state.configAcl), &localError, false);
        if (result == ControlResult::Ready) result = ParseControlConfig(bytes, count, &config);
        if (result == ControlResult::Ready) {
            wchar_t paths[4][kControlPathBytes]{};
            paths[0][0]=config.scope.serverRoot[0];paths[0][1]=L':';paths[0][2]=L'\\';
            const bool pathsReady=ValidScope(config.scope) &&
                swprintf_s(paths[1],L"%ls",config.scope.serverRoot)>0 &&
                swprintf_s(paths[2],L"%ls\\Binaries",config.scope.serverRoot)>0 &&
                swprintf_s(paths[3],L"%ls\\Binaries\\Win64",config.scope.serverRoot)>0;
            if(config.scope.schema==2 && !allowManualPilot) {
                result=ControlResult::InvalidConfig;localError=ERROR_INVALID_STATE;
            } else if(!pathsReady || GetDriveTypeW(paths[0])!=DRIVE_FIXED ||
                CompareStringOrdinal(executableDirectory,-1,paths[3],-1,TRUE)!=CSTR_EQUAL) {
                result = ControlResult::InvalidPath; localError = ERROR_INVALID_NAME;
            } else if (!state.security.administratorSidBytes) {
                result = ControlResult::SecurityRejected; localError = ERROR_ACCESS_DENIED;
            } else if (!SidEqual(config.operatorSid, state.security.administratorSid)) {
                result = ControlResult::InvalidIdentity; localError = ERROR_ACCESS_DENIED;
            } else {
                state.security.operatorSidBytes = config.operatorSidBytes;
                std::memcpy(state.security.operatorSid, config.operatorSid, sizeof(config.operatorSid));
                state.scope=config.scope;
                state.consoleRequested=config.consoleRequested;
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
namespace {
bool ClaimControl(ControlState& state, RequestOrigin origin) noexcept {
    if (!state.enabled || InterlockedCompareExchange(&state.started, 0, 0) != 1 ||
        InterlockedCompareExchange(&state.stop, 0, 0) ||
        InterlockedCompareExchange(&state.result, 0, 0) != static_cast<LONG>(ControlResult::Ready) ||
        !ValidIdentity(state.identity) || !ValidScope(state.scope) ||
        (origin != RequestOrigin::Pipe &&
            (origin != RequestOrigin::ServerAdminConsole || !state.consoleRequested ||
                ReadConsoleRegistration(state)!=ConsoleRegistration::Available || state.scope.schema!=2))) return false;
    return InterlockedCompareExchange(&state.latched, static_cast<LONG>(origin), 0) == 0;
}
} // namespace
bool ClaimConsoleControlRequest(ControlState& state) noexcept {
    return ClaimControl(state, RequestOrigin::ServerAdminConsole);
}
bool ReleasePreflightClaim(ControlState& state) noexcept {
    if (state.scope.schema != 2 || !state.enabled ||
        InterlockedCompareExchange(&state.started, 0, 0) != 1 ||
        InterlockedCompareExchange(&state.stop, 0, 0) ||
        InterlockedCompareExchange(&state.result, 0, 0) != static_cast<LONG>(ControlResult::Ready)) return false;
    const LONG origin = InterlockedCompareExchange(&state.latched, 0, 0);
    return (origin == static_cast<LONG>(RequestOrigin::Pipe) || origin == static_cast<LONG>(RequestOrigin::ServerAdminConsole)) &&
        InterlockedCompareExchange(&state.latched, 0, origin) == origin;
}
ConsoleRegistration ReadConsoleRegistration(const ControlState& state) noexcept {
    return static_cast<ConsoleRegistration>(InterlockedCompareExchange(
        const_cast<volatile LONG*>(&state.consoleRegistration),0,0));
}
bool ReadLatchedControl(const ControlState& state, ControlRequest* output, RequestOrigin* origin) noexcept {
    if (output) *output = {};
    if (origin) *origin = RequestOrigin::None;
    const auto selected = static_cast<RequestOrigin>(InterlockedCompareExchange(
        const_cast<volatile LONG*>(&state.latched), 0, 0));
    if (!output || !ValidIdentity(state.identity) || !ValidScope(state.scope) || (selected != RequestOrigin::Pipe &&
        (selected != RequestOrigin::ServerAdminConsole || !state.consoleRequested ||
            ReadConsoleRegistration(state)!=ConsoleRegistration::Available || state.scope.schema!=2))) return false;
    *output = state.identity;
    if (origin) *origin = selected;
    return true;
}
void ConsoleConfirmation(const BYTE (&runId)[16],
    char (&output)[kConsoleConfirmationCharacters + 1]) noexcept {
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < kConsoleConfirmationCharacters / 2; ++i) {
        output[2 * i] = hex[runId[i] >> 4];
        output[2 * i + 1] = hex[runId[i] & 15];
    }
    output[kConsoleConfirmationCharacters] = 0;
}
ConsoleCommand ParseConsoleCommand(const wchar_t* text, std::size_t count,
    const char (&confirmation)[kConsoleConfirmationCharacters + 1]) noexcept {
    if (!text || !count || count > kConsoleCommandCharacters) return ConsoleCommand::Unrelated;
    auto lower = [](wchar_t c) noexcept { return c >= L'A' && c <= L'Z' ? c + (L'a' - L'A') : c; };
    constexpr wchar_t prefix[] = L"rs2leech";
    std::size_t cursor{};
    while (cursor < count && text[cursor] == L' ') ++cursor;
    for (std::size_t i = 0; i < std::size(prefix) - 1; ++i, ++cursor)
        if (cursor == count || lower(text[cursor]) != prefix[i]) return ConsoleCommand::Unrelated;
    // Do not swallow another command with a shared prefix.
    if (cursor < count && text[cursor] > L' ' && text[cursor] <= L'~') return ConsoleCommand::Unrelated;
    for (std::size_t i = 0; i < count; ++i)
        if (text[i] < L' ' || text[i] > L'~') return ConsoleCommand::Invalid;
    auto word = [&](const wchar_t* expected, std::size_t length) noexcept {
        while (cursor < count && text[cursor] == L' ') ++cursor;
        for (std::size_t i = 0; i < length; ++i, ++cursor)
            if (cursor == count || lower(text[cursor]) != expected[i]) return false;
        return cursor == count || text[cursor] == L' ';
    };
    const auto argument = cursor;
    if (word(L"status", 6)) {
        while (cursor < count && text[cursor] == L' ') ++cursor;
        return cursor == count ? ConsoleCommand::Status : ConsoleCommand::Invalid;
    }
    cursor = argument;
    if (!word(L"recover", 7) || cursor == count || confirmation[kConsoleConfirmationCharacters])
        return ConsoleCommand::Invalid;
    while (cursor < count && text[cursor] == L' ') ++cursor;
    for (std::size_t i = 0; i < kConsoleConfirmationCharacters; ++i, ++cursor) {
        const auto expected = confirmation[i];
        if (!((expected >= '0' && expected <= '9') || (expected >= 'a' && expected <= 'f')) ||
            cursor == count || text[cursor] != static_cast<wchar_t>(expected)) return ConsoleCommand::Invalid;
    }
    while (cursor < count && text[cursor] == L' ') ++cursor;
    return cursor == count ? ConsoleCommand::Recover : ConsoleCommand::Invalid;
}
#ifdef RS2_REPORTING_TESTING
bool ClaimControlForTesting(ControlState& state, RequestOrigin origin) noexcept {
    return ClaimControl(state, origin);
}
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
