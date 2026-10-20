#include "companion/leech_recovery_control.h"
#include "test_framework.h"
#include <sddl.h>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <string>

namespace rs2fix::testcases {
namespace {
using namespace recovery;
ControlRequest Identity() noexcept {
    ControlRequest identity{}; identity.pid = 73;
    for (BYTE i = 0; i < 16; ++i) identity.runId[i] = i;
    return identity;
}
std::string Request() {
    return "{\"schema\":1,\"action\":\"finish-recreate\",\"pid\":73,"
        "\"run_id\":\"000102030405060708090a0b0c0d0e0f\",\"training_root\":\"E:\\\\rs2v_trainingsrv\"}";
}
void Parsers() {
    ControlConfig config{};
    const std::string disabled = "schema=1\npermission=disabled\ntraining_root=E:\\rs2v_trainingsrv\noperator_sid=none\n";
    const std::string enabled = "schema=1\npermission=training-finish-recreate\ntraining_root=E:\\rs2v_trainingsrv\noperator_sid=S-1-5-21-1-2-3-1001\n";
    RS2_CHECK(ParseControlConfig(disabled.data(), disabled.size(), &config) == ControlResult::Disabled);
    RS2_CHECK(!config.enabled && !config.operatorSidBytes);
    RS2_CHECK(ParseControlConfig(enabled.data(), enabled.size(), &config) == ControlResult::Ready);
    RS2_CHECK(config.enabled && config.operatorSidBytes);
    const std::string invalid[] = {
        disabled + "mode=repair\n", enabled + "schema=1\n",
        "schema=1\npermission=repair\ntraining_root=E:\\rs2v_trainingsrv\noperator_sid=none\n",
        "schema=1\npermission=training-finish-recreate\ntraining_root=E:\\rs2v_trainingsrv\noperator_sid=none\n",
        "schema=1\npermission=training-finish-recreate\ntraining_root=E:\\rs2v_trainingsrv\noperator_sid=S-1-1-0\n",
        "schema=1\npermission=disabled\ntraining_root=E:\\rs2v_publicsrv\noperator_sid=none\n"
    };
    for (const auto& text : invalid) {
        RS2_CHECK(ParseControlConfig(text.data(), text.size(), &config) == ControlResult::InvalidConfig);
        RS2_CHECK(!config.enabled && !config.operatorSidBytes);
    }
    const auto identity = Identity(); ControlRequest parsed{};
    const auto request = Request();
    RS2_CHECK(ParseControlRequest(request.data(), request.size(), identity, &parsed) == ControlResult::Ready);
    RS2_CHECK(std::memcmp(&parsed, &identity, sizeof(identity)) == 0);
    for (unsigned failure = 0; failure < 12; ++failure) {
        auto text = request;
        switch (failure) {
        case 0: text.replace(text.find("\"pid\":73"), 8, "\"pid\":74"); break;
        case 1: text.replace(text.find("000102"), 6, "100102"); break;
        case 2: text.insert(text.size() - 1, ",\"schema\":1"); break;
        case 3: text.insert(text.size() - 1, ",\"mode\":\"repair\""); break;
        case 4: text.replace(text.find("finish-recreate"), 15, "finish-only"); break;
        case 5: text.replace(text.find("rs2v_trainingsrv"), 16, "rs2v_publicsrv"); break;
        case 6: text.replace(text.find("\"pid\":73"), 8, "\"pid\":073"); break;
        case 7: text.replace(text.find("\"pid\":73"), 8, "\"pid\":4294967296"); break;
        case 8: text.replace(text.find("\"pid\":73"), 8, "\"pid\":73.0"); break;
        case 9: text += "{}"; break;
        case 10: text.insert(text.size() - 1, ","); break;
        case 11: text.resize(513, ' '); break;
        }
        RS2_CHECK(ParseControlRequest(text.data(), text.size(), identity, &parsed) == ControlResult::InvalidRequest);
        RS2_CHECK(!parsed.pid);
    }
    auto stale = identity; stale.pid = 74;
    RS2_CHECK(ParseControlRequest(request.data(), request.size(), stale, &parsed) == ControlResult::InvalidRequest);
    ControlState disabledState{}; DWORD error{};
    RS2_CHECK(!StartControl(disabledState, &error));
    RS2_CHECK(error == ERROR_INVALID_STATE && !disabledState.started && !disabledState.thread && !disabledState.latched);
}
bool Descriptor(const wchar_t* sddl, PSECURITY_DESCRIPTOR* descriptor) {
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, descriptor, nullptr) != FALSE;
}
void Security() {
    const std::string enabled = "schema=1\npermission=training-finish-recreate\ntraining_root=E:\\rs2v_trainingsrv\noperator_sid=S-1-5-21-1-2-3-1001\n";
    ControlConfig config{};
    RS2_CHECK(ParseControlConfig(enabled.data(), enabled.size(), &config) == ControlResult::Ready);
    ControlSecurity policy{}; policy.operatorSidBytes = config.operatorSidBytes;
    std::memcpy(policy.operatorSid, config.operatorSid, sizeof(config.operatorSid));
    struct Case { const wchar_t* sddl; bool permission; bool valid; };
    const Case cases[] = {
        {L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)", true, true},
        {L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FW;;;BU)", true, false},
        {L"O:BAG:BAD:P(A;;FA;;;BA)(A;;WD;;;AU)", false, false},
        {L"O:BAG:BAD:P(A;IOCI;FW;;;BU)(A;;FA;;;BA)", false, false},
        {L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)", false, true},
        {L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)", true, false},
        {L"O:S-1-5-21-1-2-3-1001G:BAD:P(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)", false, true},
        {L"O:BUG:BAD:P(A;;FA;;;BA)(A;;FR;;;BU)", false, false},
        {L"O:BAG:BAD:NO_ACCESS_CONTROL", false, false},
        {L"O:BAG:BAD:P(D;;FW;;;BU)(A;;FA;;;BA)(A;;FR;;;BU)", false, true}
    };
    for (const auto& item : cases) {
        PSECURITY_DESCRIPTOR descriptor{};
        RS2_CHECK(Descriptor(item.sddl, &descriptor));
        if (descriptor) {
            RS2_CHECK(ValidateControlSecurityForTesting(descriptor, policy, item.permission) == item.valid);
            LocalFree(descriptor);
        }
    }
}
bool WriteFixture(const wchar_t* path, const std::string& bytes, PSECURITY_DESCRIPTOR descriptor) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    const auto file = CreateFileW(path, GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written{};
    const bool okay = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
    RS2_CHECK(okay); RS2_CHECK(CloseHandle(file));
    return okay;
}
void FilesAndWorker() {
    // Every handle targets a disposable TEMP fixture, never the training tree.
    wchar_t temporary[MAX_PATH]{}, unique[MAX_PATH]{};
    RS2_CHECK(GetTempPathW(static_cast<DWORD>(std::size(temporary)), temporary));
    RS2_CHECK(GetTempFileNameW(temporary, L"lrc", 0, unique));
    RS2_CHECK(DeleteFileW(unique)); RS2_CHECK(CreateDirectoryW(unique, nullptr));
    HANDLE token{}; RS2_CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    alignas(TOKEN_USER) BYTE userBytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]{}; DWORD returned{};
    RS2_CHECK(GetTokenInformation(token, TokenUser, userBytes, sizeof(userBytes), &returned));
    RS2_CHECK(CloseHandle(token));
    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBytes);
    ControlSecurity policy{};
    policy.operatorSidBytes = GetLengthSid(user->User.Sid);
    RS2_CHECK(CopySid(sizeof(policy.operatorSid), policy.operatorSid, user->User.Sid));
    wchar_t* sid{}; RS2_CHECK(ConvertSidToStringSidW(user->User.Sid, &sid));
    if (!sid) return;
    const std::wstring sddl = std::wstring(L"O:") + sid + L"G:BAD:P(A;;FA;;;" + sid + L")(A;;FA;;;BA)(A;;FA;;;SY)";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor{}; RS2_CHECK(Descriptor(sddl.c_str(), &descriptor));
    if (!descriptor) return;
    PSECURITY_DESCRIPTOR writableDescriptor{};
    const auto writableSddl = sddl + L"(A;;FW;;;BU)";
    RS2_CHECK(Descriptor(writableSddl.c_str(), &writableDescriptor));
    const auto identity = Identity();
    auto* acl = new wchar_t[kControlAclCharacters]{};
    auto* missingPermission = new ControlState{}; DWORD permissionError{};
    RS2_CHECK(InitializeControl(*missingPermission, unique, identity.pid, identity.runId, &permissionError) == ControlResult::Missing);
    RS2_CHECK(!missingPermission->enabled && !missingPermission->started && !missingPermission->thread &&
        !missingPermission->requestPath[0] && permissionError == ERROR_FILE_NOT_FOUND);
    delete missingPermission;
    for (unsigned failure = 0; failure < 7; ++failure) {
        const auto path = std::wstring(unique) + L"\\case" + std::to_wstring(failure) + L".json";
        auto bytes = failure == 1 ? std::string(513, ' ') : Request();
        if (failure == 2) bytes.replace(bytes.find("000102"), 6, "100102");
        RS2_CHECK(WriteFixture(path.c_str(), bytes, failure == 5 ? writableDescriptor : descriptor));
        const auto alias = std::wstring(unique) + L"\\hardlink.json";
        if (failure == 3) RS2_CHECK(CreateHardLinkW(alias.c_str(), path.c_str(), nullptr));
        const auto writer = failure == 6 ? CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) : INVALID_HANDLE_VALUE;
        if (failure == 6) RS2_CHECK(writer != INVALID_HANDLE_VALUE);
        const auto observedPath = failure == 4 ? std::wstring(unique) + L"\\.\\case4.json" : path;
        ControlRequest parsed{}; DWORD error{};
        const auto result = ReadControlRequestForTesting(observedPath.c_str(), policy, identity, &parsed, acl, kControlAclCharacters, &error);
        RS2_CHECK(result == (failure == 0 ? ControlResult::Ready : failure == 2 ? ControlResult::InvalidRequest :
            failure == 5 ? ControlResult::SecurityRejected : failure == 6 ? ControlResult::PendingWrite : ControlResult::InvalidPath));
        if (failure == 0) RS2_CHECK(acl[0] != L'\0' && parsed.pid == identity.pid);
        if (failure == 5) RS2_CHECK(acl[0] != L'\0' && error == ERROR_ACCESS_DENIED && !parsed.pid);
        if (failure == 3) RS2_CHECK(DeleteFileW(alias.c_str()));
        if (failure == 6) RS2_CHECK(CloseHandle(writer));
        RS2_CHECK(DeleteFileW(path.c_str()));
    }
    ControlRequest parsed{}; DWORD error{};
    RS2_CHECK(ReadControlRequestForTesting(unique, policy, identity, &parsed, acl, kControlAclCharacters, &error) != ControlResult::Ready);
    // The real configuration reader accepts the operator's ordinary writable
    // file grants. Configuration alone is not the pipe command authority.
    const auto permissionPath = std::wstring(unique) + L"\\permission.ini";
    const std::string permission = "schema=1\npermission=training-finish-recreate\n"
        "training_root=E:\\rs2v_trainingsrv\noperator_sid=S-1-5-21-1-2-3-1001\n";
    RS2_CHECK(WriteFixture(permissionPath.c_str(), permission, writableDescriptor));
    ControlConfig loaded{};
    RS2_CHECK(ReadControlConfigForTesting(permissionPath.c_str(), policy, &loaded, &error) == ControlResult::Ready);
    RS2_CHECK(loaded.enabled && loaded.operatorSidBytes);
    RS2_CHECK(DeleteFileW(permissionPath.c_str()));
    // Real Windows pipe, peer-token check and joined worker, never VNGame.
    for (unsigned scenario = 0; scenario < 6; ++scenario) {
        auto* state = new ControlState{};
        state->identity = identity; state->identity.pid = GetCurrentProcessId();
        state->identity.runId[15] = static_cast<BYTE>(scenario);
        state->security = policy;
        RS2_CHECK(PrepareControlPipeForTesting(*state, &error) == ControlResult::Ready);
        // Another server cannot replace this process/run endpoint.
        auto* collision = new ControlState{};
        collision->identity = state->identity; collision->security = policy;
        RS2_CHECK(PrepareControlPipeForTesting(*collision, &error) == ControlResult::EndpointUnavailable);
        RS2_CHECK(!collision->pipe);
        delete collision;
        RS2_CHECK(ControlPeerMatchesForTesting(policy, policy.operatorSid));
        BYTE systemSid[SECURITY_MAX_SID_SIZE]{}; DWORD systemSidBytes = sizeof(systemSid);
        RS2_CHECK(CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSidBytes));
        if (!EqualSid(systemSid, policy.operatorSid)) RS2_CHECK(!ControlPeerMatchesForTesting(policy, systemSid));
        if (scenario == 5) {
            state->security.operatorSidBytes = systemSidBytes;
            RS2_CHECK(CopySid(sizeof(state->security.operatorSid), state->security.operatorSid, systemSid));
        }
        state->enabled = true; state->result = static_cast<LONG>(ControlResult::Ready);
        RS2_CHECK(StartControl(*state, &error));
        HANDLE client = INVALID_HANDLE_VALUE;
        if (scenario != 3) {
            client = CreateFileW(state->requestPath, FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
                READ_CONTROL | SYNCHRONIZE, 0, nullptr, OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
            RS2_CHECK(client != INVALID_HANDLE_VALUE);
            ULONG server{};
            RS2_CHECK(GetNamedPipeServerProcessId(client, &server) && server == GetCurrentProcessId());
        }
        if (scenario == 3 || scenario == 4) StopControl(*state); // blocked connect/read
        else {
            char run[33]{}; constexpr char hex[] = "0123456789abcdef";
            for (unsigned i = 0; i < 16; ++i) { run[i*2]=hex[state->identity.runId[i]>>4]; run[i*2+1]=hex[state->identity.runId[i]&15]; }
            auto bytes = std::string("{\"schema\":1,\"action\":\"finish-recreate\",\"pid\":") +
                std::to_string(GetCurrentProcessId()) + ",\"run_id\":\"" + run +
                "\",\"training_root\":\"E:\\\\rs2v_trainingsrv\"}";
            if (scenario == 1) bytes.replace(bytes.find("000102"), 6, "100102");
            if (scenario == 2) bytes.resize(513, ' ');
            DWORD written{};
            RS2_CHECK(WriteFile(client, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size());
            if (scenario == 0) { // actual helper closes immediately after WriteFile
                RS2_CHECK(CloseHandle(client)); client = INVALID_HANDLE_VALUE;
            }
        }
        RS2_CHECK(state->thread && WaitForSingleObject(state->thread, 5000) == WAIT_OBJECT_0);
        const auto expected = scenario == 0 ? ControlResult::Latched : scenario == 1 || scenario == 2 ?
            ControlResult::InvalidRequest : scenario == 5 ? ControlResult::SecurityRejected : ControlResult::Stopped;
        RS2_CHECK(ReadLatchedControl(*state, &parsed) == (scenario == 0));
        RS2_CHECK(state->result == static_cast<LONG>(expected));
        RS2_CHECK(!StartControl(*state, &error));
        RS2_CHECK(ReadLatchedControl(*state, &parsed) == (scenario == 0));
        StopControl(*state);
        if (client != INVALID_HANDLE_VALUE) RS2_CHECK(CloseHandle(client));
        RS2_CHECK(CloseHandle(state->thread));
        RS2_CHECK(CloseHandle(state->ioEvent)); RS2_CHECK(CloseHandle(state->stopEvent));
        delete state; // Joined fixture worker only; production storage is resident.
    }
    delete[] acl; LocalFree(writableDescriptor); LocalFree(descriptor); RS2_CHECK(RemoveDirectoryW(unique));
}
} // namespace
void RunLeechRecoveryControlTests() { Parsers(); Security(); FilesAndWorker(); }
} // namespace rs2fix::testcases
