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
void PilotParsers() {
    const std::string prefix="schema=2\npermission=manual-pilot-finish-recreate\nserver_root=";
    const std::string suffix="\noperator_sid=S-1-5-21-1-2-3-1001\n";
    const auto enabled=prefix+"E:\\servertwo"+suffix;
    ControlConfig config{};
    RS2_CHECK(ParseControlConfig(enabled.data(),enabled.size(),&config)==ControlResult::Ready);
    RS2_CHECK(config.enabled && config.scope.schema==2 && std::wcscmp(config.scope.serverRoot,L"E:\\servertwo")==0);
    RS2_CHECK(!config.consoleRequested);
    const auto scope=config.scope;const auto identity=Identity();ControlRequest parsed{};
    for(const auto& choice:{std::string("disabled"),std::string("server-admin")}) {
        const auto text=enabled+"console_trigger="+choice+"\n";
        RS2_CHECK(ParseControlConfig(text.data(),text.size(),&config)==ControlResult::Ready);
        RS2_CHECK(config.consoleRequested==(choice=="server-admin"));
    }
    for(const auto& text:{enabled+"console_trigger=enabled\n",
            enabled+"console_trigger=server-admin\nconsole_trigger=disabled\n",
            std::string("schema=1\npermission=training-finish-recreate\ntraining_root=E:\\rs2v_trainingsrv")+
                suffix+"console_trigger=disabled\n"}) {
        RS2_CHECK(ParseControlConfig(text.data(),text.size(),&config)==ControlResult::InvalidConfig);
        RS2_CHECK(!config.enabled && !config.consoleRequested);
    }
    const std::string request="{\"schema\":2,\"action\":\"finish-recreate\",\"pid\":73,"
        "\"run_id\":\"000102030405060708090a0b0c0d0e0f\",\"server_root\":\"E:\\\\servertwo\"}";
    RS2_CHECK(ParseControlRequest(request.data(),request.size(),identity,&parsed,&scope)==ControlResult::Ready);
    RS2_CHECK(ParseControlRequest(request.data(),request.size(),identity,&parsed)==ControlResult::InvalidRequest);
    const auto training=Request();
    RS2_CHECK(ParseControlRequest(training.data(),training.size(),identity,&parsed,&scope)==ControlResult::InvalidRequest);
    auto other=scope;wcscpy_s(other.serverRoot,L"E:\\serverone");
    RS2_CHECK(ParseControlRequest(request.data(),request.size(),identity,&parsed,&other)==ControlResult::InvalidRequest);
    auto wrongSchema=request;wrongSchema.replace(wrongSchema.find("\"schema\":2"),10,"\"schema\":1");
    RS2_CHECK(ParseControlRequest(wrongSchema.data(),wrongSchema.size(),identity,&parsed,&scope)==ControlResult::InvalidRequest);
    auto mixedKey=request;mixedKey.replace(mixedKey.find("server_root"),11,"training_root");
    RS2_CHECK(ParseControlRequest(mixedKey.data(),mixedKey.size(),identity,&parsed,&scope)==ControlResult::InvalidRequest);
    for(const auto* root:{"E:\\","E:server","E:/server","E:\\server\\child","E:\\..","E:\\server.",
            "E:\\server name","\\\\server\\share","\\\\?\\E:\\server","E:\\server~1"}) {
        const auto text=prefix+root+suffix;
        RS2_CHECK(ParseControlConfig(text.data(),text.size(),&config)==ControlResult::InvalidConfig);
        RS2_CHECK(!config.enabled && !config.operatorSidBytes);
    }
    const auto longest=prefix+"E:\\"+std::string(32,'a')+suffix;
    RS2_CHECK(ParseControlConfig(longest.data(),longest.size(),&config)==ControlResult::Ready);
    const auto tooLong=prefix+"E:\\"+std::string(33,'a')+suffix;
    RS2_CHECK(ParseControlConfig(tooLong.data(),tooLong.size(),&config)==ControlResult::InvalidConfig);
    for(const auto& text:{
            std::string("schema=2\npermission=training-finish-recreate\nserver_root=E:\\servertwo")+suffix,
            std::string("schema=1\npermission=manual-pilot-finish-recreate\ntraining_root=E:\\rs2v_trainingsrv")+suffix,
            enabled+"training_root=E:\\rs2v_trainingsrv\n",enabled+"schema=1\n"}) {
        RS2_CHECK(ParseControlConfig(text.data(),text.size(),&config)==ControlResult::InvalidConfig);
        RS2_CHECK(!config.enabled && !config.operatorSidBytes);
    }
    const std::string disabled="schema=2\npermission=disabled\nserver_root=E:\\servertwo\noperator_sid=none\n";
    RS2_CHECK(ParseControlConfig(disabled.data(),disabled.size(),&config)==ControlResult::Disabled);
    RS2_CHECK(!config.enabled && config.scope.schema==2 && !config.operatorSidBytes);
}
void ConsoleParser() {
    const auto identity = Identity();
    char confirmation[kConsoleConfirmationCharacters + 1]{};
    ConsoleConfirmation(identity.runId, confirmation);
    RS2_CHECK(std::strcmp(confirmation, "0001020304050607") == 0);
    struct Case { const wchar_t* text; ConsoleCommand expected; };
    const Case cases[] = {
        {L"rs2leech status", ConsoleCommand::Status},
        {L"  RS2LEECH  STATUS  ", ConsoleCommand::Status},
        {L"rs2leech recover 0001020304050607", ConsoleCommand::Recover},
        {L"RS2LEECH RECOVER 0001020304050607 ", ConsoleCommand::Recover},
        {L"rs2leech", ConsoleCommand::Invalid},
        {L"rs2leech status extra", ConsoleCommand::Invalid},
        {L"rs2leech recover", ConsoleCommand::Invalid},
        {L"rs2leech recover 1001020304050607", ConsoleCommand::Invalid},
        {L"rs2leech recover 000102030405060", ConsoleCommand::Invalid},
        {L"rs2leech recover 0001020304050607 extra", ConsoleCommand::Invalid},
        {L"rs2leech recover 0001020304050607\nquit", ConsoleCommand::Invalid},
        {L"rs2leech\tstatus", ConsoleCommand::Invalid},
        {L"rs2leech st\x00e4tus", ConsoleCommand::Invalid},
        {L"rs2fix status", ConsoleCommand::Unrelated},
        {L"rs2leechother status", ConsoleCommand::Unrelated},
        {L"say rs2leech recover 0001020304050607", ConsoleCommand::Unrelated},
    };
    for (const auto& item : cases)
        RS2_CHECK(ParseConsoleCommand(item.text, std::wcslen(item.text), confirmation) == item.expected);
    // A supplied span is authoritative; no accidental dependence on a trailing
    // NUL or read beyond its end, including embedded-NUL command injection.
    const wchar_t exact[] = {L'r',L's',L'2',L'l',L'e',L'e',L'c',L'h',L' ',L's',L't',L'a',L't',L'u',L's'};
    RS2_CHECK(ParseConsoleCommand(exact, std::size(exact), confirmation) == ConsoleCommand::Status);
    const wchar_t embedded[] = L"rs2leech status\0recover 0001020304050607";
    RS2_CHECK(ParseConsoleCommand(embedded, std::size(embedded) - 1, confirmation) == ConsoleCommand::Invalid);
    confirmation[0] = 'z';
    RS2_CHECK(ParseConsoleCommand(L"rs2leech recover 0001020304050607", 33, confirmation) == ConsoleCommand::Invalid);
}
struct ClaimFixture { ControlState* state; HANDLE gate; RequestOrigin origin; bool won; };
DWORD WINAPI ClaimThread(void* parameter) noexcept {
    auto& fixture = *static_cast<ClaimFixture*>(parameter);
    if (WaitForSingleObject(fixture.gate, INFINITE) == WAIT_OBJECT_0)
        fixture.won = ClaimControlForTesting(*fixture.state, fixture.origin);
    return 0;
}
void SharedClaim() {
    auto* state = new ControlState{};
    state->identity = Identity();
    state->scope={2,L"E:\\servertwo"};
    state->enabled = true;
    state->started = 1;
    state->result = static_cast<LONG>(ControlResult::Ready);
    RS2_CHECK(!ClaimConsoleControlRequest(*state) && !state->latched);
    RS2_CHECK(!ClaimControlForTesting(*state, RequestOrigin::None) && !state->latched);
    state->consoleRequested = true;
    state->consoleRegistration = static_cast<LONG>(ConsoleRegistration::Available);
    state->scope=kTrainingControlScope;
    RS2_CHECK(!ClaimConsoleControlRequest(*state) && !state->latched);
    state->scope={};
    RS2_CHECK(!ClaimControlForTesting(*state,RequestOrigin::Pipe) && !state->latched);
    state->scope={2,L"E:\\servertwo"};
    for (unsigned round = 0; round < 16; ++round) {
        state->latched = 0; // Fresh disposable fixture, never an operator reset.
        const auto gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        RS2_CHECK(gate != nullptr);
        if (!gate) break;
        ClaimFixture contenders[] = {{state, gate, RequestOrigin::Pipe, false},
            {state, gate, RequestOrigin::ServerAdminConsole, false}};
        HANDLE threads[2]{};
        for (unsigned i = 0; i < 2; ++i) {
            threads[i] = CreateThread(nullptr, 0, ClaimThread, &contenders[i], 0, nullptr);
            RS2_CHECK(threads[i] != nullptr);
        }
        RS2_CHECK(SetEvent(gate));
        for (auto thread : threads) if (thread) {
            RS2_CHECK(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0);
            RS2_CHECK(CloseHandle(thread));
        }
        RS2_CHECK(CloseHandle(gate));
        if (threads[0] && threads[1]) {
            RS2_CHECK(contenders[0].won != contenders[1].won);
            ControlRequest request{}; RequestOrigin origin{};
            RS2_CHECK(ReadLatchedControl(*state, &request, &origin));
            RS2_CHECK(origin == (contenders[0].won ? RequestOrigin::Pipe : RequestOrigin::ServerAdminConsole));
            const auto identity = Identity();
            RS2_CHECK(std::memcmp(&request, &identity, sizeof(identity)) == 0);
            RS2_CHECK(std::memcmp(&state->identity, &identity, sizeof(identity)) == 0);
            RS2_CHECK(!ClaimControlForTesting(*state, RequestOrigin::Pipe));
            RS2_CHECK(!ClaimConsoleControlRequest(*state));
        }
    }
    state->latched = 0;
    // A failed pipe worker consumes the process's attempt even before the
    // owner next visits it. Neither a late console request nor its duplicate
    // may report queued after that failure.
    state->result = static_cast<LONG>(ControlResult::InvalidRequest);
    RS2_CHECK(!ClaimConsoleControlRequest(*state) && !state->latched);
    RS2_CHECK(!ClaimConsoleControlRequest(*state) && !state->latched);
    state->result = static_cast<LONG>(ControlResult::Ready);
    state->stop = 1;
    RS2_CHECK(!ClaimControlForTesting(*state, RequestOrigin::Pipe) && !state->latched);
    state->stop = 0; state->started = 0;
    RS2_CHECK(!ClaimConsoleControlRequest(*state) && !state->latched);
    state->started = 1; state->enabled = false;
    RS2_CHECK(!ClaimControlForTesting(*state, RequestOrigin::Pipe) && !state->latched);
    state->latched = 3;
    ControlRequest request{}; RequestOrigin origin = RequestOrigin::Pipe;
    RS2_CHECK(!ReadLatchedControl(*state, &request, &origin) && !request.pid && origin == RequestOrigin::None);
    state->latched = 2; state->consoleRegistration = static_cast<LONG>(ConsoleRegistration::Unavailable);
    RS2_CHECK(!ReadLatchedControl(*state, &request, &origin) && !request.pid);
    delete state;
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
    const std::string pilotPermission="schema=2\npermission=manual-pilot-finish-recreate\n"
        "server_root=E:\\servertwo\noperator_sid=S-1-5-21-1-2-3-1001\n";
    const auto pilotPermissionPath=std::wstring(unique)+L"\\RS2LeechRecovery.ini";
    RS2_CHECK(WriteFixture(pilotPermissionPath.c_str(),pilotPermission,writableDescriptor));
    for(const bool allowPilot:{false,true}) {
        auto* refused=new ControlState{};
        RS2_CHECK(InitializeControl(*refused,unique,identity.pid,identity.runId,&error,allowPilot)==
            (allowPilot?ControlResult::InvalidPath:ControlResult::InvalidConfig));
        RS2_CHECK(!refused->enabled && !refused->pipe && !refused->thread);
        for(const auto handle:refused->directories) RS2_CHECK(!handle);
        delete refused;
    }
    RS2_CHECK(DeleteFileW(pilotPermissionPath.c_str()));
    // Real Windows pipe, peer-token check and joined worker, never VNGame.
    for (unsigned scenario = 0; scenario < 7; ++scenario) {
        auto* state = new ControlState{};
        state->identity = identity; state->identity.pid = GetCurrentProcessId();
        state->scope=kTrainingControlScope;
        if(scenario==6) state->scope.schema=2;
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
        if (scenario == 6) {
            state->consoleRequested = true;
            state->consoleRegistration = static_cast<LONG>(ConsoleRegistration::Available); // Own-code fixture publication.
            RS2_CHECK(ClaimConsoleControlRequest(*state));
        }
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
            auto bytes = std::string("{\"schema\":")+std::to_string(state->scope.schema)+",\"action\":\"finish-recreate\",\"pid\":" +
                std::to_string(GetCurrentProcessId()) + ",\"run_id\":\"" + run +
                (state->scope.schema==1 ? "\",\"training_root\":\"E:\\\\rs2v_trainingsrv\"}" :
                    "\",\"server_root\":\"E:\\\\rs2v_trainingsrv\"}");
            if (scenario == 1) bytes.replace(bytes.find("000102"), 6, "100102");
            if (scenario == 2) bytes.resize(513, ' ');
            DWORD written{};
            RS2_CHECK(WriteFile(client, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size());
            if (scenario == 0) { // actual helper closes immediately after WriteFile
                RS2_CHECK(CloseHandle(client)); client = INVALID_HANDLE_VALUE;
            }
        }
        if(scenario==6) {
            // Schema2 keeps its authenticated endpoint after a duplicate request.
            // Emulate owner-confirmed preflight release and reconnect through
            // the actual Windows pipe rather than resetting a fixture latch.
            RS2_CHECK(WaitNamedPipeW(state->requestPath,5000));
            RS2_CHECK(CloseHandle(client));client=INVALID_HANDLE_VALUE;
            RS2_CHECK(ReleasePreflightClaim(*state));
            client=CreateFileW(state->requestPath,FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL,0,nullptr,
                OPEN_EXISTING,SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            RS2_CHECK(client!=INVALID_HANDLE_VALUE);
            char run[33]{};constexpr char hex[]="0123456789abcdef";
            for(unsigned i=0;i<16;++i) {run[i*2]=hex[state->identity.runId[i]>>4];run[i*2+1]=hex[state->identity.runId[i]&15];}
            const auto bytes=std::string("{\"schema\":2,\"action\":\"finish-recreate\",\"pid\":")+
                std::to_string(GetCurrentProcessId())+",\"run_id\":\""+run+"\",\"server_root\":\"E:\\\\rs2v_trainingsrv\"}";
            DWORD written{};RS2_CHECK(WriteFile(client,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr));
            // A bounded fixture wait observes claim publication; no engine runs.
            const auto deadline=GetTickCount64()+5000;
            while(!InterlockedCompareExchange(&state->latched,0,0) && GetTickCount64()<deadline) Sleep(1);
            RS2_CHECK(state->latched==static_cast<LONG>(RequestOrigin::Pipe));
            StopControl(*state);
        }
        RS2_CHECK(state->thread && WaitForSingleObject(state->thread, 5000) == WAIT_OBJECT_0);
        const auto expected = scenario == 6 ? ControlResult::Stopped : scenario == 0 ? ControlResult::Latched : scenario == 1 || scenario == 2 ?
            ControlResult::InvalidRequest : scenario == 5 ? ControlResult::SecurityRejected : ControlResult::Stopped;
        RS2_CHECK(ReadLatchedControl(*state, &parsed) == (scenario == 0 || scenario == 6));
        RS2_CHECK(state->result == static_cast<LONG>(expected));
        RS2_CHECK(!StartControl(*state, &error));
        RS2_CHECK(ReadLatchedControl(*state, &parsed) == (scenario == 0 || scenario == 6));
        StopControl(*state);
        if (client != INVALID_HANDLE_VALUE) RS2_CHECK(CloseHandle(client));
        RS2_CHECK(CloseHandle(state->thread));
        RS2_CHECK(CloseHandle(state->ioEvent)); RS2_CHECK(CloseHandle(state->stopEvent));
        delete state; // Joined fixture worker only; production storage is resident.
    }
    delete[] acl; LocalFree(writableDescriptor); LocalFree(descriptor); RS2_CHECK(RemoveDirectoryW(unique));
}
} // namespace
void RunLeechRecoveryControlTests() { Parsers(); PilotParsers(); ConsoleParser(); SharedClaim(); Security(); FilesAndWorker(); }
} // namespace rs2fix::testcases
