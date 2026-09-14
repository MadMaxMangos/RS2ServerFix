#include "companion/console_status.h"
#include "companion/companion_init.h"
#include "shared/version.h"
#include "test_framework.h"
#include <array>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

namespace rs2fix::testcases {
namespace {
MarkerData GoodMarker() {
    MarkerData data{};
    data.utc = {2026, 9, 0, 13, 12, 34, 56, 789};
    data.processId = 1234;
    data.executableSize = 23994880;
    RS2_CHECK(ParseSha256Upper(
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393", &data.digest));
    data.digestValid = true;
    data.buildIdentity = BuildIdentity::CurrentFullDump;
    data.genuineSystem32 = true;
    data.genuineExportsMask = kRequiredGenuineExports;
    data.triggerKind = kTriggerExeCrtInitialize;
    data.mode = ReconMode::Active;
    data.recon = {ReconOutcome::Active, FixReason::None, 0, true};
    data.initializeResult = kInitOk;
    data.bootstrapBesideExecutable = true;
    data.companionBesideExecutable = true;
    data.complete = true;
    wcscpy_s(data.executableLeaf, L"VNGame.exe");
    return data;
}
void TestMarkerFormat() {
    auto data = GoodMarker();
    char buffer[8192]{};
    std::size_t size = 0;
    RS2_CHECK(FormatMarkerUtf8(data, buffer, sizeof(buffer), &size));
    const std::string expected =
        "schema=3\r\nversion=" RS2FIX_VERSION_ASCII "\r\nutc=2026-09-13T12:34:56.789Z\r\n"
        "pid=1234\r\nexecutable=VNGame.exe\r\nexecutable_size=23994880\r\n"
        "sha256=0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393\r\n"
        "build_identity=current-full-dump\r\nbootstrap=X3DAudio1_7.dll\r\n"
        "bootstrap_beside_executable=true\r\ncompanion=RS2ServerFix.dll\r\n"
        "companion_beside_executable=true\r\ngenuine_module=system32\r\n"
        "genuine_initialize_present=true\r\ngenuine_calculate_present=true\r\n"
        "trigger=exe-crt-initialize\r\nmode=active\r\nfix=recon-exclusive-scale-v1\r\n"
        "qualification=ready\r\nrecon=active\r\nreason=none\r\ninitialize_result=0\r\n"
        "primary_write_error=0\r\ncompletion=complete\r\n";
    RS2_CHECK(std::string(buffer, size) == expected);
    RS2_CHECK(size == expected.size() && buffer[size] == '\0');
    std::vector<char> exact(size + 1);
    RS2_CHECK(FormatMarkerUtf8(data, exact.data(), exact.size(), &size));
    std::size_t failedSize = 99;
    RS2_CHECK(!FormatMarkerUtf8(data, exact.data(), exact.size() - 1, &failedSize));
    RS2_CHECK(failedSize == 0 && exact[0] == '\0');
    buffer[0] = 'x';
    RS2_CHECK(!FormatMarkerUtf8(data, buffer, sizeof(buffer), nullptr) && buffer[0] == '\0');
    RS2_CHECK(!FormatMarkerUtf8(data, nullptr, sizeof(buffer), &size) && size == 0);
    RS2_CHECK(!FormatMarkerUtf8(data, buffer, 0, &size) && size == 0);
    for (const wchar_t* bad : {L"C:\\Users\\Name\\VNGame.exe", L"VNGame\ncompletion=complete", L"..", L"VNGame\r.exe"}) {
        wcscpy_s(data.executableLeaf, bad);
        RS2_CHECK(!FormatMarkerUtf8(data, buffer, sizeof(buffer), &size));
        RS2_CHECK(buffer[0] == '\0' && size == 0);
    }
    data = GoodMarker();
    data.utc.wMonth = 13;
    RS2_CHECK(!FormatMarkerUtf8(data, buffer, sizeof(buffer), &size));
    data = GoodMarker();
    data.recon.reason = static_cast<FixReason>(999);
    RS2_CHECK(!FormatMarkerUtf8(data, buffer, sizeof(buffer), &size));
    data = GoodMarker();
    data.digestValid = false;
    data.buildIdentity = BuildIdentity::Indeterminate;
    data.recon = {ReconOutcome::Disabled, FixReason::HostOpenSharingViolation, ERROR_SHARING_VIOLATION, false};
    data.initializeResult = kInitHostIdentityFailed;
    RS2_CHECK(FormatMarkerUtf8(data, buffer, sizeof(buffer), &size));
    RS2_CHECK(std::strstr(buffer, "sha256=unavailable\r\n") != nullptr);
    RS2_CHECK(std::strstr(buffer, "qualification=rejected\r\nrecon=disabled\r\n") != nullptr);
    RS2_CHECK(std::strstr(buffer, "reason=host_open_sharing_violation\r\n") != nullptr);
    RS2_CHECK(std::strstr(buffer, "completion=complete\r\n") != nullptr);
    RS2_CHECK(!MarkerStateAccepted(data));
    for (const char* forbidden : {"C:\\", "\\Users\\", "account", "player", "command_line", "eos", "eac"})
        RS2_CHECK(std::strstr(buffer, forbidden) == nullptr);
}
enum class MarkerFailure { None, Open, Failed, Short, Zero, Flush, Close, Remove };
struct MarkerFake {
    MarkerFailure failure{};
    bool failBoth{};
    unsigned opens{}, writes{}, flushes{}, closes{}, removes{};
    std::string lastData;
    std::wstring removedPath;
    std::string* trace{};
    bool Fails() const { return failBoth || opens == 1; }
};
HANDLE MarkerCreate(void* context, const wchar_t*, DWORD* error) noexcept {
    auto& state = *static_cast<MarkerFake*>(context);
    ++state.opens;
    if (state.trace) *state.trace += "create;";
    if (state.Fails() && state.failure == MarkerFailure::Open) {
        *error = ERROR_ACCESS_DENIED;
        return INVALID_HANDLE_VALUE;
    }
    *error = ERROR_SUCCESS;
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(state.opens));
}
bool MarkerWrite(void* context, HANDLE, const void* data, DWORD size, DWORD* written, DWORD* error) noexcept {
    auto& state = *static_cast<MarkerFake*>(context);
    ++state.writes;
    if (state.trace) *state.trace += "write;";
    state.lastData.assign(static_cast<const char*>(data), size);
    *written = size;
    *error = ERROR_SUCCESS;
    if (!state.Fails()) return true;
    if (state.failure == MarkerFailure::Short) *written = size - 1;
    if (state.failure == MarkerFailure::Zero) *written = 0;
    if (state.failure == MarkerFailure::Remove) *written = size - 1;
    if (state.failure == MarkerFailure::Failed) {
        *error = ERROR_WRITE_FAULT;
        return false;
    }
    return true;
}
bool MarkerFlush(void* context, HANDLE, DWORD* error) noexcept {
    auto& state = *static_cast<MarkerFake*>(context);
    ++state.flushes;
    *error = state.Fails() && state.failure == MarkerFailure::Flush ? ERROR_WRITE_FAULT : ERROR_SUCCESS;
    return *error == ERROR_SUCCESS;
}
bool MarkerClose(void* context, HANDLE, DWORD* error) noexcept {
    auto& state = *static_cast<MarkerFake*>(context);
    ++state.closes;
    if (state.trace) *state.trace += "close;";
    *error = state.Fails() && state.failure == MarkerFailure::Close ? ERROR_INVALID_HANDLE : ERROR_SUCCESS;
    return *error == ERROR_SUCCESS;
}
bool MarkerRemove(void* context, const wchar_t* path, DWORD* error) noexcept {
    auto& state = *static_cast<MarkerFake*>(context);
    ++state.removes;
    if (state.trace) *state.trace += "remove;";
    state.removedPath = path;
    *error = state.failure == MarkerFailure::Remove ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    return *error == ERROR_SUCCESS;
}
MarkerFileOps MarkerOps(MarkerFake& state) {
    return {&state, MarkerCreate, MarkerWrite, MarkerFlush, MarkerClose, MarkerRemove};
}
void TestMarkerWrites() {
    const auto data = GoodMarker();
    for (const auto failure : {MarkerFailure::None, MarkerFailure::Open, MarkerFailure::Failed,
        MarkerFailure::Short, MarkerFailure::Zero, MarkerFailure::Flush, MarkerFailure::Close}) {
        for (bool failBoth : {false, true}) {
            MarkerFake state{};
            state.failure = failure;
            state.failBoth = failBoth;
            MarkerWriteResult result{};
            const bool ok = WriteMarkerWithFallback(L"C:\\primary", L"C:\\temporary", data, &result, MarkerOps(state));
            const bool failed = failure != MarkerFailure::None;
            RS2_CHECK(ok == (!failed || !failBoth));
            RS2_CHECK(result.written == ok);
            RS2_CHECK(state.opens == (failed ? 2u : 1u));
            RS2_CHECK(state.writes <= state.opens && state.closes <= state.opens);
            RS2_CHECK(state.removes == (failure == MarkerFailure::Open || !failed ? 0u : failBoth ? 2u : 1u));
            RS2_CHECK(result.usedFallback == (failed && !failBoth));
            if (failed) RS2_CHECK(result.primaryError != ERROR_SUCCESS);
            if (failed && !failBoth) {
                const std::string field = "primary_write_error=" + std::to_string(result.primaryError) + "\r\n";
                RS2_CHECK(state.lastData.find(field) != std::string::npos);
                RS2_CHECK(state.lastData.find("completion=complete\r\n") != std::string::npos);
            }
            if (failure == MarkerFailure::Short || failure == MarkerFailure::Zero || failure == MarkerFailure::Failed)
                RS2_CHECK(state.flushes == (failBoth ? 0u : 1u));
        }
    }
    MarkerFake state{};
    state.failure = MarkerFailure::Remove;
    MarkerWriteResult result{};
    RS2_CHECK(WriteMarkerWithFallback(L"C:\\primary", L"C:\\temporary", data, &result, MarkerOps(state)));
    RS2_CHECK(result.cleanupError == ERROR_ACCESS_DENIED);
    RS2_CHECK(state.lastData.find("recon=active\r\n") != std::string::npos);
    const char* initializeField = std::strstr(state.lastData.c_str(), "initialize_result=");
    RS2_CHECK(initializeField != nullptr);
    if (initializeField) {
        MarkerData fallback = data;
        fallback.initializeResult = std::strtoul(initializeField + std::strlen("initialize_result="), nullptr, 10);
        RS2_CHECK(fallback.initializeResult == kInitMarkerWriteFailed);
        RS2_CHECK(!MarkerStateAccepted(fallback));
    }
    ConsoleReportContext line{};
    RS2_CHECK(FormatConsoleStatus(data, result, &line));
    RS2_CHECK(std::strstr(line.line, "marker=failed; acceptance=failed") != nullptr);
    auto ops = MarkerOps(state);
    ops.write = nullptr;
    const unsigned opens = state.opens;
    RS2_CHECK(!WriteMarkerWithFallback(L"C:\\primary", L"C:\\temporary", data, &result, ops));
    RS2_CHECK(state.opens == opens && result.finalError == ERROR_INVALID_PARAMETER);
}
void TestNativeMarkerFallback() {
    wchar_t temporary[MAX_PATH]{}, directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temporary);
    RS2_CHECK(length > 0 && length < MAX_PATH);
    RS2_CHECK(GetTempFileNameW(temporary, L"R2M", 0, directory) != 0);
    RS2_CHECK(DeleteFileW(directory) != FALSE);
    RS2_CHECK(CreateDirectoryW(directory, nullptr) != FALSE);
    auto data = GoodMarker();
    data.processId = GetCurrentProcessId();
    const std::wstring missing = std::wstring(directory) + L"\\missing";
    MarkerWriteResult result{};
    RS2_CHECK(WriteMarkerWithFallback(missing.c_str(), directory, data, &result));
    RS2_CHECK(result.written && result.usedFallback && result.primaryError != ERROR_SUCCESS);
    const HANDLE file = CreateFileW(result.writtenPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file != INVALID_HANDLE_VALUE) {
        char content[8192]{};
        DWORD read = 0;
        RS2_CHECK(ReadFile(file, content, sizeof(content) - 1, &read, nullptr) != FALSE);
        RS2_CHECK(CloseHandle(file) != FALSE);
        RS2_CHECK(read != 0 && std::strstr(content, "schema=3\r\n") == content);
        RS2_CHECK(std::strstr(content, "completion=complete\r\n") != nullptr);
        const std::string field = "primary_write_error=" + std::to_string(result.primaryError) + "\r\n";
        RS2_CHECK(std::strstr(content, field.c_str()) != nullptr);
    }
    if (result.writtenPath[0]) RS2_CHECK(DeleteFileW(result.writtenPath) != FALSE);
    RS2_CHECK(RemoveDirectoryW(directory) != FALSE);
}
struct ConsoleFake {
    ULONGLONG tick{};
    DWORD availableAt{};
    bool neverAvailable{}, invalidHandle{}, failWrite{}, shortWrite{}, zeroWrite{}, failThread{}, failClose{};
    bool frozenClock{}, backwardsClock{};
    unsigned polls{}, writes{}, sleeps{}, starts{}, closes{};
    std::string output;
    std::string* trace{};
    LPTHREAD_START_ROUTINE savedFunction{};
    void* savedContext{};
};
ULONGLONG ConsoleTicks(void* context) noexcept {
    const auto& state = *static_cast<ConsoleFake*>(context);
    return state.backwardsClock && state.polls > 0 ? 0 : state.tick;
}
void ConsoleSleep(void* context, DWORD delay) noexcept {
    auto& state = *static_cast<ConsoleFake*>(context);
    ++state.sleeps;
    if (!state.frozenClock) state.tick += delay;
}
HANDLE ConsoleOutput(void* context, DWORD* error) noexcept {
    auto& state = *static_cast<ConsoleFake*>(context);
    ++state.polls;
    if (state.trace) *state.trace += "console;";
    *error = ERROR_SUCCESS;
    if (state.neverAvailable || state.tick < state.availableAt)
        return state.invalidHandle ? INVALID_HANDLE_VALUE : nullptr;
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(123));
}
bool ConsoleWrite(void* context, HANDLE, const void* bytes, DWORD size, DWORD* written, DWORD* error) noexcept {
    auto& state = *static_cast<ConsoleFake*>(context);
    ++state.writes;
    if (state.trace) *state.trace += "stdout;";
    state.output.assign(static_cast<const char*>(bytes), size);
    *written = state.zeroWrite ? 0 : state.shortWrite ? size - 1 : size;
    *error = state.failWrite ? ERROR_BROKEN_PIPE : ERROR_SUCCESS;
    return !state.failWrite;
}
HANDLE ConsoleStart(void* context, LPTHREAD_START_ROUTINE function, void* data, DWORD* error) noexcept {
    auto& state = *static_cast<ConsoleFake*>(context);
    ++state.starts;
    state.savedFunction = function;
    state.savedContext = data;
    *error = state.failThread ? ERROR_NOT_ENOUGH_MEMORY : ERROR_SUCCESS;
    return state.failThread ? nullptr : reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(456));
}
bool ConsoleClose(void* context, HANDLE, DWORD* error) noexcept {
    auto& state = *static_cast<ConsoleFake*>(context);
    ++state.closes;
    *error = state.failClose ? ERROR_INVALID_HANDLE : ERROR_SUCCESS;
    return !state.failClose;
}
ConsoleStatusOps ConsoleOps(ConsoleFake& state) {
    return {&state, ConsoleTicks, ConsoleSleep, ConsoleOutput, ConsoleWrite, ConsoleStart, ConsoleClose};
}
void TestFatalTerminalReporting() {
    for (unsigned scenario = 0; scenario < 7; ++scenario) {
        auto data = GoodMarker();
        data.recon = {ReconOutcome::Fatal, FixReason::RollbackFailed, ERROR_WRITE_FAULT, true};
        data.initializeResult = kInitFixDisabled;
        data.complete = true;
        std::string trace;
        MarkerFake marker;
        marker.trace = &trace;
        ConsoleFake console;
        console.trace = &trace;
        if (scenario == 1) { marker.failure = MarkerFailure::Open; marker.failBoth = true; }
        if (scenario == 2) marker.failure = MarkerFailure::Remove;
        if (scenario == 3) console.neverAvailable = true;
        if (scenario == 4) console.failWrite = true;
        if (scenario == 5) console.shortWrite = true;
        if (scenario == 6) console.zeroWrite = true;
        auto consoleOps = ConsoleOps(console);
        // Fatal reporting must work without the polling/thread adapter methods.
        consoleOps.ticks = nullptr;
        consoleOps.sleep = nullptr;
        consoleOps.startThread = nullptr;
        consoleOps.closeThread = nullptr;
        MarkerWriteResult written{};
        const bool reported = TryReportFatalInitialization(L"C:\\primary", L"C:\\temporary",
            data, &written, MarkerOps(marker), consoleOps);
        RS2_CHECK(reported == (scenario != 1 && scenario != 2));
        RS2_CHECK(console.polls == 1 && console.writes == (scenario == 3 ? 0u : 1u));
        RS2_CHECK(console.sleeps == 0 && console.starts == 0 && console.closes == 0);
        const auto consoleAt = trace.find("console;");
        RS2_CHECK(consoleAt != std::string::npos && consoleAt > trace.rfind("create;"));
        if (scenario != 1) {
            RS2_CHECK(consoleAt > trace.rfind("close;"));
            RS2_CHECK(marker.lastData.find("recon=fatal\r\nreason=rollback_failed\r\n") != std::string::npos);
            RS2_CHECK(marker.lastData.find(scenario == 2 ? "initialize_result=4\r\n" : "initialize_result=5\r\n") != std::string::npos);
            RS2_CHECK(marker.lastData.find("completion=complete\r\n") != std::string::npos);
        }
        if (scenario != 3) {
            RS2_CHECK(console.output.find("recon=fatal;") != std::string::npos);
            RS2_CHECK(console.output.find("reason=rollback_failed;") != std::string::npos);
            RS2_CHECK(console.output.find("acceptance=failed\r\n") != std::string::npos);
            RS2_CHECK(console.output.find((scenario == 1 || scenario == 2) ? "marker=failed;" : "marker=complete;") != std::string::npos);
        }
        RS2_CHECK(data.recon.outcome == ReconOutcome::Fatal && data.recon.reason == FixReason::RollbackFailed &&
            data.recon.error == ERROR_WRITE_FAULT && data.initializeResult == kInitFixDisabled);
    }
    MarkerFake marker;
    ConsoleFake console;
    MarkerWriteResult result{};
    RS2_CHECK(!TryReportFatalInitialization(L"C:\\primary", L"C:\\temporary",
        GoodMarker(), &result, MarkerOps(marker), ConsoleOps(console)));
    RS2_CHECK(marker.opens == 0 && console.polls == 0 && console.starts == 0);
}
void TestConsoleFormatAndAcceptance() {
    auto data = GoodMarker();
    MarkerWriteResult marker{};
    marker.written = true;
    ConsoleReportContext output{};
    RS2_CHECK(MarkerStateAccepted(data));
    RS2_CHECK(FormatConsoleStatus(data, marker, &output));
    const std::string active = output.line;
    RS2_CHECK(active == "[RS2ServerFix] v" RS2FIX_VERSION_ASCII
        " loaded; host=current-full-dump; mode=active; qualification=ready; recon=active; "
        "fix=recon-exclusive-scale-v1; reason=none; marker=complete; acceptance=passed\r\n");
    marker.written = false;
    RS2_CHECK(FormatConsoleStatus(data, marker, &output));
    RS2_CHECK(std::strstr(output.line, "recon=active;") != nullptr);
    RS2_CHECK(std::strstr(output.line, "marker=failed; acceptance=failed\r\n") != nullptr);
    marker.written = true;
    data.mode = ReconMode::Passive;
    data.recon.outcome = ReconOutcome::Passive;
    RS2_CHECK(MarkerStateAccepted(data));
    data.recon.outcome = ReconOutcome::Active;
    RS2_CHECK(!MarkerStateAccepted(data));
    const auto checkFiniteLine = [&]() {
        RS2_CHECK(FormatConsoleStatus(data, marker, &output));
        RS2_CHECK(output.bytes == std::strlen(output.line) && output.bytes < kConsoleLineCapacity);
        if (output.bytes >= 2) RS2_CHECK(std::all_of(output.line, output.line + output.bytes - 2,
            [](char value) { return value >= 32 && value <= 126; }));
    };
    data = GoodMarker();
    for (unsigned identity = 0; identity <= static_cast<unsigned>(BuildIdentity::Indeterminate); ++identity) {
        data.buildIdentity = static_cast<BuildIdentity>(identity);
        checkFiniteLine();
    }
    data = GoodMarker();
    for (unsigned outcome = 0; outcome <= static_cast<unsigned>(ReconOutcome::Fatal); ++outcome) {
        data.recon.outcome = static_cast<ReconOutcome>(outcome);
        checkFiniteLine();
    }
    data = GoodMarker();
    for (unsigned reason = 0; reason <= static_cast<unsigned>(FixReason::RollbackFailed); ++reason) {
        data.recon.reason = static_cast<FixReason>(reason);
        checkFiniteLine();
    }
    data.recon.reason = static_cast<FixReason>(999);
    RS2_CHECK(!FormatConsoleStatus(data, marker, &output));
    RS2_CHECK(output.bytes == 0 && output.line[0] == '\0');
}
void TestConsoleOpportunityAndScheduling() {
    auto data = GoodMarker();
    MarkerWriteResult marker{};
    marker.written = true;
    ConsoleReportContext report{};
    RS2_CHECK(FormatConsoleStatus(data, marker, &report));
    for (DWORD delay : {DWORD{0}, DWORD{500}, DWORD{29900}, DWORD{30000}}) {
        ConsoleFake state{};
        state.availableAt = delay;
        const auto result = RunConsoleReporter(report, ConsoleOps(state));
        RS2_CHECK(result.written == (delay < 30000));
        RS2_CHECK(result.timedOut == (delay == 30000));
        RS2_CHECK(result.delayMs == delay && state.writes == (delay < 30000 ? 1u : 0u));
        RS2_CHECK(state.sleeps == delay / 100);
    }
    for (bool invalid : {false, true}) {
        ConsoleFake state{};
        state.neverAvailable = true;
        state.invalidHandle = invalid;
        const auto result = RunConsoleReporter(report, ConsoleOps(state));
        RS2_CHECK(result.timedOut && !result.attempted && state.writes == 0);
        RS2_CHECK(state.sleeps == 300 && state.tick == 30000);
    }
    for (bool backwards : {false, true}) {
        ConsoleFake state{};
        state.tick = 100;
        state.neverAvailable = true;
        state.frozenClock = !backwards;
        state.backwardsClock = backwards;
        const auto result = RunConsoleReporter(report, ConsoleOps(state));
        RS2_CHECK(!result.attempted && !result.written && state.writes == 0);
        RS2_CHECK(result.error == static_cast<DWORD>(backwards ? ERROR_INVALID_DATA : ERROR_TIMEOUT));
        RS2_CHECK(state.sleeps == (backwards ? 1u : 300u));
    }
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        ConsoleFake state{};
        state.failWrite = scenario == 0;
        state.shortWrite = scenario == 1;
        state.zeroWrite = scenario == 2;
        const auto result = RunConsoleReporter(report, ConsoleOps(state));
        RS2_CHECK(!result.written && result.attempted && state.writes == 1);
        RS2_CHECK(state.polls == 1 && state.sleeps == 0);
        RS2_CHECK(result.error == static_cast<DWORD>(scenario == 0 ? ERROR_BROKEN_PIPE : ERROR_WRITE_FAULT));
    }
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        ConsoleFake state{};
        state.failThread = scenario == 1;
        state.failClose = scenario == 2;
        ReporterStorage storage{};
        ConsoleReportContext caller = report;
        const auto started = TryStartReporter(&storage, caller, ConsoleOps(state));
        RS2_CHECK(started.started == !state.failThread);
        RS2_CHECK(state.starts == 1 && state.writes == 0 && state.polls == 0);
        RS2_CHECK(state.savedContext == &storage);
        RS2_CHECK(state.closes == (state.failThread ? 0u : 1u));
        if (scenario != 0) RS2_CHECK(started.error != ERROR_SUCCESS);
        caller = {}; // A destroyed/changed caller buffer cannot change the worker's copy.
        if (!state.failThread) {
            RS2_CHECK(state.savedFunction(state.savedContext) == ERROR_SUCCESS);
            RS2_CHECK(state.output == report.line && state.writes == 1);
        }
        const auto duplicate = TryStartReporter(&storage, report, ConsoleOps(state));
        RS2_CHECK(!duplicate.started && duplicate.error == ERROR_ALREADY_EXISTS && state.starts == 1);
    }
}
void TestRedirectedOutput() {
    const auto data = GoodMarker();
    MarkerWriteResult marker{};
    marker.written = true;
    ConsoleReportContext report{};
    RS2_CHECK(FormatConsoleStatus(data, marker, &report));
    HANDLE input = nullptr, output = nullptr;
    RS2_CHECK(CreatePipe(&input, &output, nullptr, 4096) != FALSE);
    if (!input || !output) return;
    const HANDLE previous = GetStdHandle(STD_OUTPUT_HANDLE);
    RS2_CHECK(SetStdHandle(STD_OUTPUT_HANDLE, output) != FALSE);
    const auto result = RunConsoleReporter(report, ProductionConsoleStatusOps());
    RS2_CHECK(SetStdHandle(STD_OUTPUT_HANDLE, previous) != FALSE);
    RS2_CHECK(result.written && result.attempted);
    RS2_CHECK(CloseHandle(output) != FALSE);
    char bytes[kConsoleLineCapacity]{};
    DWORD count = 0;
    RS2_CHECK(ReadFile(input, bytes, sizeof(bytes), &count, nullptr) != FALSE);
    RS2_CHECK(count == report.bytes && std::memcmp(bytes, report.line, count) == 0);
    RS2_CHECK(CloseHandle(input) != FALSE);
}
}
void RunCompanionTests() {
    TestMarkerFormat();
    TestMarkerWrites();
    TestNativeMarkerFallback();
    TestFatalTerminalReporting();
    TestConsoleFormatAndAcceptance();
    TestConsoleOpportunityAndScheduling();
    TestRedirectedOutput();
}
}
