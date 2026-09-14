#include "bootstrap/companion_loader.h"
#include "shared/thread_error_mode.h"
#include "test_framework.h"
#include <cstring>
#include <cwchar>

namespace rs2fix::testcases {
namespace {
HMODULE Module(std::uintptr_t value) noexcept { return reinterpret_cast<HMODULE>(value); }
constexpr DWORD kFailure = 1234;
struct LoaderFake {
    CompanionLoadStatus failure{CompanionLoadStatus::Ok};
    bool expectedIdentityFailure{};
    bool calledV3{};
    unsigned loads{}, frees{}, invokes{};
    DWORD result{kInitOk};
    const BootstrapContextV3* received{};
};
LoaderFake& L(void* context) noexcept { return *static_cast<LoaderFake*>(context); }
bool Build(void* context, HMODULE, wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    if (L(context).failure == CompanionLoadStatus::PathFailed) { *error = kFailure; return false; }
    wcscpy_s(output, capacity, L"expected"); *error = 0; return true;
}
HMODULE Load(void* context, const wchar_t*, DWORD* error) noexcept {
    auto& fake = L(context); ++fake.loads; *error = kFailure;
    if (fake.failure == CompanionLoadStatus::LoadFailed) return nullptr;
    if (fake.failure == CompanionLoadStatus::SelfModule) return Module(1);
    if (fake.failure == CompanionLoadStatus::GenuineModule) return Module(2);
    *error = 0; return Module(3);
}
bool Path(void* context, HMODULE, wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    if (L(context).failure == CompanionLoadStatus::CandidatePathFailed) { *error = kFailure; return false; }
    wcscpy_s(output, capacity, L"actual"); *error = 0; return true;
}
bool Identity(void* context, const wchar_t* path, FileIdentity* result, DWORD* error) noexcept {
    auto& fake = L(context);
    const bool expected = path[0] == L'e';
    if (fake.failure == CompanionLoadStatus::FileIdentityFailed &&
        expected == fake.expectedIdentityFailure) { *error = kFailure; return false; }
    *result = {1, 2, fake.failure == CompanionLoadStatus::WrongFile && !expected ? 4u : 3u, true};
    *error = 0; return true;
}
DWORD WINAPI Stub(const BootstrapContextV3*) { return kInitOk; }
FARPROC Export(void* context, HMODULE, const char* name, DWORD* error) noexcept {
    auto& fake = L(context); fake.calledV3 = std::strcmp(name, "RS2ServerFix_InitializeV3") == 0;
    if (fake.failure == CompanionLoadStatus::ExportMissing) { *error = kFailure; return nullptr; }
    *error = 0; return reinterpret_cast<FARPROC>(Stub);
}
bool Query(void* context, FARPROC, const void** base, DWORD* error) noexcept {
    auto& fake = L(context);
    if (fake.failure == CompanionLoadStatus::QueryAddressFailed) { *error = kFailure; return false; }
    *base = fake.failure == CompanionLoadStatus::WrongAddressBase ? Module(1) : Module(3);
    *error = 0; return true;
}
bool Free(void* context, HMODULE) noexcept { ++L(context).frees; return true; }
DWORD Invoke(void* context, InitializeV3Fn, const BootstrapContextV3* supplied) noexcept {
    auto& fake = L(context); ++fake.invokes; fake.received = supplied; return fake.result;
}
CompanionLoaderOps Ops(LoaderFake& fake) noexcept {
    return {&fake, Build, Load, Path, Identity, Export, Query, Free, Invoke};
}
BootstrapContextV3 Context() noexcept {
    return {sizeof(BootstrapContextV3), kBootstrapAbiVersion, Module(4), Module(1),
        Module(2), kRequiredGenuineExports, 0, 0x1000, 12, 12, 1, kTriggerExeCrtInitialize};
}

struct ModeFake {
    DWORD current{SEM_NOOPENFILEERRORBOX};
    DWORD initial{SEM_NOOPENFILEERRORBOX};
    DWORD observed{}, fatalError{};
    unsigned sets{}, loads{}, fatals{};
    unsigned failSet{};
    bool failLoad{};
};
DWORD GetMode(void* context) noexcept { return static_cast<ModeFake*>(context)->current; }
bool SetMode(void* context, DWORD value, DWORD* error) noexcept {
    auto& fake = *static_cast<ModeFake*>(context);
    ++fake.sets;
    if (fake.sets == fake.failSet) { *error = kFailure; return false; }
    fake.current = value; *error = 0; return true;
}
HMODULE ModeLoad(void* context, const wchar_t*, DWORD flags, DWORD* error) noexcept {
    auto& fake = *static_cast<ModeFake*>(context); ++fake.loads; fake.observed = fake.current;
    if (flags != LOAD_LIBRARY_SEARCH_SYSTEM32) { *error = ERROR_INVALID_PARAMETER; return nullptr; }
    *error = fake.failLoad ? ERROR_MOD_NOT_FOUND : ERROR_SUCCESS;
    return fake.failLoad ? nullptr : Module(3);
}
void Fatal(void* context, DWORD error) noexcept {
    auto& fake = *static_cast<ModeFake*>(context); ++fake.fatals; fake.fatalError = error;
}
void TestThreadModes() {
    for (unsigned failure : {0u, 1u, 2u, 3u}) {
        ModeFake fake{}; fake.failSet = failure == 3 ? 0 : failure; fake.failLoad = failure == 3;
        ThreadErrorModeOps ops{&fake, GetMode, SetMode, ModeLoad, Fatal};
        DWORD error = 0;
        HMODULE result = LoadLibraryWithThreadErrorMode(L"C:\\qualified.dll",
            LOAD_LIBRARY_SEARCH_SYSTEM32, &error, ops);
        RS2_CHECK((result != nullptr) == (failure == 0));
        RS2_CHECK(fake.loads == (failure == 1 ? 0u : 1u));
        RS2_CHECK(fake.sets == (failure == 1 ? 1u : 2u));
        RS2_CHECK(fake.fatals == (failure == 2 ? 1u : 0u));
        if (failure != 2) RS2_CHECK(fake.current == fake.initial);
        if (failure != 1) {
            RS2_CHECK(fake.observed == (fake.initial | SEM_FAILCRITICALERRORS));
            RS2_CHECK((fake.observed & SEM_NOGPFAULTERRORBOX) == 0);
        }
        if (failure == 2) RS2_CHECK(fake.fatalError == kFailure);
        RS2_CHECK(error == (failure == 0 ? 0u : failure == 3 ? ERROR_MOD_NOT_FOUND : kFailure));
    }
    // The current thread and process policies are unchanged by all injected cases.
}
} // namespace

void RunLoaderTests() {
    const BootstrapContextV3 context = Context();
    for (CompanionLoadStatus failure : {CompanionLoadStatus::PathFailed,
        CompanionLoadStatus::LoadFailed, CompanionLoadStatus::SelfModule,
        CompanionLoadStatus::GenuineModule, CompanionLoadStatus::CandidatePathFailed,
        CompanionLoadStatus::FileIdentityFailed, CompanionLoadStatus::WrongFile,
        CompanionLoadStatus::ExportMissing, CompanionLoadStatus::QueryAddressFailed,
        CompanionLoadStatus::WrongAddressBase}) {
        LoaderFake fake{}; fake.failure = failure;
        const auto result = LoadAndInitializeCompanion(Module(1), context, Ops(fake));
        RS2_CHECK(result.status == failure && result.module == nullptr);
        RS2_CHECK(fake.invokes == 0);
        RS2_CHECK(fake.frees == (failure == CompanionLoadStatus::PathFailed ||
            failure == CompanionLoadStatus::LoadFailed || failure == CompanionLoadStatus::SelfModule ? 0u : 1u));
        const bool validation = failure == CompanionLoadStatus::SelfModule ||
            failure == CompanionLoadStatus::GenuineModule || failure == CompanionLoadStatus::WrongFile ||
            failure == CompanionLoadStatus::WrongAddressBase;
        RS2_CHECK(result.win32Error == (validation ? ERROR_INVALID_DATA : kFailure));
    }
    LoaderFake expectedFail{}; expectedFail.failure = CompanionLoadStatus::FileIdentityFailed;
    expectedFail.expectedIdentityFailure = true;
    RS2_CHECK(LoadAndInitializeCompanion(Module(1), context, Ops(expectedFail)).status == CompanionLoadStatus::FileIdentityFailed);
    RS2_CHECK(expectedFail.frees == 1 && expectedFail.invokes == 0);
    for (DWORD returnCode : {kInitOk, kInitAlreadyInitialized, kInitHostIdentityFailed, kInitMarkerWriteFailed, kInitFixDisabled}) {
        LoaderFake fake{}; fake.result = returnCode;
        const auto result = LoadAndInitializeCompanion(Module(1), context, Ops(fake));
        RS2_CHECK(result.module == Module(3) && result.initializeResult == returnCode);
        RS2_CHECK(fake.invokes == 1 && fake.loads == 1 && fake.frees == 0);
        RS2_CHECK(fake.calledV3 && fake.received == &context);
        RS2_CHECK(result.status == (returnCode <= kInitAlreadyInitialized ? CompanionLoadStatus::Ok : CompanionLoadStatus::InitializeFailed));
    }
    LoaderFake invalid{};
    auto badContext = context; badContext.reserved = 1;
    RS2_CHECK(LoadAndInitializeCompanion(Module(1), badContext, Ops(invalid)).status == CompanionLoadStatus::PathFailed);
    RS2_CHECK(invalid.loads == 0);
    const FileIdentity identity{1, 2, 3, true};
    const FARPROC function = reinterpret_cast<FARPROC>(Stub);
    RS2_CHECK(ValidateCompanionEvidence(Module(1), Module(2), Module(3), function,
        identity, identity, true, Module(3)) == CompanionLoadStatus::Ok);
    RS2_CHECK(ValidateCompanionEvidence(Module(1), Module(2), Module(3), function,
        {}, identity, true, Module(3)) == CompanionLoadStatus::FileIdentityFailed);
    RS2_CHECK(ValidateCompanionEvidence(Module(1), Module(2), Module(3), function,
        identity, {}, true, Module(3)) == CompanionLoadStatus::FileIdentityFailed);
    wchar_t path[512]{}; DWORD error = 0;
    RS2_CHECK(BuildCompanionPath(GetModuleHandleW(nullptr), path, _countof(path), &error));
    const wchar_t* leaf = std::wcsrchr(path, L'\\');
    RS2_CHECK(leaf != nullptr && std::wcscmp(leaf, L"\\RS2ServerFix.dll") == 0);
    RS2_CHECK(!BuildCompanionPath(nullptr, path, _countof(path), &error));
    RS2_CHECK(error == ERROR_INVALID_PARAMETER && path[0] == 0);
    RS2_CHECK(!BuildCompanionPath(GetModuleHandleW(nullptr), path, 1, &error));
    RS2_CHECK(error == ERROR_INSUFFICIENT_BUFFER && path[0] == 0);
    RS2_CHECK(!BuildCompanionPath(Module(1), path, _countof(path), &error));
    TestThreadModes();
}
} // namespace rs2fix::testcases
