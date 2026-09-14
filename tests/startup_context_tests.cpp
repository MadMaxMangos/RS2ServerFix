#include "companion/companion_init.h"
#include "test_framework.h"

namespace rs2fix::testcases {
namespace {
BootstrapContextV3 BasicContext() {
    // Existing modules supply only distinct, nonnull handles for the basic ABI
    // validator. They do not claim the full sibling/genuine-module qualification.
    BootstrapContextV3 context{};
    context.size = sizeof(context);
    context.abiVersion = kBootstrapAbiVersion;
    context.hostModule = GetModuleHandleW(nullptr);
    context.bootstrapModule = GetModuleHandleW(L"kernel32.dll");
    context.genuineX3AudioModule = GetModuleHandleW(L"ntdll.dll");
    context.genuineExportsMask = kRequiredGenuineExports;
    context.triggerReturnAddress = reinterpret_cast<std::uintptr_t>(context.hostModule) + 1;
    context.startupThreadId = GetCurrentThreadId();
    context.currentThreadId = GetCurrentThreadId();
    context.staticLoad = 1;
    context.triggerKind = kTriggerExeCrtInitialize;
    RS2_CHECK(context.hostModule && context.bootstrapModule && context.genuineX3AudioModule);
    return context;
}
void TestContextValidation() {
    const auto valid = BasicContext();
    RS2_CHECK(ValidateBootstrapContextV3(&valid) == kInitOk);
    RS2_CHECK(ValidateBootstrapContextV3(nullptr) == kInitInvalidContext);
    for (unsigned scenario = 0; scenario < 23; ++scenario) {
        auto context = valid;
        switch (scenario) {
        case 0: context.size = 0; break;
        case 1: --context.size; break;
        case 2: ++context.size; break;
        case 3: context.abiVersion = 2; break;
        case 4: ++context.abiVersion; break;
        case 5: context.reserved = 1; break;
        case 6: context.hostModule = nullptr; break;
        case 7: context.bootstrapModule = nullptr; break;
        case 8: context.genuineX3AudioModule = nullptr; break;
        case 9: context.hostModule = valid.bootstrapModule; break;
        case 10: context.bootstrapModule = valid.hostModule; break;
        case 11: context.genuineX3AudioModule = valid.hostModule; break;
        case 12: context.genuineX3AudioModule = valid.bootstrapModule; break;
        case 13: context.genuineExportsMask = kGenuineInitializePresent; break;
        case 14: context.genuineExportsMask = kGenuineCalculatePresent; break;
        case 15: context.genuineExportsMask |= 4; break;
        case 16: context.staticLoad = 0; break;
        case 17: context.staticLoad = 2; break;
        case 18: context.triggerKind = 0; break;
        case 19: ++context.triggerKind; break;
        case 20: context.startupThreadId = context.currentThreadId = 0; break;
        case 21: context.currentThreadId ^= 1; break;
        case 22:
            // Matching supplied IDs are insufficient: they must name this thread.
            context.currentThreadId ^= 1;
            context.startupThreadId = context.currentThreadId;
            break;
        }
        RS2_CHECK(ValidateBootstrapContextV3(&context) == kInitInvalidContext);
    }
    auto notMain = valid;
    notMain.hostModule = reinterpret_cast<HMODULE>(reinterpret_cast<std::uintptr_t>(valid.hostModule) + 0x1000);
    RS2_CHECK(ValidateBootstrapContextV3(&notMain) == kInitInvalidContext);
}
void TestOneShotClaim() {
    volatile LONG state = 0;
    RS2_CHECK(ClaimInitialization(&state) == InitializationClaim::Claimed);
    RS2_CHECK(state == 1);
    // The owner calls again while still holding the claim. A waiting claim
    // implementation would block here; the required result is immediately Running.
    RS2_CHECK(ClaimInitialization(&state) == InitializationClaim::Running);
    RS2_CHECK(state == 1);
    InterlockedExchange(&state, 2);
    RS2_CHECK(ClaimInitialization(&state) == InitializationClaim::Finished);
    RS2_CHECK(state == 2);
    RS2_CHECK(ClaimInitialization(&state) == InitializationClaim::Finished);
    RS2_CHECK(state == 2);
    RS2_CHECK(ClaimInitialization(nullptr) == InitializationClaim::Running);
}
}
void RunStartupContextTests() {
    TestContextValidation();
    TestOneShotClaim();
}
}
