#include "companion/companion_init.h"
#include "shared/bootstrap_abi.h"

#include <Windows.h>

namespace {

LONG volatile g_initializationState{};

} // namespace

extern "C" DWORD WINAPI RS2ServerFix_InitializeV1(
    const rs2fix::BootstrapContextV1* context) noexcept {
    const DWORD validation = rs2fix::ValidateBootstrapContextV1(context);
    if (validation != rs2fix::kInitOk) {
        return validation;
    }
    return rs2fix::RunCompanionInitialization(
        *context, &g_initializationState);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) noexcept {
    return TRUE;
}
