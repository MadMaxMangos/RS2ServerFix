#include "companion/companion_init.h"

namespace {
LONG volatile g_initializationState{};
}

extern "C" DWORD WINAPI RS2ServerFix_InitializeV3(
    const rs2fix::BootstrapContextV3* context) noexcept {
    const DWORD validation = rs2fix::ValidateBootstrapContextV3(context);
    if (validation != rs2fix::kInitOk) return validation;
    return rs2fix::RunCompanionInitialization(*context, &g_initializationState);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) noexcept {
    return TRUE;
}
