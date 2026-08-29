#pragma once

#include "shared/bootstrap_abi.h"

#include <Windows.h>

#include <cstdint>

namespace rs2fix {

enum class InitializationClaim : std::uint32_t {
    Claimed,
    Running,
    Finished,
};

DWORD ValidateBootstrapContextV1(
    const BootstrapContextV1* context) noexcept;

InitializationClaim ClaimInitialization(
    LONG volatile* state) noexcept;

DWORD RunCompanionInitialization(
    const BootstrapContextV1& context,
    LONG volatile* state) noexcept;

} // namespace rs2fix
