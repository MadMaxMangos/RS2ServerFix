#pragma once
#include "bootstrap/genuine_resolver.h"

namespace rs2fix {
bool TryForwardCalculate(GenuineResolverState*, HMODULE,
    const GenuineResolverOps&, const BYTE*, const void*, const void*, UINT32, void*);
[[noreturn]] void FailFastX3Audio() noexcept;
} // namespace rs2fix
