#pragma once
#include "companion/steam_reporting_runtime.h"

namespace rs2fix::reporting {
// Cold, unpublished state only. Exact compiled own frames are qualified before
// any fourth-IAT/task pointer can expose these process-resident entrypoints.
bool PrepareRuntimeCapture(Runtime&, HMODULE companion) noexcept;
bool PublishRuntime(Runtime&) noexcept;
__declspec(noinline) void PumpEntry();
__declspec(noinline) bool BuilderEntry(void* borrowedHolder);
#if defined(RS2_REPORTING_TESTING)
void ResetPublishedRuntimeForTest() noexcept;
#endif
} // namespace rs2fix::reporting
