#pragma once

#include "bootstrap/bootstrap_types.h"
#include "shared/path_identity.h"

#include <cstddef>

namespace rs2fix {

CompanionLoadStatus ValidateCompanionEvidence(
    HMODULE bootstrap,
    HMODULE genuine,
    HMODULE candidate,
    FARPROC initializer,
    const FileIdentity& expected,
    const FileIdentity& actual,
    bool virtualQuerySucceeded,
    const void* allocationBase) noexcept;

bool BuildCompanionPath(
    HMODULE bootstrap,
    wchar_t* output,
    std::size_t capacity,
    DWORD* error) noexcept;

CompanionLoadResult LoadAndInitializeCompanion(
    HMODULE bootstrap,
    const BootstrapContextV1& context) noexcept;

} // namespace rs2fix
