#pragma once
#include <string>
namespace rs2fix::tooling {
bool IsAbsoluteToolPath(const wchar_t* input) noexcept;
bool RequireAbsolutePlainFile(const wchar_t* input, std::wstring* normalized,
                              std::string* error);
bool RequireAbsolutePlainDirectory(const wchar_t* input, std::wstring* normalized,
                                   std::string* error);
bool RequireAbsoluteNewFileOutsideRoot(const wchar_t* input,
    const std::wstring& forbiddenRoot, std::wstring* normalized, std::string* error);
bool IsPathWithin(const std::wstring& root, const std::wstring& candidate,
                  bool allowRoot) noexcept;
}
