#include "shared/path_identity.h"
#include "test_framework.h"
#include <array>
#include <cwchar>

namespace rs2fix::testcases {
namespace {
enum class GuardOperation { AppendDirectory, AppendLeaf, Extract };
struct GuardCall {
    GuardOperation operation;
    const wchar_t* input;
    std::size_t capacity;
    bool returned;
    bool exception;
    DWORD error;
    wchar_t output[1024];
    wchar_t leaf[1024];
};
int AccessViolationOnly(DWORD code) noexcept {
    return code == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
// No RAII in this SEH leaf; an overread is reported without losing later cases.
void GuardedCall(GuardCall* call) noexcept {
    __try {
        if (call->operation == GuardOperation::Extract) {
            call->returned = ExtractDirectoryAndLeaf(call->input, call->capacity,
                call->output, _countof(call->output), call->leaf, _countof(call->leaf), &call->error);
        } else if (call->operation == GuardOperation::AppendDirectory) {
            call->returned = AppendPathLeaf(call->input, call->capacity, L"x", 2,
                call->output, _countof(call->output), &call->error);
        } else {
            call->returned = AppendPathLeaf(L"C:\\", 4, call->input, call->capacity,
                call->output, _countof(call->output), &call->error);
        }
    } __except (AccessViolationOnly(GetExceptionCode())) {
        call->exception = true;
    }
}
void TestGuardPages() {
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    const std::size_t page = system.dwPageSize;
    auto* allocation = static_cast<BYTE*>(VirtualAlloc(nullptr, page * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    RS2_CHECK(allocation != nullptr);
    if (allocation == nullptr) return;
    DWORD old = 0;
    RS2_CHECK(VirtualProtect(allocation + page, page, PAGE_NOACCESS, &old));
    for (std::size_t capacity : {1u, 2u, 511u, 512u}) {
        auto* input = reinterpret_cast<wchar_t*>(allocation + page - capacity * sizeof(wchar_t));
        for (bool terminated : {false, true}) {
            for (GuardOperation operation : {GuardOperation::AppendDirectory,
                    GuardOperation::AppendLeaf, GuardOperation::Extract}) {
                for (std::size_t i = 0; i < capacity; ++i) input[i] = L'x';
                if (terminated) input[capacity - 1] = L'\0';
                if (terminated && capacity >= 5 && operation == GuardOperation::Extract) {
                    input[0] = L'C'; input[1] = L':'; input[2] = L'\\';
                }
                GuardCall call{};
                call.operation = operation; call.input = input; call.capacity = capacity;
                call.output[0] = L'z'; call.leaf[0] = L'z';
                GuardedCall(&call);
                RS2_CHECK(!call.exception);
                const bool expected = terminated && capacity > 1 &&
                    (operation != GuardOperation::Extract || capacity >= 5);
                RS2_CHECK(call.returned == expected);
                if (!expected) {
                    RS2_CHECK(call.error == ERROR_INVALID_NAME);
                    RS2_CHECK(call.output[0] == L'\0');
                }
            }
        }
    }
    RS2_CHECK(VirtualFree(allocation, 0, MEM_RELEASE));
}
} // namespace

void RunPathTests() {
    TestGuardPages();
    wchar_t output[512]{};
    wchar_t directory[512]{};
    wchar_t leaf[512]{};
    DWORD error = 0;
    RS2_CHECK(BuildSystemX3AudioPath(output, _countof(output), &error));
    const wchar_t* expectedLeaf = L"\\X3DAudio1_7.dll";
    RS2_CHECK(std::wcslen(output) >= std::wcslen(expectedLeaf));
    RS2_CHECK(_wcsicmp(output + std::wcslen(output) - std::wcslen(expectedLeaf), expectedLeaf) == 0);
    RS2_CHECK(ExtractDirectoryAndLeaf(L"C:\\x", 5, directory, _countof(directory), leaf, _countof(leaf), &error));
    RS2_CHECK(std::wcscmp(directory, L"C:\\") == 0 && std::wcscmp(leaf, L"x") == 0);
    RS2_CHECK(AppendPathLeaf(directory, _countof(directory), leaf, _countof(leaf),
        directory, _countof(directory), &error));
    RS2_CHECK(std::wcscmp(directory, L"C:\\x") == 0);
    RS2_CHECK(!AppendPathLeaf(L"C:\\", 4, L"x", 2, output, 4, &error));
    RS2_CHECK(error == ERROR_INSUFFICIENT_BUFFER && output[0] == L'\0');
    RS2_CHECK(!ExtractDirectoryAndLeaf(L"C:\\x", 5, directory, 3, leaf, _countof(leaf), &error));
    RS2_CHECK(error == ERROR_INSUFFICIENT_BUFFER && directory[0] == L'\0' && leaf[0] == L'\0');
    RS2_CHECK(!ExtractDirectoryAndLeaf(L"C:\\x", 5, directory, _countof(directory), leaf, 1, &error));
    RS2_CHECK(error == ERROR_INSUFFICIENT_BUFFER && directory[0] == L'\0' && leaf[0] == L'\0');
    RS2_CHECK(!AppendPathLeaf(nullptr, 0, L"x", 2, output, _countof(output), &error));
    RS2_CHECK(error == ERROR_INVALID_PARAMETER && output[0] == L'\0');
    RS2_CHECK(!BuildSystemX3AudioPath(output, 1, &error));
    RS2_CHECK(error == ERROR_INSUFFICIENT_BUFFER && output[0] == L'\0');
    RS2_CHECK(GetBoundedModulePath(nullptr, output, _countof(output), &error));
    FileIdentity identity{};
    RS2_CHECK(QueryFileIdentity(output, &identity, &error));
    RS2_CHECK(SameFileIdentity(identity, identity));
    RS2_CHECK(!SameFileIdentity(identity, {}));
}
} // namespace rs2fix::testcases
