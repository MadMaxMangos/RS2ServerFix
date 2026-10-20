#include "shared/path_identity.h"
#include "test_framework.h"
#include <array>
#include <cwchar>
#include <cstring>

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

    // Bind V3 receipts to the held file, preserving the complete 128-bit ID.
    // The running test image is sufficient; no server log or game is opened.
    HANDLE file = CreateFileW(output, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file != INVALID_HANDLE_VALUE) {
        FILE_ID_INFO native{};
        FileIdentity128 full{};
        RS2_CHECK(GetFileInformationByHandleEx(file, FileIdInfo, &native, sizeof(native)));
        RS2_CHECK(QueryFileIdentity128(file, &full, &error));
        RS2_CHECK(error == ERROR_SUCCESS && full.valid);
        RS2_CHECK(full.volumeSerial == native.VolumeSerialNumber);
        RS2_CHECK(std::memcmp(full.fileId, native.FileId.Identifier, sizeof(full.fileId)) == 0);
        RS2_CHECK(SameFileIdentity128(full, full));
        RS2_CHECK(!SameFileIdentity128(full, {}));
        auto changed = full;
        changed.fileId[15] ^= 1;
        RS2_CHECK(!SameFileIdentity128(full, changed));
        changed = full;
        changed.volumeSerial ^= (1ULL << 63);
        RS2_CHECK(!SameFileIdentity128(full, changed));
        // A failed query must erase a previous successful identity, and must
        // not close the caller's handle even on argument rejection.
        RS2_CHECK(!QueryFileIdentity128(nullptr, &full, &error));
        RS2_CHECK(!full.valid && error == ERROR_INVALID_PARAMETER);
        RS2_CHECK(!QueryFileIdentity128(file, nullptr, &error));
        RS2_CHECK(QueryFileIdentity128(file, &full, &error));
        RS2_CHECK(!QueryFileIdentity128(INVALID_HANDLE_VALUE, &full, &error));
        RS2_CHECK(!full.valid && error == ERROR_INVALID_PARAMETER);
        RS2_CHECK(CloseHandle(file));
    }
    // A non-file handle exercises the OS-query failure, not just input checks.
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    RS2_CHECK(event != nullptr);
    if (event != nullptr) {
        FileIdentity128 invalid{};
        invalid.valid = true;
        RS2_CHECK(!QueryFileIdentity128(event, &invalid, &error));
        RS2_CHECK(!invalid.valid && error != ERROR_SUCCESS);
        RS2_CHECK(SetEvent(event));
        RS2_CHECK(CloseHandle(event));
    }
}
} // namespace rs2fix::testcases
