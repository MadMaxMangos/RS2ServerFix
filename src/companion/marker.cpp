#include "companion/marker.h"
#include "shared/version.h"
#if defined(RS2_STARTUP_TEST_PROFILE)
#include "fixture_profile.h"
#endif

#include <Windows.h>

#include <array>
#include <charconv>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <limits>
#include <new>
#include <string_view>

namespace rs2fix {
namespace {

constexpr std::size_t kMarkerCapacity = 8192;

struct MarkerWorkspace {
    std::array<char, kMarkerCapacity> formatted;
    wchar_t primaryPath[kMarkerPathCapacity];
    wchar_t fallbackPath[kMarkerPathCapacity];
    MarkerData fallbackData;
};

class BufferWriter {
public:
    BufferWriter(char* output, const std::size_t capacity) noexcept
        : output_(output), capacity_(capacity) {
        if (output_ == nullptr || capacity_ == 0) {
            valid_ = false;
        } else {
            output_[0] = '\0';
        }
    }

    bool Append(const std::string_view text) noexcept {
        if (!valid_ || text.size() > Remaining()) {
            valid_ = false;
            return false;
        }
        std::memcpy(output_ + used_, text.data(), text.size());
        used_ += text.size();
        output_[used_] = '\0';
        return true;
    }

    template <typename Integer>
    bool AppendInteger(const Integer value) noexcept {
        std::array<char, 32> buffer{};
        const auto converted = std::to_chars(
            buffer.data(), buffer.data() + buffer.size(), value);
        if (converted.ec != std::errc{}) {
            valid_ = false;
            return false;
        }
        return Append(std::string_view(
            buffer.data(),
            static_cast<std::size_t>(converted.ptr - buffer.data())));
    }

    bool valid() const noexcept { return valid_; }
    std::size_t used() const noexcept { return valid_ ? used_ : 0; }

private:
    std::size_t Remaining() const noexcept {
        if (used_ >= capacity_) {
            return 0;
        }
        return capacity_ - used_ - 1;
    }

    char* output_{};
    std::size_t capacity_{};
    std::size_t used_{};
    bool valid_{true};
};

const char* BooleanName(const bool value) noexcept {
    return value ? "true" : "false";
}

bool AppendField(
    BufferWriter& writer,
    const std::string_view name,
    const std::string_view value) noexcept {
    return writer.Append(name) && writer.Append("=") &&
           writer.Append(value) && writer.Append("\r\n");
}

template <typename Integer>
bool AppendIntegerField(
    BufferWriter& writer,
    const std::string_view name,
    const Integer value) noexcept {
    return writer.Append(name) && writer.Append("=") &&
           writer.AppendInteger(value) && writer.Append("\r\n");
}

bool AppendDigest(
    BufferWriter& writer,
    const MarkerData& data) noexcept {
    if (!writer.Append("sha256=")) {
        return false;
    }
    if (!data.digestValid) {
        return writer.Append("unavailable\r\n");
    }

    constexpr char kHex[] = "0123456789ABCDEF";
    std::array<char, 64> encoded{};
    for (std::size_t index = 0; index < data.digest.size(); ++index) {
        encoded[index * 2] = kHex[data.digest[index] >> 4];
        encoded[index * 2 + 1] = kHex[data.digest[index] & 0x0f];
    }
    return writer.Append(std::string_view(encoded.data(), encoded.size())) &&
           writer.Append("\r\n");
}

bool ConvertLeafName(
    const wchar_t* input,
    char* output,
    const int capacity) noexcept {
    if (input == nullptr || output == nullptr || capacity <= 0) {
        return false;
    }
    const std::size_t length = wcsnlen_s(input, 260);
    if (length == 0 || length >= 260) {
        return false;
    }
    if (std::wcscmp(input, L".") == 0 || std::wcscmp(input, L"..") == 0) return false;
    for (std::size_t i = 0; i < length; ++i) {
        if (input[i] < 32 || input[i] == 127 || input[i] == L'\\' ||
            input[i] == L'/' || input[i] == L':' || input[i] == L'=') return false;
    }
    const int converted = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input,
        -1,
        output,
        capacity,
        nullptr,
        nullptr);
    return converted > 0;
}

bool BuildMarkerPath(
    const wchar_t* directory,
    const DWORD processId,
    wchar_t* output,
    const std::size_t capacity) noexcept {
    if (directory == nullptr || output == nullptr || capacity == 0) {
        return false;
    }
    const std::size_t directoryLength =
        wcsnlen_s(directory, kMarkerPathCapacity);
    if (directoryLength == 0 || directoryLength >= kMarkerPathCapacity) {
        return false;
    }

    wchar_t filename[64]{};
    const int filenameLength = swprintf_s(
        filename,
        L"RS2ServerFix.loader.%lu.log",
        static_cast<unsigned long>(processId));
    if (filenameLength <= 0) {
        return false;
    }

    const bool needsSlash = directory[directoryLength - 1] != L'\\' &&
                            directory[directoryLength - 1] != L'/';
    const std::size_t required = directoryLength +
        (needsSlash ? 1u : 0u) +
        static_cast<std::size_t>(filenameLength) + 1;
    if (required > capacity) {
        return false;
    }

    std::memcpy(
        output, directory, directoryLength * sizeof(wchar_t));
    std::size_t cursor = directoryLength;
    if (needsSlash) {
        output[cursor++] = L'\\';
    }
    std::memcpy(
        output + cursor,
        filename,
        (static_cast<std::size_t>(filenameLength) + 1) * sizeof(wchar_t));
    return true;
}

HANDLE CreateMarker(void*, const wchar_t* path, DWORD* error) noexcept {
    const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    *error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    return file;
}
bool WriteMarker(void*, HANDLE file, const void* bytes, DWORD size,
                 DWORD* written, DWORD* error) noexcept {
    const bool ok = WriteFile(file, bytes, size, written, nullptr) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
bool FlushMarker(void*, HANDLE file, DWORD* error) noexcept {
    const bool ok = FlushFileBuffers(file) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
bool CloseMarker(void*, HANDLE file, DWORD* error) noexcept {
    const bool ok = CloseHandle(file) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
bool RemoveMarker(void*, const wchar_t* path, DWORD* error) noexcept {
    const bool ok = DeleteFileW(path) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
constexpr MarkerFileOps kMarkerOps{
    nullptr, CreateMarker, WriteMarker, FlushMarker, CloseMarker, RemoveMarker};

bool WriteMarkerFile(
    const wchar_t* path,
    const char* data,
    const std::size_t size,
    DWORD* error,
    DWORD* cleanupError,
    const MarkerFileOps& ops) noexcept {
    if (error != nullptr) {
        *error = ERROR_INVALID_PARAMETER;
    }
    if (path == nullptr || data == nullptr ||
        size > std::numeric_limits<DWORD>::max()) {
        return false;
    }

    DWORD localError = ERROR_SUCCESS;
    HANDLE file = ops.createAlways(ops.context, path, &localError);
    if (!file || file == INVALID_HANDLE_VALUE) {
        *error = localError == ERROR_SUCCESS ? ERROR_OPEN_FAILED : localError;
        return false;
    }
    DWORD written = 0;
    bool success = ops.write(ops.context, file, data, static_cast<DWORD>(size), &written, &localError);
    if (written != size) success = false;
    if (!success && localError == ERROR_SUCCESS) localError = ERROR_WRITE_FAULT;
    if (success && !ops.flush(ops.context, file, &localError)) {
        success = false;
        if (localError == ERROR_SUCCESS) localError = ERROR_WRITE_FAULT;
    }
    DWORD closeError = ERROR_SUCCESS;
    if (!ops.close(ops.context, file, &closeError) && success) {
        success = false;
        localError = closeError == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : closeError;
    }
    if (!success) {
        DWORD removeError = ERROR_SUCCESS;
        if (!ops.remove(ops.context, path, &removeError))
            *cleanupError = removeError == ERROR_SUCCESS ? ERROR_WRITE_FAULT : removeError;
    }
    if (error != nullptr) {
        *error = success ? ERROR_SUCCESS : localError;
    }
    return success;
}

void CopyPath(
    const wchar_t* source,
    wchar_t* destination,
    const std::size_t capacity) noexcept {
    if (source == nullptr || destination == nullptr || capacity == 0) {
        return;
    }
    const std::size_t length = wcsnlen_s(source, capacity);
    if (length >= capacity) {
        return;
    }
    std::memcpy(
        destination, source, (length + 1) * sizeof(wchar_t));
}

} // namespace

const MarkerFileOps& ProductionMarkerFileOps() noexcept { return kMarkerOps; }

bool MarkerStateAccepted(const MarkerData& data) noexcept {
    const bool supportedHost =
#if defined(RS2_STARTUP_TEST_PROFILE)
        data.digest == kFixtureReconProfile.hostDigest;
#else
        data.buildIdentity == BuildIdentity::CurrentFullDump &&
        ClassifyBuild(data.digest, data.digestValid) == BuildIdentity::CurrentFullDump;
#endif
    const bool outcomeMatches =
        (data.mode == ReconMode::Passive && data.recon.outcome == ReconOutcome::Passive) ||
        (data.mode == ReconMode::Active && data.recon.outcome == ReconOutcome::Active);
    return data.complete && data.digestValid &&
        supportedHost &&
        data.bootstrapBesideExecutable && data.companionBesideExecutable &&
        data.genuineSystem32 && data.genuineExportsMask == kRequiredGenuineExports &&
        data.triggerKind == kTriggerExeCrtInitialize && data.recon.qualified &&
        outcomeMatches && data.recon.reason == FixReason::None &&
        data.recon.error == ERROR_SUCCESS && data.initializeResult == kInitOk;
}

bool FormatMarkerUtf8(
    const MarkerData& data,
    char* output,
    const std::size_t capacity,
    std::size_t* bytesUsed) noexcept {
    if (bytesUsed != nullptr) {
        *bytesUsed = 0;
    }
    if (output && capacity) output[0] = '\0';
    if (output == nullptr || bytesUsed == nullptr || capacity == 0) {
        return false;
    }

    char leafName[1024]{};
    if (!ConvertLeafName(
            data.executableLeaf, leafName, sizeof(leafName))) {
        output[0] = '\0';
        return false;
    }

    const SYSTEMTIME& utc = data.utc;
    FILETIME validatedUtc{};
    if (utc.wYear > 9999 || !SystemTimeToFileTime(&utc, &validatedUtc) ||
        static_cast<unsigned>(data.buildIdentity) > static_cast<unsigned>(BuildIdentity::Indeterminate) ||
        static_cast<unsigned>(data.mode) > static_cast<unsigned>(ReconMode::Active) ||
        static_cast<unsigned>(data.recon.outcome) > static_cast<unsigned>(ReconOutcome::Fatal) ||
        static_cast<unsigned>(data.recon.reason) > static_cast<unsigned>(FixReason::RollbackFailed) ||
        (data.genuineExportsMask & ~kRequiredGenuineExports) != 0 ||
        data.triggerKind > kTriggerExeCrtInitialize) return false;
    char timestamp[64]{};
    const int timestampLength = std::snprintf(
        timestamp,
        sizeof(timestamp),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        utc.wYear,
        utc.wMonth,
        utc.wDay,
        utc.wHour,
        utc.wMinute,
        utc.wSecond,
        utc.wMilliseconds);
    if (timestampLength <= 0 ||
        static_cast<std::size_t>(timestampLength) >= sizeof(timestamp)) {
        output[0] = '\0';
        return false;
    }

    BufferWriter writer(output, capacity);
    AppendField(writer, "schema", "3");
    AppendField(writer, "version", RS2FIX_VERSION_ASCII);
    AppendField(writer, "utc", timestamp);
    AppendIntegerField(writer, "pid", data.processId);
    AppendField(writer, "executable", leafName);
    AppendIntegerField(writer, "executable_size", data.executableSize);
    AppendDigest(writer, data);
    AppendField(
        writer,
        "build_identity",
        BuildIdentityName(data.buildIdentity));
    AppendField(writer, "bootstrap", "X3DAudio1_7.dll");
    AppendField(
        writer,
        "bootstrap_beside_executable",
        BooleanName(data.bootstrapBesideExecutable));
    AppendField(writer, "companion", "RS2ServerFix.dll");
    AppendField(
        writer,
        "companion_beside_executable",
        BooleanName(data.companionBesideExecutable));
    AppendField(
        writer,
        "genuine_module",
        data.genuineSystem32
            ? "system32"
            : "unavailable");
    AppendField(writer, "genuine_initialize_present",
        BooleanName((data.genuineExportsMask & kGenuineInitializePresent) != 0));
    AppendField(writer, "genuine_calculate_present",
        BooleanName((data.genuineExportsMask & kGenuineCalculatePresent) != 0));
    AppendField(writer, "trigger", data.triggerKind == kTriggerExeCrtInitialize
        ? "exe-crt-initialize" : "unavailable");
    AppendField(writer, "mode", ReconModeName(data.mode));
    AppendField(writer, "fix", kReconFixId);
    AppendField(writer, "qualification", data.recon.qualified ? "ready" : "rejected");
    AppendField(writer, "recon", ReconOutcomeName(data.recon.outcome));
    AppendField(writer, "reason", FixReasonName(data.recon.reason));
    AppendIntegerField(writer, "initialize_result", data.initializeResult);
    AppendIntegerField(
        writer, "primary_write_error", data.primaryWriteError);
    AppendField(
        writer,
        "completion",
        data.complete ? "complete" : "partial");

    if (!writer.valid()) {
        output[0] = '\0';
        return false;
    }
    *bytesUsed = writer.used();
    return true;
}

bool WriteMarkerWithFallback(
    const wchar_t* primaryDirectory,
    const wchar_t* fallbackDirectory,
    const MarkerData& data,
    MarkerWriteResult* result,
    const MarkerFileOps& ops) noexcept {
    if (result == nullptr) {
        return false;
    }
    result->written = false;
    result->usedFallback = false;
    result->primaryError = ERROR_SUCCESS;
    result->finalError = ERROR_SUCCESS;
    result->cleanupError = ERROR_SUCCESS;
    result->writtenPath[0] = L'\0';
    if (!ops.createAlways || !ops.write || !ops.flush || !ops.close || !ops.remove) {
        result->primaryError = result->finalError = ERROR_INVALID_PARAMETER;
        return false;
    }
    void* storage = VirtualAlloc(
        nullptr,
        sizeof(MarkerWorkspace),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    auto* workspace = storage ? ::new (storage) MarkerWorkspace{} : nullptr;
    if (workspace == nullptr) {
        result->primaryError = ERROR_NOT_ENOUGH_MEMORY;
        result->finalError = ERROR_NOT_ENOUGH_MEMORY;
        return false;
    }

    std::size_t formattedSize = 0;

    if (BuildMarkerPath(
            primaryDirectory,
            data.processId,
            workspace->primaryPath,
            kMarkerPathCapacity) &&
        FormatMarkerUtf8(
            data,
            workspace->formatted.data(),
            workspace->formatted.size(),
            &formattedSize) &&
        WriteMarkerFile(
            workspace->primaryPath,
            workspace->formatted.data(),
            formattedSize,
            &result->primaryError, &result->cleanupError, ops)) {
        result->written = true;
        CopyPath(
            workspace->primaryPath,
            result->writtenPath,
            kMarkerPathCapacity);
        VirtualFree(workspace, 0, MEM_RELEASE);
        return true;
    }
    if (result->primaryError == ERROR_SUCCESS) {
        result->primaryError = ERROR_INVALID_NAME;
    }

    workspace->fallbackData = data;
    workspace->fallbackData.primaryWriteError = result->primaryError;
    if (result->cleanupError != ERROR_SUCCESS)
        workspace->fallbackData.initializeResult = kInitMarkerWriteFailed;
    workspace->formatted.fill('\0');
    formattedSize = 0;
    if (!BuildMarkerPath(
            fallbackDirectory,
            data.processId,
            workspace->fallbackPath,
            kMarkerPathCapacity) ||
        _wcsicmp(workspace->primaryPath, workspace->fallbackPath) == 0 ||
        !FormatMarkerUtf8(
            workspace->fallbackData,
            workspace->formatted.data(),
            workspace->formatted.size(),
            &formattedSize) ||
        !WriteMarkerFile(
            workspace->fallbackPath,
            workspace->formatted.data(),
            formattedSize,
            &result->finalError, &result->cleanupError, ops)) {
        if (result->finalError == ERROR_SUCCESS) {
            result->finalError = ERROR_INVALID_NAME;
        }
        VirtualFree(workspace, 0, MEM_RELEASE);
        return false;
    }

    result->written = true;
    result->usedFallback = true;
    result->finalError = ERROR_SUCCESS;
    CopyPath(
        workspace->fallbackPath,
        result->writtenPath,
        kMarkerPathCapacity);
    VirtualFree(workspace, 0, MEM_RELEASE);
    return true;
}

} // namespace rs2fix
