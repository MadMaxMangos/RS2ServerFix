#include "companion/marker.h"

#include <Windows.h>

#include <array>
#include <charconv>
#include <cstdio>
#include <cwchar>
#include <limits>
#include <string_view>

namespace rs2fix {
namespace {

constexpr std::size_t kMarkerCapacity = 8192;

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

const char* ResolverStatusName(
    const GenuineResolverStatus status) noexcept {
    switch (status) {
    case GenuineResolverStatus::Ok:
        return "ok";
    case GenuineResolverStatus::SystemPathFailed:
        return "system-path-failed";
    case GenuineResolverStatus::LoadFailed:
        return "load-failed";
    case GenuineResolverStatus::SelfModule:
        return "self-module";
    case GenuineResolverStatus::CandidatePathFailed:
        return "candidate-path-failed";
    case GenuineResolverStatus::FileIdentityFailed:
        return "file-identity-failed";
    case GenuineResolverStatus::WrongFile:
        return "wrong-file";
    case GenuineResolverStatus::ExportMissing:
        return "export-missing";
    case GenuineResolverStatus::QueryAddressFailed:
        return "query-address-failed";
    case GenuineResolverStatus::SelfAddress:
        return "self-address";
    }
    return "unknown";
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

bool WriteMarkerFile(
    const wchar_t* path,
    const char* data,
    const std::size_t size,
    DWORD* error) noexcept {
    if (error != nullptr) {
        *error = ERROR_INVALID_PARAMETER;
    }
    if (path == nullptr || data == nullptr ||
        size > std::numeric_limits<DWORD>::max()) {
        return false;
    }

    HANDLE file = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (error != nullptr) {
            *error = GetLastError();
        }
        return false;
    }

    bool success = true;
    DWORD remaining = static_cast<DWORD>(size);
    const char* cursor = data;
    DWORD localError = ERROR_SUCCESS;
    while (remaining != 0) {
        DWORD written = 0;
        if (!WriteFile(file, cursor, remaining, &written, nullptr) ||
            written == 0) {
            success = false;
            localError = GetLastError();
            if (localError == ERROR_SUCCESS) {
                localError = ERROR_WRITE_FAULT;
            }
            break;
        }
        cursor += written;
        remaining -= written;
    }
    if (success && !FlushFileBuffers(file)) {
        success = false;
        localError = GetLastError();
    }
    if (!CloseHandle(file) && success) {
        success = false;
        localError = GetLastError();
    }
    if (!success) {
        DeleteFileW(path);
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

bool FormatMarkerUtf8(
    const MarkerData& data,
    char* output,
    const std::size_t capacity,
    std::size_t* bytesUsed) noexcept {
    if (bytesUsed != nullptr) {
        *bytesUsed = 0;
    }
    if (output == nullptr || bytesUsed == nullptr || capacity == 0) {
        return false;
    }

    char leafName[1024]{};
    if (!ConvertLeafName(
            data.executableLeaf, leafName, sizeof(leafName))) {
        output[0] = '\0';
        return false;
    }

    SYSTEMTIME utc{};
    GetSystemTime(&utc);
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
    AppendField(writer, "schema", "1");
    AppendField(writer, "utc", timestamp);
    AppendIntegerField(writer, "pid", data.processId);
    AppendField(writer, "executable", leafName);
    AppendIntegerField(writer, "executable_size", data.executableSize);
    AppendDigest(writer, data);
    AppendField(
        writer,
        "build_identity",
        BuildIdentityName(data.buildIdentity));
    AppendField(writer, "bootstrap", "faultrep.dll");
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
        "resolver_status",
        ResolverStatusName(data.resolverStatus));
    AppendIntegerField(writer, "resolver_error", data.resolverError);
    AppendField(
        writer,
        "genuine_module",
        data.resolverStatus == GenuineResolverStatus::Ok
            ? "system32"
            : "unavailable");
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

MarkerWriteResult WriteMarkerWithFallback(
    const wchar_t* primaryDirectory,
    const wchar_t* fallbackDirectory,
    const MarkerData& data) noexcept {
    MarkerWriteResult result{};
    std::array<char, kMarkerCapacity> formatted{};
    std::size_t formattedSize = 0;

    wchar_t primaryPath[kMarkerPathCapacity]{};
    if (BuildMarkerPath(
            primaryDirectory,
            data.processId,
            primaryPath,
            kMarkerPathCapacity) &&
        FormatMarkerUtf8(
            data, formatted.data(), formatted.size(), &formattedSize) &&
        WriteMarkerFile(
            primaryPath,
            formatted.data(),
            formattedSize,
            &result.primaryError)) {
        result.written = true;
        CopyPath(primaryPath, result.writtenPath, kMarkerPathCapacity);
        return result;
    }
    if (result.primaryError == ERROR_SUCCESS) {
        result.primaryError = GetLastError();
        if (result.primaryError == ERROR_SUCCESS) {
            result.primaryError = ERROR_INVALID_NAME;
        }
    }

    MarkerData fallbackData = data;
    fallbackData.primaryWriteError = result.primaryError;
    formatted.fill('\0');
    formattedSize = 0;
    wchar_t fallbackPath[kMarkerPathCapacity]{};
    if (!BuildMarkerPath(
            fallbackDirectory,
            data.processId,
            fallbackPath,
            kMarkerPathCapacity) ||
        !FormatMarkerUtf8(
            fallbackData,
            formatted.data(),
            formatted.size(),
            &formattedSize) ||
        !WriteMarkerFile(
            fallbackPath,
            formatted.data(),
            formattedSize,
            &result.finalError)) {
        if (result.finalError == ERROR_SUCCESS) {
            result.finalError = ERROR_INVALID_NAME;
        }
        return result;
    }

    result.written = true;
    result.usedFallback = true;
    result.finalError = ERROR_SUCCESS;
    CopyPath(fallbackPath, result.writtenPath, kMarkerPathCapacity);
    return result;
}

} // namespace rs2fix
