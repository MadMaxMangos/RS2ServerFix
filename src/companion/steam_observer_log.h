#pragma once

#include "companion/steam_observer_dispatch.h"

namespace rs2fix::observer {
struct Writer;
inline constexpr std::size_t kWriterPathCapacity = 4096;
inline constexpr std::uint32_t kDefaultLogMiB = 512;

enum class WriterStatus : LONG { Prepared, Recording, Failed, Truncated, Stopped };
struct WriterSnapshot {
    WriterStatus status;
    DWORD error;
    std::uint64_t bytesWritten;
    std::uint64_t eventsWritten;
    std::uint64_t droppedContention;
    std::uint64_t droppedFull;
    std::uint64_t abandoned;
    std::uint32_t queueDepth;
};

// These are startup/worker APIs, never hook APIs. Preparing does not inspect the
// supplied zero-initialized dispatch storage: initialize it, publish its sink,
// commit its Armed gate, then call ArmWriter. Storage remains process-lifetime.
Writer* PrepareWriter(const wchar_t* executableDirectory, std::uint32_t maxLogMiB,
    DispatchState* dispatch, Reason* reason, DWORD* error) noexcept;
EventSink GetWriterSink(Writer* writer) noexcept;
void ArmWriter(Writer* writer) noexcept;
void StopUnarmedWriter(Writer* writer) noexcept;
const wchar_t* GetWriterDirectory(const Writer* writer) noexcept;
WriterSnapshot SnapshotWriter(Writer* writer) noexcept;

// Disabled paths own a separate static reporter slot; no logger/key resources
// are created. Failure to display a notice is not a recon/initialization failure.
void ScheduleObserverDisabledNotice(Reason reason) noexcept;

#if defined(RS2_OBSERVER_TESTING)
// Owned inert-file seams only; never part of a production artifact. Manual mode
// starts no threads/reporters and lets a test exhaust the queue deterministically.
struct WriterTestOptions {
    std::uint64_t byteLimit;
    void* context;
    bool (*write)(void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept;
    bool (*flush)(void*, HANDLE, DWORD*) noexcept;
};
Writer* PrepareWriterForTest(const wchar_t* directory, DispatchState* dispatch,
    const WriterTestOptions& options, Reason* reason, DWORD* error) noexcept;
void PumpWriterForTest(Writer* writer) noexcept;
void FinishWriterForTest(Writer* writer) noexcept;
void LockWriterQueueForTest(Writer* writer) noexcept;
void UnlockWriterQueueForTest(Writer* writer) noexcept;
bool HmacSteamIdForTest(const unsigned char key[32], std::uint64_t id,
    char token[33]) noexcept;
#endif
} // namespace rs2fix::observer
